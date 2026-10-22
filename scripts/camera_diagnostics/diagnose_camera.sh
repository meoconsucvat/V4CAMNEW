#!/bin/sh
# Read-only, local iOS diagnostics. No plist secrets, file contents, or uploads.
# Usage: sh diagnose_camera.sh ACTUAL_SHARED_DIR [ACTUAL_SELECTED_MEDIA_FILE]
set -eu
umask 077

die() { printf '%s\n' "$*" >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || die 'Run this script on the target iOS device, not the build host.'
[ "$(id -u)" = 0 ] || die 'Run as root for process and metadata visibility.'
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || die 'Usage: sh diagnose_camera.sh ACTUAL_SHARED_DIR [ACTUAL_SELECTED_MEDIA_FILE]'
case "$1" in /*) ;; *) die 'Shared directory must be an absolute path.' ;; esac
SHARED=$(CDPATH= cd "$1" && pwd -P) || die 'Shared directory is not accessible.'
case "$SHARED" in */Library/VCNext) ;; *) die 'Expected a resolved Library/VCNext directory.' ;; esac

metadata() {
    [ -e "$1" ] || [ -L "$1" ] || { printf 'MISSING %s\n' "$1"; return; }
    stat -f '%N | uid=%u gid=%g mode=%Lp inode=%d:%i modified=%m' "$1" 2>/dev/null || ls -ldn "$1"
    # ACLs/flags are metadata, not file contents. Unsupported options fall back.
    ls -ldneO "$1" 2>/dev/null || ls -ldn "$1"
}

PB=''
for candidate in /usr/libexec/PlistBuddy /var/jb/usr/libexec/PlistBuddy; do
    if [ -x "$candidate" ]; then PB=$candidate; break; fi
done
if [ -z "$PB" ]; then PB=$(command -v PlistBuddy 2>/dev/null || true); fi

read_key() {
    [ -n "$PB" ] || return 1
    "$PB" -c "Print :$2" "$1" 2>/dev/null
}

printf '%s\n' 'VCNext read-only camera diagnosis (metadata; no credentials)'
date '+Local clock: %Y-%m-%d %H:%M:%S %z'
printf 'Effective shell identity: '; id
for key in hw.machine kern.osrelease kern.osversion hw.cpusubtype; do
    printf '%s=' "$key"
    /usr/sbin/sysctl -n "$key" 2>/dev/null || printf '%s\n' unavailable
done
printf 'uname -m='; uname -m
printf 'Resolved shared directory: %s\n' "$SHARED"

printf '\n%s\n' 'Ancestor traversal metadata (root readability is not daemon readability):'
ancestor=$SHARED
while :; do
    metadata "$ancestor"
    [ "$ancestor" = / ] && break
    ancestor=$(dirname "$ancestor")
done

printf '\n%s\n' 'Shared public/private file metadata only:'
for relative in Media Streams CameraConfig.plist CameraStatus.plist CapabilityLease.plist AuthSession.plist Injected; do
    metadata "$SHARED/$relative"
done
count=0
for marker in "$SHARED"/Injected/*; do
    [ -e "$marker" ] || continue
    metadata "$marker"
    count=$((count + 1)); [ "$count" -lt 8 ] || break
done
printf '%s\n' 'Injected marker absence is inconclusive: creating it requires directory write access.'

printf '\n%s\n' 'CameraConfig public fields (no AuthSession/lease content):'
for key in directMediaEnabled selectedMediaKind linkEnabled linkMode; do
    value=$(read_key "$SHARED/CameraConfig.plist" "$key" || true)
    [ -n "$value" ] || value='unavailable (PlistBuddy missing, absent key, or unreadable plist)'
    printf '%s=%s\n' "$key" "$value"
done
SELECTED=${2:-}
if [ -z "$SELECTED" ]; then
    SELECTED=$(read_key "$SHARED/CameraConfig.plist" selectedMediaPath || true)
fi
if [ -n "$SELECTED" ]; then
    printf '\nSelected media path: %s\n' "$SELECTED"
    metadata "$SELECTED"
    parent=$(dirname "$SELECTED")
    count=0
    while [ "$parent" != / ] && [ "$count" -lt 12 ]; do
        metadata "$parent"
        [ "$parent" = "$SHARED" ] && break
        parent=$(dirname "$parent"); count=$((count + 1))
    done
    if command -v file >/dev/null 2>&1; then file "$SELECTED" 2>/dev/null || true; fi
else
    printf '%s\n' 'Selected media path unavailable; pass its actual resolved filesystem path explicitly.'
fi

printf '\n%s\n' 'Whitelisted CameraStatus fields (last writer wins across processes):'
for key in process state hookProfile machine chipFamily deviceGroup hookedClassCount nodeOutputFrames previewSubclassFrames imageQueueSinkFrames remoteQueueSinkFrames renderedFrames deliveredVirtualFrames inPlaceFrames deduplicatedFrames inPlaceFailures eligibleNodeOutputFrames connectedConsumerOutputFrames rejectedNodeOutputFrames replacementMisses replacementFormatMismatches lastObservedPixelFormat updatedAt; do
    value=$(read_key "$SHARED/CameraStatus.plist" "$key" || true)
    [ -z "$value" ] || printf '%s=%s\n' "$key" "$value"
done
printf '%s\n' 'A missing/stale CameraStatus can reflect failed atomic publication; it does not prove injection failure.'

printf '\n%s\n' 'Actual selected process IDs and effective identities:'
ROWS=$(ps -axo pid=,uid=,gid=,comm= 2>/dev/null | awk '$0 ~ /(^|\/)(mediaserverd|cameracaptured|VCNStreamDaemon|VCNNetworkDaemon|VCNext)$/ {print}' || true)
printf 'PID UID GID COMM\n%s\n' "$ROWS"
if command -v sudo >/dev/null 2>&1; then
    PROBE_SHELL=$(command -v sh)
    printf '\n%s\n' 'Optional UID/GID credential probes (fresh shell, NOT the daemon sandbox):'
    printf '%s\n' "$ROWS" | while read -r probe_pid probe_uid probe_gid probe_command; do
        case "$probe_pid:$probe_uid:$probe_gid" in *[!0-9:]*|::*|:) continue ;; esac
        [ -n "$probe_uid" ] && [ -n "$probe_gid" ] || continue
        printf 'PID %s UID %s GID %s:\n' "$probe_pid" "$probe_uid" "$probe_gid"
        sudo -n -u "#$probe_uid" -g "#$probe_gid" "$PROBE_SHELL" -c '
            for probe_path do
                [ -n "$probe_path" ] || continue
                if [ -d "$probe_path" ]; then
                    if [ -x "$probe_path" ]; then access=traversable; else access=not-traversable; fi
                else
                    if [ -r "$probe_path" ]; then access=readable; else access=not-readable; fi
                    if command -v dd >/dev/null 2>&1; then
                        if dd if="$probe_path" of=/dev/null bs=1 count=1 2>/dev/null; then
                            access="$access open-read-ok"
                        else
                            access="$access open-read-failed"
                        fi
                    fi
                fi
                printf "%s %s\n" "$access" "$probe_path"
            done
        ' vcnext-dac-probe "$SHARED" "$SHARED/Media" "$SHARED/CameraConfig.plist" \
          "$SHARED/CapabilityLease.plist" "$SELECTED" || printf '%s\n' 'Credential probe could not be started; no daemon-access conclusion.'
    done
else
    printf '%s\n' 'sudo unavailable: actual-UID read probe not performed. Do not substitute launchctl asuser; it does not drop credentials.'
fi
if command -v vmmap >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    printf '\n%s\n' 'Optional mapped-image evidence (no matches is not proof of absence):'
    printf '%s\n' "$ROWS" | awk '$1 ~ /^[0-9]+$/ {print $1}' | while IFS= read -r pid; do
        printf 'PID %s:\n' "$pid"
        timeout 5 vmmap "$pid" 2>/dev/null | awk '/VCNextCamera|AutoPatches|PatchLoader/ {print}' || true
    done
else
    printf '%s\n' 'vmmap or a timeout runner unavailable: mapped-image/injection state remains unverified.'
fi

case "$SHARED" in
    */var/mobile/Library/VCNext)
        PREFIX=${SHARED%/var/mobile/Library/VCNext}
        FILTER="$PREFIX/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.plist"
        printf '\n%s\n' 'Injection filter and patch marker metadata:'
        metadata "$FILTER"
        if [ -n "$PB" ]; then "$PB" -c 'Print :Filter:Executables' "$FILTER" 2>/dev/null || true; fi
        metadata "$PREFIX/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib.roothidepatch"
        ;;
esac

printf '\n%s\n' 'Relevant crash-report filenames/metadata only (at most eight per directory):'
for crash_dir in /var/mobile/Library/Logs/CrashReporter /Library/Logs/CrashReporter; do
    [ -d "$crash_dir" ] || continue
    count=0
    for crash in "$crash_dir"/mediaserverd* "$crash_dir"/cameracaptured*; do
        [ -f "$crash" ] || continue
        metadata "$crash"
        count=$((count + 1)); [ "$count" -lt 8 ] || break
    done
done
printf '\n%s\n' 'No files changed. No daemon was restarted. No data was uploaded.'
printf '%s\n' 'DAC metadata does not prove an iOS sandbox extension or in-process open succeeded.'
