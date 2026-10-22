#!/bin/sh
# Narrow, reversible DAC A/B test. Does not edit binaries, plist values, or users.
# Close VCNext before applying/restoring; an atomic rewrite changes file inodes.
# Usage: sh repair_camera_read_access.sh --apply ACTUAL_SHARED_DIR [ACTUAL_SELECTED_FILE]
#        sh repair_camera_read_access.sh --restore ROOT_OWNED_MODE_MANIFEST
set -eu
umask 077

die() { printf '%s\n' "$*" >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || die 'Run on the target iOS device, not the build host.'
[ "$(id -u)" = 0 ] || die 'Run as root.'

no_controls() {
    case "$1" in
        *'
'*) die 'Newlines in paths are not supported.' ;;
    esac
    if printf '%s' "$1" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null 2>&1; then
        die 'Control characters in paths are not supported.'
    fi
}

canonical_dir() {
    no_controls "$1"
    case "$1" in /*) ;; *) die 'Expected an absolute path.' ;; esac
    CDPATH= cd "$1" && pwd -P
}

metadata_identity() { stat -f '%d:%i' "$1"; }
metadata_mode() { stat -f '%Lp' "$1"; }

safe_path() {
    no_controls "$1"
    case "$1" in "$SHARED"|"$SHARED/Media"|"$SHARED/Media/"*|"$SHARED/CameraConfig.plist") ;; *) die "Refusing out-of-scope path: $1" ;; esac
    [ ! -L "$1" ] || die "Refusing symlink leaf: $1"
    safe_parent=$(canonical_dir "$(dirname "$1")") || die 'Cannot resolve parent directory.'
    safe_leaf=$(basename "$1")
    [ "$safe_parent/$safe_leaf" = "$1" ] || die "Refusing a noncanonical/symlinked path: $1"
}

change_mode() {
    mode=$1; target=$2
    safe_path "$target"
    [ -e "$target" ] || die "Missing target: $target"
    # Record metadata before changing only the known public camera path.
    printf '%s\t%s\t%s\n' "$(metadata_mode "$target")" "$(metadata_identity "$target")" "$target" >> "$MANIFEST"
    chmod "$mode" "$target"
}

case "${1:-}" in
    --apply)
        [ "$#" -ge 2 ] && [ "$#" -le 3 ] || die 'Usage: --apply ACTUAL_SHARED_DIR [ACTUAL_SELECTED_FILE]'
        SHARED=$(canonical_dir "$2") || die 'Cannot resolve shared directory.'
        case "$SHARED" in */Library/VCNext) ;; *) die 'Expected a Library/VCNext directory.' ;; esac
        [ -f "$SHARED/CameraConfig.plist" ] && [ ! -L "$SHARED/CameraConfig.plist" ] || die 'Select Use as Camera first; a real CameraConfig.plist is required.'
        [ -d "$SHARED/Media" ] && [ ! -L "$SHARED/Media" ] || die 'Expected a real Media directory.'
        SELECTED=${3:-}
        if [ -z "$SELECTED" ]; then
            PB=''
            for candidate in /usr/libexec/PlistBuddy /var/jb/usr/libexec/PlistBuddy; do
                if [ -x "$candidate" ]; then PB=$candidate; break; fi
            done
            if [ -z "$PB" ]; then PB=$(command -v PlistBuddy 2>/dev/null || true); fi
            [ -n "$PB" ] || die 'Pass the actual selected media file explicitly; PlistBuddy is unavailable.'
            SELECTED=$("$PB" -c 'Print :selectedMediaPath' "$SHARED/CameraConfig.plist" 2>/dev/null) || die 'Cannot read selectedMediaPath.'
        fi
        no_controls "$SELECTED"
        [ -f "$SELECTED" ] && [ ! -L "$SELECTED" ] || die 'Selected media must be an existing regular non-symlink file.'
        SELECTED=$(canonical_dir "$(dirname "$SELECTED")")/$(basename "$SELECTED")
        case "$SELECTED" in "$SHARED/Media/"*) ;; *) die 'Selected media must resolve inside this VCNext Media directory.' ;; esac
        safe_path "$SHARED"; safe_path "$SHARED/Media"; safe_path "$SELECTED"
        [ "$(stat -f '%u' "$SHARED")" = 501 ] || die 'Expected mobile ownership (UID 501); inspect unexpected ownership before changing modes.'
        parent=$(dirname "$SELECTED")
        while :; do
            safe_path "$parent"
            [ -d "$parent" ] || die 'Selected-media parent is not a directory.'
            [ "$parent" = "$SHARED/Media" ] && break
            parent=$(dirname "$parent")
        done
        BACKUP=$(mktemp -d /var/tmp/vcnext-camera-modes.XXXXXX) || die 'Cannot create private mode manifest directory.'
        chmod 700 "$BACKUP"
        MANIFEST="$BACKUP/modes.tsv"
        printf '# VCNext camera permission test\n# shared\t%s\n' "$SHARED" > "$MANIFEST"
        chmod 600 "$MANIFEST"
        printf 'Mode manifest (retain even if a later step fails): %s\n' "$MANIFEST"
        # Traversal only on the mixed public/private root; do not list secrets.
        change_mode 0711 "$SHARED"
        change_mode 0644 "$SHARED/CameraConfig.plist"
        parent=$(dirname "$SELECTED")
        while :; do
            change_mode 0755 "$parent"
            [ "$parent" = "$SHARED/Media" ] && break
            parent=$(dirname "$parent")
        done
        change_mode 0644 "$SELECTED"
        printf 'Applied read/traversal A/B test. Restore manifest: %s\n' "$MANIFEST"
        printf '%s\n' 'AuthSession, CapabilityLease, Streams, unselected media, ownership and external ancestors were not changed.'
        printf '%s\n' 'CameraStatus publication is NOT repaired by this read-only access change.'
        printf '%s\n' 'No daemon restarted. Re-run diagnostics after any new import or Use as Camera write.'
        ;;
    --restore)
        [ "$#" -eq 2 ] || die 'Usage: --restore ROOT_OWNED_MODE_MANIFEST'
        MANIFEST=$2
        no_controls "$MANIFEST"
        [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || die 'Expected a real mode manifest.'
        [ "$(stat -f '%u' "$MANIFEST")" = 0 ] || die 'Manifest must be root-owned.'
        [ "$(metadata_mode "$MANIFEST")" = 600 ] || die 'Manifest must have mode 0600.'
        manifest_parent=$(canonical_dir "$(dirname "$MANIFEST")") || die 'Cannot resolve manifest directory.'
        [ "$(stat -f '%u' "$manifest_parent")" = 0 ] && [ "$(metadata_mode "$manifest_parent")" = 700 ] || die 'Manifest directory must be root-owned mode 0700.'
        SHARED=$(awk -F "$(printf '\t')" 'NR == 2 && $1 == "# shared" { print $2; exit }' "$MANIFEST")
        [ -n "$SHARED" ] || die 'Invalid manifest header.'
        [ "$(canonical_dir "$SHARED")" = "$SHARED" ] || die 'Shared directory identity/path changed.'
        case "$SHARED" in */Library/VCNext) ;; *) die 'Manifest root is out of scope.' ;; esac
        TAB=$(printf '\t')
        while IFS="$TAB" read -r mode identity target; do
            case "$mode" in \#*) continue ;; ''|*[!0-7]*) die 'Invalid manifest mode.' ;; esac
            safe_path "$target"
            if [ ! -e "$target" ] || [ "$(metadata_identity "$target")" != "$identity" ]; then
                printf 'SKIPPED changed/replaced target: %s\n' "$target" >&2
                continue
            fi
            chmod "$mode" "$target"
        done < "$MANIFEST"
        printf '%s\n' 'Original modes restored for unchanged recorded inodes. Manifest retained for review.'
        ;;
    *) die 'Usage: --apply ACTUAL_SHARED_DIR [ACTUAL_SELECTED_FILE] | --restore ROOT_OWNED_MODE_MANIFEST' ;;
esac
