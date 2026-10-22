"""Offline shell-control tests: mocked Darwin metadata, never an iOS device.

The real repair script runs against temporary files under Git's POSIX shell.
Only OS identity/stat/chmod/mktemp are mocked. These assertions verify its
scope/manifest/rollback logic, not iOS DAC, sandbox or root permissions.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SHELL = Path("C:/Program Files/Git/usr/bin/sh.exe")
CYGPATH = SHELL.with_name("cygpath.exe")
HELPERS = ROOT / "scripts/camera_diagnostics"


def posix(path: Path) -> str:
    return subprocess.check_output([str(CYGPATH), "-u", str(path)], text=True).strip()


def main() -> None:
    assert SHELL.is_file() and CYGPATH.is_file()
    results = {}
    for name in ("diagnose_camera.sh", "repair_camera_read_access.sh"):
        result = subprocess.run([str(SHELL), "-n", str(HELPERS / name)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        results[name + "_syntax"] = True
        guard = subprocess.run([str(SHELL), str(HELPERS / name)], capture_output=True, text=True)
        assert guard.returncode == 2 and "target iOS device" in guard.stderr
        results[name + "_host_guard"] = True
    original = (HELPERS / "repair_camera_read_access.sh").read_text(encoding="utf-8")
    shims = r'''
uname() { printf 'Darwin\n'; }
id() { printf '0\n'; }
stat() {
    awk -F '\t' -v target="$3" -v field="$2" '
        $1 == target {
            found=1;
            if(field=="%Lp") print $2;
            else if(field=="%d:%i") print $3;
            else if(field=="%u") print $4;
            else exit 5;
        }
        END { if(!found) exit 4; }
    ' "$AUDIT_STATE"
}
chmod() {
    printf '%s\t%s\n' "$1" "$2" >> "$AUDIT_CALLS"
    awk -F '\t' -v OFS='\t' -v target="$2" -v value="$1" '
        $1==target { $2=value; found=1; }
        { print }
        END { if(!found) print target,value,"1:9999",0; }
    ' "$AUDIT_STATE" > "$AUDIT_STATE.next"
    mv "$AUDIT_STATE.next" "$AUDIT_STATE"
}
mktemp() { mkdir -p "$AUDIT_BACKUP"; printf '%s\n' "$AUDIT_BACKUP"; }
'''
    with tempfile.TemporaryDirectory(prefix="vcn-camera-mode-test-") as temporary:
        base = Path(temporary)
        shared = base / "Library/VCNext"
        media = shared / "Media/nested"
        media.mkdir(parents=True)
        (shared / "Streams").mkdir()
        selected = media / "nonsecret-test.jpg"
        for path in (selected, shared / "CameraConfig.plist", shared / "AuthSession.plist", shared / "CapabilityLease.plist"):
            path.write_bytes(b"synthetic fixture only\n")
        state, calls, wrapper = base / "modes.tsv", base / "calls.tsv", base / "wrapper.sh"
        backup = base / "backup"
        sp, selectedp = posix(shared), posix(selected)
        before = {
            sp: ("700", "1:1", "501"), sp + "/Media": ("700", "1:2", "501"),
            sp + "/Media/nested": ("700", "1:3", "501"), selectedp: ("600", "1:4", "501"),
            sp + "/CameraConfig.plist": ("600", "1:5", "501"),
            sp + "/AuthSession.plist": ("600", "1:6", "501"),
            sp + "/CapabilityLease.plist": ("644", "1:7", "501"),
            sp + "/Streams": ("700", "1:8", "501"),
        }
        state.write_text("".join("\t".join([p, *row]) + "\n" for p, row in before.items()), encoding="utf-8")
        wrapper.write_text("export PATH=/usr/bin:/bin\n" + shims + "\n" + original, encoding="utf-8", newline="\n")
        environment = dict(os.environ, AUDIT_STATE=posix(state), AUDIT_CALLS=posix(calls), AUDIT_BACKUP=posix(backup))

        def run(*args):
            return subprocess.run([str(SHELL), str(wrapper), *args], env=environment,
                                  capture_output=True, text=True, encoding="utf-8")

        def states():
            return {row[0]: row[1:] for line in state.read_text(encoding="utf-8").splitlines()
                    if (row := line.split("\t"))}

        result = run("--apply", sp, selectedp)
        assert result.returncode == 0, result.stderr
        after = states()
        assert after[sp][0] == "0711" and after[selectedp][0] == "0644"
        assert after[sp + "/CameraConfig.plist"][0] == "0644"
        assert after[sp + "/Media"][0] == after[sp + "/Media/nested"][0] == "0755"
        assert all(tuple(after[p]) == before[p] for p in before if p.endswith(("AuthSession.plist", "CapabilityLease.plist", "Streams")))
        results["apply_scoped_to_config_selected_media_and_traversal"] = True
        results["credential_and_stream_modes_unchanged"] = True
        manifest = backup / "modes.tsv"
        recorded = [line for line in manifest.read_text().splitlines() if not line.startswith("#")]
        assert len(recorded) == 5
        # Simulate atomic publication replacing the selected file's inode.
        changed = state.read_text().replace(selectedp + "\t0644\t1:4\t", selectedp + "\t0644\t1:44\t")
        state.write_text(changed)
        result = run("--restore", posix(manifest))
        assert result.returncode == 0 and "SKIPPED changed/replaced target" in result.stderr, result.stderr
        restored = states()
        assert restored[selectedp][0] == "0644"
        assert all(tuple(restored[p]) == before[p] for p in before if p != selectedp)
        results["rollback_restores_original_modes_and_skips_replaced_inode"] = True
        size = calls.stat().st_size
        outside = base / "outside.jpg"
        outside.write_bytes(b"fixture")
        denied = run("--apply", sp, posix(outside))
        assert denied.returncode == 2 and calls.stat().st_size == size
        results["out_of_scope_media_rejected_before_changes"] = True
        denied = run("--apply", sp, selectedp + "\nnot-a-path")
        assert denied.returncode == 2 and calls.stat().st_size == size
        results["newline_path_rejected_before_changes"] = True
    report = {"method": "Git POSIX shell with mocked Darwin identity/stat/chmod/mktemp; synthetic files only",
              "ios_executed": False, "actual_darwin_permissions_verified": False,
              "test_count": len(results), "tests": results, "passed": True,
              "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HELPERS.glob("*.sh")}}
    output = ROOT / "docs/evidence/camera_diagnosis/helper_tests.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
