"""Local, redacted precommit gate. Never stages, commits, pushes or contacts services.

Before Git initialization it uses disposable Git metadata to evaluate the actual
ignore rules. Afterwards it also examines index blobs and reachable history.
Only derived manifests/evidence are written; credentials are never printed.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import tarfile
import zipfile

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/git_precommit"
LIST = ROOT / "docs/GIT_STAGING_APPROVED.txt"
MANIFEST = ROOT / "docs/GIT_STAGING_MANIFEST.json"
MAX_BLOB = 20 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
PATTERNS = {
    "telegram_bot_token": rb"(?<![A-Za-z0-9_])[0-9]{6,12}:[A-Za-z0-9_-]{30,60}(?![A-Za-z0-9_-])",
    "aws_access_key_id": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "github_token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{50,255})\b",
    "slack_token": rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
    "private_pem_block": rb"-----BEGIN ((?:[A-Z0-9]+ )?PRIVATE KEY)-----[\s\S]{32,65536}?-----END \1-----",
    "private_pem_header": rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----",
    "openssh_private_binary": rb"openssh-key-v1\x00",
    "sqlite_database_bytes": rb"SQLite format 3\x00",
    "credential_in_url": rb"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb)://[^\s/:@]{1,80}:[^\s/@]{1,160}@",
    "aws_secret_assignment": rb"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}\b",
}
RULES = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}
SENSITIVE_NAME = re.compile(
    r"(?i)(?:\.(?:pem|key|ppk|p12|pfx|jks|keystore|mobileprovision|db|sql|dump)$|"
    r"\.db-|\.sqlite|(?:^|/)(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)|"
    r"(?:^|/)\.env(?:$|\.)|\.env$|(?:^|/)(?:AuthSession|CapabilityLease)(?:_sample)?\.plist$)"
)
PROBES = {
    "NGUYEN VAN HIEU.pem": True,
    "server/server_private_key.pem": True,
    "server/key.ppk": True,
    "server/vcnext.env": True,
    "server/.env.production": True,
    "server/vcnext.env.local": True,
    "server/licenses.db": True,
    "server/licenses.db-wal": True,
    "server/licenses.db-shm": True,
    "server/snapshot.sqlite3-wal": True,
    "scripts/__pycache__/a.pyc": True,
    ".codex-backups/auth-refactor-20261021/source-before.zip": True,
    "docs/evidence/capture.json": True,
    "dist/VCNext-server-auth-refactor.zip": True,
    "extracted/data/Applications/VCNext.app/VCNext": True,
    "mocks/test_server_private_key.pem": True,
    "server/vcnext.env.example": False,
    "server/server.py": False,
    "scripts/audit_git_precommit.py": False,
    "docs/CODEX_GIT_PRECOMMIT_AUDIT.md": False,
    "dist/VCAMPLUS-roothide.deb": False,
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_git(prefix, args, data=None, check=True):
    result = subprocess.run(prefix + args, input=data, capture_output=True)
    if check and result.returncode:
        # Never forward subprocess output: object/path content could be sensitive.
        raise RuntimeError("Git metadata query failed: " + args[0])
    return result


def der_sequences(data):
    for match in re.finditer(b"\x30", data):
        start = match.start()
        if start + 2 >= len(data):
            continue
        first = data[start + 1]
        if first < 128:
            length, header = first, 2
        else:
            size = first & 127
            if not 1 <= size <= 4 or start + 2 + size > len(data):
                continue
            length = int.from_bytes(data[start + 2:start + 2 + size], "big")
            header = 2 + size
        end = start + header + length
        if 32 <= length <= 16384 and end <= len(data):
            # Private PKCS1/SEC1/PKCS8 start with a version integer; encrypted
            # PKCS8 starts with an algorithm sequence. Parsing rejects others.
            if data[start + header] in (2, 48):
                yield start, data[start:end]


def secret_scan(label, data, findings):
    label = safe_label(label)
    if len(data) > MAX_BLOB:
        findings.append({"path": label, "category": "blob_limit_exceeded"})
        return
    for name, rule in RULES.items():
        for match in rule.finditer(data):
            findings.append({"path": label, "category": name,
                             "offset": match.start(), "line": data[:match.start()].count(b"\n") + 1})
    for offset, value in der_sequences(data):
        try:
            serialization.load_der_private_key(value, password=None)
        except TypeError:
            # A syntactically admitted encrypted key without its password.
            findings.append({"path": label, "category": "encrypted_der_private_key", "offset": offset})
        except (ValueError, OverflowError):
            pass
        else:
            findings.append({"path": label, "category": "der_private_key", "offset": offset})


def safe_label(label):
    raw = label.encode("utf-8", "replace")
    if any(rule.search(raw) for rule in RULES.values()):
        return "[redacted-path-sha256:" + digest(raw) + "]"
    return label


def scan_carrier(label, data, findings, archive_rows, budget, depth=0):
    secret_scan("path-metadata", label.encode("utf-8", "replace"), findings)
    label = safe_label(label)
    budget[0] += len(data)
    if budget[0] > MAX_EXPANDED or depth > 3:
        findings.append({"path": label, "category": "archive_scan_limit_exceeded"})
        return
    secret_scan(label, data, findings)
    if data.startswith(b"!<arch>\n"):
        position, count, member_names = 8, 0, []
        while position < len(data):
            header = data[position:position + 60]
            assert len(header) == 60 and header[58:] == b"`\n"
            name = header[:16].decode("ascii").strip().removesuffix("/")
            member_names.append(name)
            size = int(header[48:58]); start = position + 60
            assert size >= 0 and start + size <= len(data)
            scan_carrier(label + "!" + name, data[start:start + size], findings, archive_rows, budget, depth + 1)
            position = start + size + size % 2; count += 1
        assert position == len(data)
        if label.lower().endswith(".deb"):
            assert member_names == ["debian-binary", "control.tar.zst", "data.tar.zst"], "Unexpected Debian carrier layout"
        archive_rows.append({"path": label, "format": "ar", "members": count})
    elif data.startswith(b"\x28\xb5\x2f\xfd"):
        from compression import zstd
        with zstd.ZstdFile(io.BytesIO(data)) as stream:
            expanded = stream.read(MAX_EXPANDED + 1)
        if len(expanded) > MAX_EXPANDED:
            findings.append({"path": label, "category": "zstd_limit_exceeded"})
            return
        scan_tar(label, expanded, findings, archive_rows, budget, depth + 1)
    elif data.startswith((b"\x1f\x8b", b"\xfd7zXZ\x00", b"BZh")):
        opener, kind = ((gzip.GzipFile, "gzip") if data.startswith(b"\x1f\x8b") else
                        (lzma.LZMAFile, "xz") if data.startswith(b"\xfd7zXZ\x00") else
                        (bz2.BZ2File, "bzip2"))
        with (opener(fileobj=io.BytesIO(data)) if kind == "gzip" else opener(io.BytesIO(data))) as stream:
            expanded = stream.read(MAX_EXPANDED + 1)
        if len(expanded) > MAX_EXPANDED:
            findings.append({"path": label, "category": "compressed_scan_limit_exceeded"})
            return
        scan_carrier(label + "!" + kind, expanded, findings, archive_rows, budget, depth + 1)
        archive_rows.append({"path": label, "format": kind, "expanded_bytes": len(expanded)})
    elif data[257:262] == b"ustar":
        scan_tar(label, data, findings, archive_rows, budget, depth + 1)
    elif zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                if member.flag_bits & 1 or member.file_size > MAX_BLOB:
                    findings.append({"path": label + "!" + member.filename, "category": "unscannable_zip_member"})
                    continue
                child = label + "!" + member.filename
                if SENSITIVE_NAME.search(member.filename):
                    findings.append({"path": child, "category": "sensitive_archive_member_name"})
                scan_carrier(child, archive.read(member), findings, archive_rows, budget, depth + 1)
            archive_rows.append({"path": label, "format": "zip", "members": len(archive.infolist())})
    elif data.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")):
        findings.append({"path": label, "category": "unsupported_archive_carrier"})
    elif label.lower().endswith((".deb", ".zip", ".tar", ".zst", ".gz", ".xz", ".bz2", ".7z", ".rar")):
        findings.append({"path": label, "category": "unrecognized_or_corrupt_archive_carrier"})


def scan_tar(label, data, findings, archive_rows, budget, depth):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            assert not path.is_absolute() and ".." not in path.parts
            if not member.isfile():
                continue
            child = label + "!" + member.name
            if SENSITIVE_NAME.search(member.name):
                findings.append({"path": child, "category": "sensitive_archive_member_name"})
            if member.size > MAX_BLOB:
                findings.append({"path": child, "category": "archive_member_limit_exceeded"})
                continue
            scan_carrier(child, archive.extractfile(member).read(), findings, archive_rows, budget, depth)
        archive_rows.append({"path": label, "format": "tar", "members": len(members)})


def audit(prefix, real_repository):
    findings, archive_rows = [], []
    for path, expected in PROBES.items():
        status = run_git(prefix, ["check-ignore", "--no-index", "-q", "--", path], check=False).returncode
        assert status in (0, 1) and (status == 0) == expected, path
    prospective = run_git(prefix, ["ls-files", "--cached", "--others", "--exclude-standard", "-z"]).stdout
    approved = sorted(set(p.decode("utf-8") for p in prospective.split(b"\0") if p))
    records = []
    for relative in approved:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            findings.append({"path": relative, "category": "unapproved_link_or_missing_file"})
            continue
        ignored = run_git(prefix, ["check-ignore", "--no-index", "-q", "--", relative], check=False).returncode == 0
        if ignored:
            findings.append({"path": relative, "category": "tracked_despite_ignore_policy"})
        data = path.read_bytes()
        scan_carrier(relative, data, findings, archive_rows, [0])
        records.append({"path": safe_label(relative), "bytes": len(data), "sha256": digest(data)})

    index_count = history_count = history_metadata_count = 0
    if real_repository:
        entries = run_git(prefix, ["ls-files", "--stage", "-z"]).stdout.split(b"\0")
        for entry in entries:
            if not entry:
                continue
            metadata, path = entry.split(b"\t", 1)
            mode, oid, stage = metadata.split()
            label = "index:" + path.decode("utf-8")
            if stage != b"0" or mode not in (b"100644", b"100755"):
                findings.append({"path": label, "category": "unapproved_index_entry"})
                continue
            scan_carrier(label, run_git(prefix, ["cat-file", "blob", oid.decode()]).stdout, findings, archive_rows, [0])
            index_count += 1
        history = run_git(prefix, ["rev-list", "--objects", "--all"]).stdout.splitlines()
        for entry in history:
            parts = entry.split(b" ", 1)
            oid = parts[0].decode()
            kind = run_git(prefix, ["cat-file", "-t", oid]).stdout.strip()
            if kind in (b"commit", b"tag"):
                secret_scan("history-metadata-object:" + oid, run_git(prefix, ["cat-file", "-p", oid]).stdout, findings)
                history_metadata_count += 1
            if kind != b"blob":
                continue
            if len(parts) == 2:
                historical_path = parts[1].decode("utf-8", "replace")
                secret_scan("history-path-metadata", parts[1], findings)
                if (SENSITIVE_NAME.search(historical_path) or
                    run_git(prefix, ["check-ignore", "--no-index", "-q", "--", historical_path], check=False).returncode == 0):
                    findings.append({"path": "history-object:" + oid,
                                     "category": "historical_sensitive_or_ignored_path"})
            size = int(run_git(prefix, ["cat-file", "-s", oid]).stdout)
            if size > MAX_BLOB:
                findings.append({"path": "history-object:" + oid, "category": "history_blob_limit_exceeded"})
                continue
            scan_carrier("history-object:" + oid, run_git(prefix, ["cat-file", "blob", oid]).stdout, findings, archive_rows, [0])
            history_count += 1

    result = {"method": "Exact Git ignore evaluation, prospective/index/history byte scans and recursive approved archives",
              "network_or_service_calls": False, "workspace_git_initialized": real_repository,
              "staged_blob_count_checked": index_count, "reachable_history_blobs_checked": history_count,
              "reachable_commit_tag_messages_checked": history_metadata_count,
              "ignore_probe_count": len(PROBES), "prospective_file_count": len(approved),
              "findings": findings, "archive_scans": archive_rows,
              "zero_unresolved_findings": not findings,
              "limitations": ["Pattern and DER parsing coverage is finite; no timeless zero-risk guarantee.",
                              "Encrypted/nonstandard/obfuscated credentials can evade these checks.",
                              "No remote GitHub settings, remote history or deployment hooks inspected.",
                              "New or modified content requires rescanning; --force can defeat ignores."]}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "staging_scan.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if findings:
        print(json.dumps({"passed": False, "finding_count": len(findings), "findings": findings}, indent=2))
        return 1
    # A manifest cannot include its own digest. Both generated manifest paths
    # are explicitly listed; other file digests are exact working-tree bytes.
    names = sorted(set(approved) | {LIST.relative_to(ROOT).as_posix(), MANIFEST.relative_to(ROOT).as_posix()})
    LIST.write_text("\n".join(names) + "\n", encoding="utf-8", newline="\n")
    nonself = [r for r in records if r["path"] not in (LIST.relative_to(ROOT).as_posix(), MANIFEST.relative_to(ROOT).as_posix())]
    list_raw = LIST.read_bytes()
    nonself.append({"path": LIST.relative_to(ROOT).as_posix(), "bytes": len(list_raw), "sha256": digest(list_raw)})
    manifest = {"approved_count": len(names), "approved_paths": names, "files": sorted(nonself, key=lambda r: r["path"]),
                "manifest_self_hash": "Excluded to avoid a circular checksum; scan before staging.",
                "scope": "Exact inspected snapshot only", "zero_unresolved_secret_findings": True}
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "approved_file_count": len(names), "ignore_probes_passed": len(PROBES),
                      "staged_blobs_scanned": index_count, "reachable_history_blobs_scanned": history_count,
                      "workspace_git_created_by_audit": False, "secrets_printed": False}, indent=2))
    return 0


def main():
    check = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"], capture_output=True)
    if check.returncode == 0:
        assert Path(check.stdout.decode().strip()).resolve() == ROOT
        return audit(["git", "-c", "core.excludesFile=" + os.devnull, "-C", str(ROOT)], True)
    with tempfile.TemporaryDirectory(prefix="vcnext-precommit-metadata-") as directory:
        subprocess.run(["git", "-c", "init.templateDir=", "init", "--bare", "--quiet", directory],
                       check=True, capture_output=True)
        prefix = ["git", "-c", "core.excludesFile=" + os.devnull,
                  "--git-dir=" + directory, "--work-tree=" + str(ROOT)]
        return audit(prefix, False)


if __name__ == "__main__":
    raise SystemExit(main())
