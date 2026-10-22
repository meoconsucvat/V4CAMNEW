"""Build a verified, secret-free source release; never contacts the VPS."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist"
NAME = "VCNext-server-auth-refactor"
PRODUCT = ["store.py", "server.py", "notify.py", "telegram_bot.py"]
SUPPORT = ["vcnext.service", "vcnext-bot.service", "vcnext.env.example", "DEPLOY_AUTH_REFACTOR.md"]
RUNNERS = ["test_store_auth_transactions.py", "test_auth_device_locking.py", "audit_login_notifications_isolated.py"]
EVIDENCE = ["docs/evidence/auth_refactor/store_transactions.json",
            "docs/evidence/auth_refactor/integration_tests.json",
            "docs/evidence/telegram_audit/login_alert_tests.json"]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    payloads = {"server/" + name: (ROOT / "server" / name).read_bytes()
                for name in PRODUCT + SUPPORT}
    payloads.update({"scripts/" + name: (ROOT / "scripts" / name).read_bytes() for name in RUNNERS})
    payloads.update({name: (ROOT / name).read_bytes() for name in EVIDENCE})
    payloads["README.md"] = (
        b"# Archive layout\n\nCopy the files inside server/ to /opt/vcnext_server/ "
        b"only after following the guide below. Run scripts/ verification from "
        b"this unpacked staging directory, never by importing production modules.\n\n"
        + payloads["server/DEPLOY_AUTH_REFACTOR.md"])
    hashes = {name: digest(payloads["server/" + name]) for name in PRODUCT}
    store, integration, alerts = [json.loads(payloads[name]) for name in EVIDENCE]
    assert store["passed"] is True and integration["passed"] is True
    assert alerts["passed"] == len(alerts["tests"])
    assert store["source_sha256"] == hashes["store.py"]
    assert all(hashes[name] == expected for name, expected in integration["source_sha256"].items())
    assert all(hashes[name] == expected for name, expected in alerts["source_sha256"].items())
    for unit in ("vcnext.service", "vcnext-bot.service"):
        assert b"EnvironmentFile=/opt/vcnext_server/vcnext.env" in payloads["server/" + unit]
    token_pattern = re.compile(rb"\b[0-9]{6,}:[A-Za-z0-9_-]{25,}\b")
    assert not any(token_pattern.search(data) for data in payloads.values())
    assert not any(name.endswith((".db", ".pem", ".deb", "vcnext.env")) for name in payloads)
    for name, data in payloads.items():
        if name.endswith(".py"):
            compile(data.decode("utf-8"), name, "exec")
    manifest = {
        "release_date": "2026-10-21", "timezone": "Asia/Saigon",
        "target_host": "13.238.38.121", "install_directory": "/opt/vcnext_server/",
        "production_deployed": False, "telegram_requests_made_during_verification": 0,
        "source_sha256": hashes,
        "verification": {"store_checks": store["test_count"],
                         "http_groups": len(integration["tests"]), "bot_alert_checks": alerts["passed"],
                         "expected_mocked_alerts": integration["notification_expected_calls"],
                         "mocked_deliveries": integration["notification_transport_deliveries"],
                         "all_suites_exit_code": 0},
        "files": {name: {"sha256": digest(data), "bytes": len(data)}
                  for name, data in sorted(payloads.items())},
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    payloads["MANIFEST.json"] = manifest_bytes
    OUT.mkdir(exist_ok=True)
    archive_path = OUT / (NAME + ".zip")
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(payloads.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 21, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.testzip() is None
        assert all(archive.read(name) == data for name, data in payloads.items())
    (OUT / (NAME + ".manifest.json")).write_bytes(manifest_bytes)
    print(json.dumps({"archive": str(archive_path), "sha256": digest(archive_path.read_bytes()),
                      "bytes": archive_path.stat().st_size, "members": len(payloads),
                      "verification": manifest["verification"]}, indent=2))


if __name__ == "__main__":
    main()
