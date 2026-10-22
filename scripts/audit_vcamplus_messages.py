#!/usr/bin/env python3
"""Offline, secret-free VCAMPLUS presentation checks against current source.

AST loading omits store's import-time init_db(), server's private-key load,
relative imports, environment-dependent seeding, and notify's atexit hook.
All database writes use a temporary fixture; Telegram is a fake transport.
No HTTP listener, production API request, environment lookup or key read occurs.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
from pathlib import Path
import tempfile
import types

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/vcamplus/messages_verification.json"
CONTACT = "Liên Hệ Telegram: @vcamplus"
EXPECTED = {
    "wrong_password": "Sai mật khẩu đăng nhập!\n" + CONTACT,
    "invalid_credentials": "Tài khoản chưa được đăng ký!\n" + CONTACT,
    "account_expired": "Tài khoản đã hết hạn sử dụng!\n" + CONTACT,
    "device_limit_reached": "Đã đủ số thiết bị đăng ký!\n" + CONTACT,
    "account_disabled": "Tài khoản đang bị tạm khóa!\n" + CONTACT,
    "device_bound_to_other_user": "Thiết bị đã gắn với tài khoản khác!\n" + CONTACT,
}


def load_source(name: str, supplied: dict | None = None):
    path = ROOT / "server" / (name + ".py")
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    body = []
    for node in tree.body:
        if isinstance(node, (ast.Expr, ast.With)):
            continue
        if name == "server" and isinstance(node, ast.Try):
            continue  # The relative store/notify imports would run module I/O.
        if name == "server" and isinstance(node, ast.If) and node.lineno == 44:
            continue  # Validation of the intentionally omitted private key.
        if name == "store" and isinstance(node, ast.FunctionDef) and node.name == "init_db":
            # Only schema/migration setup in this temporary fixture. Omit the
            # optional environment-controlled developer-account seed.
            node.body[0].body = [part for part in node.body[0].body if part.lineno < 409]
        body.append(node)
    module = types.ModuleType("vcamplus_offline_" + name)
    module.__file__ = str(path)
    module.__dict__.update(supplied or {})
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), "exec"), module.__dict__)
    return module


def inventory(path: Path) -> list[dict]:
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    result = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and
                ((isinstance(node.func, ast.Name) and node.func.id == "AuthError") or
                 (isinstance(node.func, ast.Attribute) and node.func.attr == "AuthError")) and
                len(node.args) >= 3):
            try:
                status, code, message = [ast.literal_eval(arg) for arg in node.args[:3]]
            except (ValueError, TypeError):
                continue
            result.append({"source": path.relative_to(ROOT).as_posix(), "line": node.lineno,
                           "status": status, "code": code, "message": message,
                           "source_lines": len(message.splitlines()),
                           "support_contact": CONTACT in message})
    return sorted(result, key=lambda value: value["line"])


def main():
    checks = []
    def check(label, actual, expected=True):
        passed = actual == expected
        checks.append({"test": label, "pass": passed, "actual": actual, "expected": expected})
        if not passed:
            raise AssertionError(label)

    sources = {str(Path("server") / name): hashlib.sha256((ROOT / "server" / name).read_bytes()).hexdigest()
               for name in ("store.py", "server.py", "notify.py", "telegram_bot.py")}
    store = load_source("store")
    fake_alerts = []
    notify_stub = types.SimpleNamespace(
        notify_login_success=lambda *args, **kwargs: fake_alerts.append(("success", args, kwargs)),
        notify_login_fail=lambda *args, **kwargs: fake_alerts.append(("failure", args, kwargs)))
    server = load_source("server", {"store": store, "notify": notify_stub})
    records = inventory(ROOT / "server/store.py") + inventory(ROOT / "server/server.py")
    check("all_literal_autherror_wire_codes_lowercase", all(row["code"] == row["code"].lower() for row in records))
    legacy = {"INVALID_CREDENTIALS", "DEVICE_LIMIT"}
    check("no_literal_autherror_code_matches_client_legacy_suffix", not any(row["code"] in legacy for row in records))

    cases = []
    def capture(label, function):
        try:
            function()
        except store.AuthError as error:
            cases.append({"label": label, "status": error.status, "code": error.code, "message": error.message})
            check("manual_" + label, [error.status, error.message], [403, EXPECTED[error.code]])
        else:
            raise AssertionError(label + " accepted unexpectedly")

    with tempfile.TemporaryDirectory(prefix="vcamplus-message-audit-") as directory:
        store.DB_PATH = str(Path(directory) / "fixture.db")
        store.init_db()
        user = store.create_user("audituser", "synthetic-password", max_devices=1)
        ts = store.now()
        capture("unknown_account", lambda: store._require_live_user(None, ts))
        capture("disabled_account", lambda: store._require_live_user(dict(user, enabled=0), ts))
        capture("expired_account", lambda: store._require_live_user(dict(user, expires_at=ts), ts))
        with store.connect() as con:
            con.execute("INSERT INTO devices(device_id,username,enabled,first_seen,last_seen) VALUES (?,?,1,?,?)",
                        ("SYNTHETIC-A", "audituser", ts, ts))
            capture("quota", lambda: store._check_device_in_tx(con, user, "SYNTHETIC-B"))
            capture("cross_account", lambda: store._check_device_in_tx(con, dict(user, username="otheruser"), "SYNTHETIC-A"))
            con.execute("INSERT INTO challenges(challenge_id,device_id,username,thumbprint,nonce,expires_at,payload_json,device_public_key,auth_epoch) VALUES (?,?,?,?,?,?,?,?,?)",
                        ("synthetic-challenge", "SYNTHETIC-A", "audituser", "synthetic-thumbprint",
                         "synthetic-nonce", ts + 90, "{}", "synthetic-key", 1))
        capture("wrong_password", lambda: store.complete_login("synthetic-challenge", "SYNTHETIC-A", "incorrect", "synthetic-nonce", lambda *args: True))
        helper = store.validate_credentials("unknownfixture", "synthetic-password")
        check("user_not_found_is_helper_code_without_http_message", helper[2], "user_not_found")

    wire = []
    for case in cases:
        handler = object.__new__(server.VCNextRequestHandler)
        handler._login_event_pending = True
        handler._request_path = "/api/v2/auth/login"
        handler._request_body = {"username": "audituser", "device_id": "SYNTHETIC-A", "device_name": "Synthetic iPhone"}
        handler.headers = {}
        handler.client_address = ("127.0.0.1", 12345)
        handler.wfile = io.BytesIO()
        headers = {}
        statuses = []
        handler.send_response = statuses.append
        handler.send_header = headers.__setitem__
        handler.end_headers = lambda: None
        before = len(fake_alerts)
        payload = {"ok": False, "error": case["code"], "message": case["message"]}
        handler._send_json(case["status"], payload)
        raw = handler.wfile.getvalue()
        check("wire_" + case["label"], json.loads(raw), payload)
        check("byte_length_" + case["label"], int(headers["Content-Length"]), len(raw))
        check("utf8_content_type_" + case["label"], headers["Content-Type"], "application/json; charset=utf-8")
        check("status_unchanged_" + case["label"], statuses, [403])
        check("one_dispatch_" + case["label"], len(fake_alerts) - before, 1)
        handler._send_json(case["status"], payload)
        check("same_response_flag_not_double_dispatched_" + case["label"], len(fake_alerts) - before, 1)
        wire.append({"condition": case["label"], "code": case["code"], "message": case["message"],
                     "body_bytes": len(raw), "source_lines": len(case["message"].splitlines())})

    # Exercise the real background worker with an explicitly fake credential and
    # dependency-injected transport. No environment lookup or network is used.
    notify = load_source("notify")
    telegram_calls = []
    def fake_transport(method, payload, _fake_token, _timeout):
        telegram_calls.append({"method": method, "payload": payload})
        if method == "getMe":
            return {"ok": True, "result": {"is_bot": True, "username": "VCAM_V5_ADMIN_BOT"}}
        return {"ok": True, "result": {"message_id": len(telegram_calls)}}
    dispatcher = notify._Dispatcher("synthetic-not-a-real-credential", transport=fake_transport)
    try:
        check("fake_worker_enqueues", dispatcher.enqueue(notify._message(False, "<audit>", "SYNTHETIC-A", "127.0.0.1", "Synthetic iPhone", "wrong_password")))
        check("fake_worker_flush", dispatcher.flush(2.0))
        check("fake_worker_methods", [row["method"] for row in telegram_calls], ["getMe", "sendMessage"])
        check("fake_worker_fixed_owner", telegram_calls[1]["payload"]["chat_id"], 5137016124)
        check("fake_worker_html_escaped", "&lt;audit&gt;" in telegram_calls[1]["payload"]["text"])
        check("fake_worker_brand", "VCAMPLUS · vc.huxa.xyz" in telegram_calls[1]["payload"]["text"])
    finally:
        check("fake_worker_stopped", dispatcher.shutdown(2.0))
    check("unknown_account_telegram_reason_is_generic", "Đăng nhập không hợp lệ" in notify._message(False, "audit", "SYNTHETIC-A", "127.0.0.1", reason="invalid_credentials"))

    # The same semantic codes also have unbranded session/expiry variants.
    session = {"renewal_token": "synthetic-renewal", "access_token": "synthetic-access",
               "device_owner": "audituser", "username": "audituser", "device_enabled": 1,
               "account_enabled": 1, "account_expires": ts + 3600, "expires_at": ts + 3600,
               "auth_epoch": 1, "account_epoch": 1, "enrolled_key": "synthetic-key",
               "enrolled_thumb": "synthetic-thumb", "thumbprint": "synthetic-thumb"}
    unbranded_runtime = []
    for label, operation in (
        ("build_auth_response_expired", lambda: server.build_auth_response({"expires_at": ts}, {}, issued_at=ts)),
        ("refresh_owner_changed", lambda: server._validate_session(dict(session, device_owner="otheruser"), "synthetic-access", "heartbeat", ts)),
        ("refresh_account_disabled", lambda: server._validate_session(dict(session, account_enabled=0), "synthetic-access", "heartbeat", ts)),
        ("refresh_account_expired", lambda: server._validate_session(dict(session, account_expires=ts), "synthetic-access", "heartbeat", ts)),
    ):
        try:
            operation()
        except store.AuthError as error:
            check("observed_unbranded_" + label, CONTACT not in error.message)
            unbranded_runtime.append({"condition": label, "status": error.status, "code": error.code, "message": error.message})
        else:
            raise AssertionError(label + " unexpectedly accepted")

    # A successful challenge is deliberately silent. A successful login queues
    # one success event, while failures at either login stage queue one failure.
    for endpoint, status, expected_kind in (
        ("challenge", 200, None), ("challenge", 403, "failure"),
        ("login", 200, "success"), ("login", 403, "failure"),
    ):
        handler = object.__new__(server.VCNextRequestHandler)
        handler._login_event_pending = True
        handler._request_path = "/api/v2/auth/" + endpoint
        handler._request_body = {"username": "audituser", "device_id": "SYNTHETIC-A"}
        handler.headers = {}
        handler.client_address = ("127.0.0.1", 12345)
        handler.wfile = io.BytesIO()
        handler.send_response = lambda code: None
        handler.send_header = lambda key, value: None
        handler.end_headers = lambda: None
        before = len(fake_alerts)
        handler._send_json(status, {"user": {"username": "audituser"}, "error": "wrong_password"})
        actual = fake_alerts[-1][0] if len(fake_alerts) > before else None
        check("dispatch_" + endpoint + "_" + str(status), actual, expected_kind)

    check("source_sha256_unchanged", sources, {
        str(Path("server") / name): hashlib.sha256((ROOT / "server" / name).read_bytes()).hexdigest()
        for name in ("store.py", "server.py", "notify.py", "telegram_bot.py")})

    # Deliberately record noncompliant remaining paths as findings, not as
    # expected requirements that could falsely pass the overall integration.
    missing = [row for row in records if row["code"] in EXPECTED and not row["support_contact"]]
    result = {"audit_scope": "offline source AST, temporary SQLite fixture, fake Telegram only",
              "source_sha256": sources, "checks": checks, "passed_checks": len(checks),
              "all_test_assertions_pass": True, "all_relevant_error_paths_have_brand_contact": not missing,
              "manual_error_cases": wire, "unbranded_relevant_error_paths": missing,
              "unbranded_runtime_reproductions": unbranded_runtime,
              "all_literal_auth_errors": records,
              "limitations": ["No production HTTPS/VPS/Telegram calls", "No iOS screen or UIKit layout test",
                              "Two newline-separated source lines do not prove two rendered lines",
                              "Notification enqueue/delivery is best effort; no durable or exactly-once delivery claim",
                              "Client legacy comparison evidence is prior saved static decompilation"]}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed_checks": len(checks), "manual_cases": len(wire),
                      "unbranded_paths": len(missing), "output": str(OUT)}))


if __name__ == "__main__":
    main()
