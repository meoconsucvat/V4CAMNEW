"""Offline regression checks for login alerts and owner-only Telegram dispatch.

Never imports production store.py, reads dotenv/DB/key files, or contacts Telegram.
The process environment is replaced before loading the two modules under test.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import logging
import os
import re
from pathlib import Path
import sys
import threading
import time
import types
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
OWNER = 5137016124
TEST_TOKEN = "synthetic-unit-test-credential"
RESULTS: dict[str, object] = {"network_calls": 0, "production_store_imported": False,
                              "production_database_accessed": False, "tests": {}}


def check(name, predicate):
    assert predicate, name
    RESULTS["tests"][name] = True


class FakeStore(types.ModuleType):
    def __init__(self, name):
        super().__init__(name)
        self.devices = [
            {"device_id": "fixture-device-on", "device_name": "Phone <one>", "enabled": 1, "last_seen": 900},
            {"device_id": "fixture-device-off", "device_name": "Phone &two", "enabled": 0, "last_seen": 800},
        ]
        self.states = {}
        self.mutations = []
        self.audits = []
        self.user_enabled = 1

    def now(self):
        return 1000

    def normalize_username(self, value):
        return str(value).strip().lower()

    def get_user(self, username):
        if username != "fixtureuser":
            return None
        return {"username": username, "enabled": self.user_enabled, "expires_at": 200000,
                "max_devices": 3, "note": "<fixture>", "total_devices": len(self.devices),
                "active_devices": sum(d["enabled"] == 1 for d in self.devices)}

    def list_users(self, limit=50):
        return [self.get_user("fixtureuser")]

    def list_devices(self, username):
        return [dict(d) for d in self.devices]

    def get_bot_state(self, key, default=""):
        return self.states.get(key, default)

    def set_bot_state(self, key, value):
        self.states[key] = value

    def delete_bot_state(self, key):
        self.states.pop(key, None)

    def consume_confirmation(self, actor, code):
        return "devices_reset", {"username": "fixtureuser"}

    def reset_devices(self, username, actor):
        previous = len(self.devices)
        self.devices.clear()
        self.mutations.append(("reset", username))
        return previous

    def audit(self, *args):
        self.audits.append(args)

    def backup_database(self, path):
        Path(path).write_bytes(b"synthetic-snapshot-not-a-production-database")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run():
    sources = {name: ROOT / "server" / name for name in ("notify.py", "telegram_bot.py")}
    for source in sources.values():
        ast.parse(source.read_text(encoding="utf-8"))
    package = types.ModuleType("vcnext_alert_test")
    package.__path__ = [str(ROOT / "server")]
    sys.modules[package.__name__] = package
    store = FakeStore(package.__name__ + ".store")
    sys.modules[store.__name__] = store
    package.store = store

    def reject_network(*args, **kwargs):
        RESULTS["network_calls"] += 1
        raise AssertionError("Real network is forbidden by this test")

    env = {"TELEGRAM_BOT_TOKEN": TEST_TOKEN,
           "TELEGRAM_OWNER_IDS": "999", "TELEGRAM_ADMIN_IDS": "998",
           "TELEGRAM_OPERATOR_IDS": "997", "TELEGRAM_VIEWER_IDS": "996",
           "TELEGRAM_PRIVATE_ONLY": "0"}
    with mock.patch.dict(os.environ, env, clear=True), \
            mock.patch("urllib.request.urlopen", side_effect=reject_network):
        notify = load(package.__name__ + ".notify", sources["notify.py"])
        bot = load(package.__name__ + ".telegram_bot", sources["telegram_bot.py"])
        check("import_starts_no_worker_or_network", notify._dispatcher is None and RESULTS["network_calls"] == 0)
        check("single_owner_private_even_with_hostile_env", bot.OWNER_IDS == {OWNER}
              and not bot.OPERATOR_IDS and not bot.VIEWER_IDS and bot.PRIVATE_ONLY)

        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        notify.LOG.addHandler(handler)
        notify.LOG.setLevel(logging.ERROR)
        try:
            with mock.patch.dict(os.environ, {}, clear=True):
                check("missing_token_disables_without_exception", notify.notify_login_success("fixtureuser", "fixture", "127.0.0.1") is False)
            check("missing_token_no_worker", notify._dispatcher is None)

            delivered = []
            calls = []

            def transport(method, payload, token, timeout):
                calls.append(method)
                assert token == TEST_TOKEN
                assert 0 < timeout <= 3
                if method == "getMe":
                    return {"ok": True, "result": {"is_bot": True, "username": "VCAM_V5_ADMIN_BOT"}}
                delivered.append(dict(payload))
                return {"ok": True, "result": {"message_id": len(delivered)}}

            worker = notify._Dispatcher(TEST_TOKEN, transport=transport)
            notify._dispatcher = worker
            try:
                check("success_enqueued", notify.notify_login_success("<user&>", "id<one>", "127.0.0.1", "Phone & One"))
                check("failure_enqueued", notify.notify_login_fail("fixtureuser", "id", "127.0.0.1", "wrong_password", "phone"))
                check("unknown_reason_enqueued", notify.notify_login_fail("fixtureuser", "id", "127.0.0.1", "password=never-relay-this"))
                check("all_alerts_attempted_no_cooldown", worker.flush(2) and len(delivered) == 3)
                check("identity_verified_once", calls.count("getMe") == 1)
                check("fixed_owner_html_and_timezone", all(item["chat_id"] == OWNER and item["parse_mode"] == "HTML"
                      and "Asia/Ho_Chi_Minh" in item["text"] and "+0700" in item["text"] for item in delivered))
                check("timestamp_matches_requested_format", bool(re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+0700", delivered[0]["text"])))
                check("html_escaped", "&lt;user&amp;&gt;" in delivered[0]["text"]
                      and "Phone &amp; One" in delivered[0]["text"] and "<user&>" not in delivered[0]["text"])
                check("failure_reason_allowlist", "Sai mật khẩu" in delivered[1]["text"]
                      and "never-relay-this" not in delivered[2]["text"])
                check("store_reason_aliases_supported", all(reason in notify.ERROR_LABELS for reason in
                      ("challenge_invalid", "invalid_device_key", "device_key_mismatch", "device_proof_invalid", "nonce_mismatch", "unsupported_client")))
            finally:
                worker.shutdown(1)
                notify._dispatcher = None

            wrong_calls = []

            def wrong_bot(method, payload, token, timeout):
                wrong_calls.append(method)
                return {"ok": True, "result": {"is_bot": True, "username": "DIFFERENT_BOT"}}

            worker = notify._Dispatcher(TEST_TOKEN, transport=wrong_bot)
            worker.enqueue("fixture")
            check("wrong_bot_blocks_delivery", worker.flush(1) and wrong_calls == ["getMe"] and worker.disabled)
            worker.shutdown(1)

            recovered = []

            def retry_transport(method, payload, token, timeout):
                if method == "getMe":
                    return {"ok": True, "result": {"is_bot": True, "username": "VCAM_V5_ADMIN_BOT"}}
                recovered.append(method)
                if len(recovered) == 1:
                    return {"ok": False, "error_code": 429, "parameters": {"retry_after": 0}}
                return {"ok": True}

            worker = notify._Dispatcher(TEST_TOKEN, transport=retry_transport)
            worker.enqueue("fixture")
            check("rate_limit_failure_retries_and_recovers", worker.flush(1) and len(recovered) == 2)
            worker.shutdown(1)

            transient = []

            def fail_transport(method, payload, token, timeout):
                transient.append(method)
                raise TimeoutError(TEST_TOKEN)

            worker = notify._Dispatcher(TEST_TOKEN, transport=fail_transport)
            worker.enqueue("fixture")
            check("bounded_retry_after_transport_failure", worker.flush(2) and len(transient) == notify.MAX_ATTEMPTS)
            worker.shutdown(1)
            check("sanitized_delivery_logs", TEST_TOKEN not in log_stream.getvalue())

            started, release = threading.Event(), threading.Event()

            def stalled(method, payload, token, timeout):
                if method == "getMe":
                    return {"ok": True, "result": {"is_bot": True, "username": "VCAM_V5_ADMIN_BOT"}}
                started.set()
                release.wait(2)
                return {"ok": True}

            worker = notify._Dispatcher(TEST_TOKEN, transport=stalled, capacity=1)
            worker.enqueue("first")
            assert started.wait(1)
            notify._dispatcher = worker
            began = time.perf_counter()
            accepted = notify.notify_login_success("fixtureuser", "id", "127.0.0.1")
            rejected = notify.notify_login_fail("fixtureuser", "id", "127.0.0.1", "wrong_password")
            duration = time.perf_counter() - began
            check("bounded_queue_nonblocking_under_stall", accepted and not rejected and duration < .2)
            check("flush_timeout_bounded", not worker.flush(.01))
            check("shutdown_timeout_bounded", not worker.shutdown(.01))
            release.set()
            check("shutdown_recovers_after_inflight_transport", worker.shutdown(1))
            check("post_shutdown_rejected", worker.enqueue("late") is False)
            notify._dispatcher = None

            check("users_live_counts_include_disabled", "máy bật 1/3, tắt 1, tổng 2" in bot.format_users(1))
            device_output = bot.format_devices("fixtureuser")
            check("devices_show_disabled_rows_and_escape", "Bật: 1/3 | Tắt: 1 | Tổng: 2" in device_output
                  and "🔴 TẮT" in device_output and "Phone &amp;two" in device_output)
            store.user_enabled = 0
            check("users_refresh_disabled_status", "🔴 TẮT" in bot.format_users(1))
            store.user_enabled = 1
            cleared = bot.execute_confirmation(f"telegram:{OWNER}:owner", "owner", "fixture-code")
            check("clear_reads_post_commit_counts_preserves_expiry", "Hiện tại: 0/3 máy bật; tổng 0" in cleared
                  and bot.format_epoch(200000) in cleared and "chưa ghi nhận" in bot.format_devices("fixtureuser"))
            check("users_reflect_clear_on_next_request", "máy bật 0/3, tắt 0, tổng 0" in bot.format_users(1))

            actor = f"telegram:{OWNER}:owner"
            bot.set_wizard(actor, "password", "password_manual", {"username": "fixtureuser"})
            try:
                bot.handle_wizard("fixture-password", actor, "viewer")
                denied = False
            except PermissionError:
                denied = True
            check("persisted_wizard_rechecks_role_before_mutation", denied and bot.get_wizard(actor) is None)

            sent, handled = [], []
            with mock.patch.object(bot, "send_message", side_effect=lambda *a, **kw: sent.append((a, kw))), \
                    mock.patch.object(bot, "answer_callback", side_effect=lambda *a, **kw: sent.append((a, kw))), \
                    mock.patch.object(bot, "handle_command", side_effect=lambda *a, **kw: handled.append(a) or "ok"):
                fixtures = [(OWNER, OWNER, "group"), (123, OWNER, "private"), (OWNER, 123, "private")]
                for uid, cid, kind in fixtures:
                    bot.process_message({"text": "/users", "from": {"id": uid}, "chat": {"id": cid, "type": kind}})
                    bot.process_callback({"id": "fixture", "from": {"id": uid}, "data": "confirm:fixture",
                                          "message": {"chat": {"id": cid, "type": kind}}})
                check("nonowner_group_and_mismatched_chat_rejected_audited", len(store.audits) == 6 and not handled and not sent)
                bot.process_message({"text": "/users", "from": {"id": OWNER}, "chat": {"id": OWNER, "type": "private"}})
                check("owner_private_commands_preserved", len(handled) == 1 and len(sent) == 1)

            actual_keyboard = [button["text"] for row in bot.MAIN_KEYBOARD["keyboard"] for button in row]
            check("persistent_keyboard_preserved", actual_keyboard == ["👥 Tài khoản", "📱 Thiết bị", "➕ Tạo tài khoản", "🔎 Tìm tài khoản",
                  "⏳ Gia hạn", "🔑 Đổi mật khẩu", "🧹 Đổi máy", "🗑 Xóa tài khoản", "⌛ Đã hết hạn", "📊 Hệ thống", "💾 Sao lưu", "❓ Trợ giúp"])
            upload_paths = []

            def upload(cid, path, caption=""):
                assert cid == OWNER and Path(path).read_bytes().startswith(b"synthetic-snapshot")
                upload_paths.append(Path(path))

            with mock.patch.object(bot, "send_document", side_effect=upload):
                bot.handle_command("/backup", actor, "owner", chat_id=OWNER)
            check("backup_uses_snapshot_and_removes_temporary_file", len(upload_paths) == 1 and not upload_paths[0].exists())

            with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(bot, "BOT_TOKEN", ""):
                check("bot_missing_token_fails_startup", bot.main() == 2)
            with mock.patch.object(bot, "acquire_lock"), mock.patch.object(bot.signal, "signal"), \
                    mock.patch.object(bot, "request_json", return_value={"result": {"is_bot": True, "username": "OTHER_BOT"}}), \
                    mock.patch.object(bot, "configure_commands") as configure, contextlib.redirect_stderr(io.StringIO()):
                check("bot_wrong_identity_fails_before_commands", bot.main() == 2 and not configure.called)
        finally:
            notify.shutdown(1)
            notify.LOG.removeHandler(handler)
    check("zero_live_network_calls", RESULTS["network_calls"] == 0)
    RESULTS["source_sha256"] = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sources.items()}
    RESULTS["passed"] = len(RESULTS["tests"])
    destination = ROOT / "docs" / "evidence" / "telegram_audit" / "login_alert_tests.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": RESULTS["passed"], "network_calls": RESULTS["network_calls"],
                      "evidence": str(destination)}, ensure_ascii=True))


if __name__ == "__main__":
    run()
