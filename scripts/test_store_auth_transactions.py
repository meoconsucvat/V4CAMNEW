"""Exercise the current store source against disposable databases, never production."""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import types
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "server/store.py"
OUT = ROOT / "docs/evidence/auth_refactor/store_transactions.json"


@contextmanager
def isolated(source: bytes):
    with tempfile.TemporaryDirectory(prefix="vcnext-store-test-") as folder:
        copied = Path(folder) / "store.py"
        copied.write_bytes(source)
        module = types.ModuleType("isolated_store")
        module.__file__ = str(copied)
        exec(compile(source, str(copied), "exec"), module.__dict__)
        clock = int(time.time())
        module.now = lambda: clock
        yield module, Path(folder)


def user(store, name="customer", slots=1):
    return store.create_user(name, "synthetic-secret", duration_seconds=86400, max_devices=slots)


def challenge(store, name="customer", device="fixture-device-1", key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    raw = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    payload = {"version": 2, "purpose": "auth.challenge", "issuer": "vcnext-main", "audience": "vcnext-ios",
               "challenge_id": "fixture-" + __import__("secrets").token_hex(12), "device_id": device,
               "username": name, "nonce": __import__("secrets").token_hex(32), "build": "37",
               "device_key_thumbprint": hashlib.sha256(raw).hexdigest(), "issued_at": store.now(),
               "expires_at": store.now() + 90}
    public_key = base64.b64encode(raw).decode("ascii")
    stored = store.save_auth_challenge(payload, public_key)
    assert stored == payload
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode("ascii")

    def verifier(actual_payload, actual_key, actual_signature):
        assert actual_payload == payload and actual_key == public_key
        decoded = base64.b64decode(actual_key, validate=True)
        parsed = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), decoded)
        parsed.verify(base64.b64decode(actual_signature, validate=True), data, ec.ECDSA(hashes.SHA256()))
        return True

    return payload, signature, verifier, key


def login(store, item, password="synthetic-secret", verifier=None, requested=None):
    payload, signature, default_verifier, _ = item
    return store.complete_login(payload["challenge_id"], payload["device_id"], password, payload["nonce"],
                                verifier or default_verifier, "Synthetic Device", "37", device_signature=signature,
                                requested_username=requested or payload["username"])


def rejected(store, action, code):
    try:
        action()
    except store.AuthError as error:
        assert error.code == code, (error.code, code)
        return
    raise AssertionError("Expected rejection: " + code)


def counts(store, table, name="customer"):
    with store.connect() as connection:
        return connection.execute(f"SELECT COUNT(*) FROM {table} WHERE username = ?", (name,)).fetchone()[0]


def main():
    source = SOURCE.read_bytes()
    results = {"source_sha256": hashlib.sha256(source).hexdigest(), "scope": "isolated copies and synthetic fixtures only", "tests": []}

    def run(name, test):
        try:
            with isolated(source) as (store, folder):
                details = test(store, folder) or {}
            results["tests"].append({"name": name, "passed": True, **details})
        except Exception as error:
            results["tests"].append({"name": name, "passed": False, "error": type(error).__name__ + ": " + str(error)})

    def schema(store, _):
        with store.connect() as connection:
            assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
            for table, needed in {"sessions": {"session_id", "session_version", "auth_epoch"},
                                  "challenges": {"payload_json", "device_public_key", "auth_epoch"},
                                  "auth_responses": {"session_id", "request_id", "request_hash", "response_json", "expires_at"}}.items():
                assert needed <= {row["name"] for row in connection.execute("PRAGMA table_info(" + table + ")")}
            assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        return {"journal_mode": "wal", "busy_timeout_ms": 5000}
    run("schema_and_wal", schema)

    def passwords(store, _):
        created = user(store)
        assert len(bytes.fromhex(created["password_salt"])) == 16
        assert store.PBKDF2_ROUNDS == 200000
        assert store.validate_credentials("customer", "synthetic-secret")[0]
        assert not store.validate_credentials("customer", "incorrect")[0]
        assert not store.validate_credentials("admin", "")[0]
        assert not store.validate_credentials("admin", "incorrect")[0]
        store.set_user_password("admin", "fixture-admin-password")
        assert store.validate_credentials("admin", "fixture-admin-password")[0]
    run("password_kdf_and_admin_no_bypass", passwords)

    def success(store, _):
        user(store)
        item = challenge(store)
        response = login(store, item)
        assert response["user"]["active_devices"] == response["user"]["total_devices"] == 1
        assert response["session"]["auth_epoch"] == response["user"]["auth_epoch"]
        assert len(response["session"]["session_id"]) == 48
        assert counts(store, "challenges") == 0
        snap = store.get_session_snapshot(item[0]["device_id"])
        assert snap["device"]["username"] == "customer" and snap["session"] == response["session"]
    run("real_p256_login_and_snapshot", success)

    def invalid_inputs(store, _):
        user(store)
        item = challenge(store)
        rejected(store, lambda: login(store, item, password="incorrect"), "wrong_password")
        rejected(store, lambda: login(store, item, requested="someone-else"), "challenge_invalid")
        rejected(store, lambda: store.complete_login(item[0]["challenge_id"], item[0]["device_id"], "synthetic-secret", "bad", item[2], device_signature=item[1]), "nonce_mismatch")
        rejected(store, lambda: store.complete_login(item[0]["challenge_id"], item[0]["device_id"], "synthetic-secret", "không hợp lệ", item[2], device_signature=item[1]), "nonce_mismatch")
        rejected(store, lambda: login(store, item, verifier=lambda *_: False), "device_proof_invalid")
        assert counts(store, "challenges") == 1 and counts(store, "devices") == 0
        login(store, item)
        rejected(store, lambda: login(store, item), "challenge_invalid")
    run("invalid_credentials_nonce_proof_and_replay", invalid_inputs)

    def ownership(store, _):
        user(store)
        user(store, "other-account", 3)
        item = challenge(store)
        login(store, item)
        rejected(store, lambda: challenge(store, "other-account", item[0]["device_id"]), "device_bound_to_other_user")
        ok, code = store.record_device_login("other-account", {"device_id": item[0]["device_id"]})
        assert not ok and code == "device_bound_to_other_user"
        assert store.list_devices("customer")[0]["username"] == "customer"
    run("global_device_owner_never_transfers", ownership)

    def disabled(store, _):
        user(store, slots=3)
        item = challenge(store)
        login(store, item)
        with store.connect() as connection:
            connection.execute("UPDATE devices SET enabled = 0 WHERE username = 'customer'")
        rejected(store, lambda: challenge(store, device=item[0]["device_id"], key=item[3]), "device_disabled")
        snapshot = store.get_user("customer")
        assert snapshot["active_devices"] == 0 and snapshot["total_devices"] == 1
    run("disabled_device_and_realtime_counts", disabled)

    def race_quota(store, _):
        user(store)
        first = challenge(store, device="quota-device-a")
        second = challenge(store, device="quota-device-b")
        barrier = threading.Barrier(2)
        def attempt(item):
            def verifier(*arguments):
                answer = item[2](*arguments)
                barrier.wait(10)
                return answer
            try:
                login(store, item, verifier=verifier)
                return "ok"
            except store.AuthError as error:
                return error.code
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            values = list(pool.map(attempt, (first, second)))
        assert sorted(values) == ["device_limit_reached", "ok"], values
        assert counts(store, "devices") == counts(store, "sessions") == 1
        return {"results": sorted(values), "enrolled_devices": 1}
    run("concurrent_first_activation_quota_atomic", race_quota)

    def race_challenge(store, _):
        user(store)
        item = challenge(store)
        barrier = threading.Barrier(2)
        def attempt(_):
            def verifier(*arguments):
                answer = item[2](*arguments)
                barrier.wait(10)
                return answer
            try:
                login(store, item, verifier=verifier)
                return "ok"
            except store.AuthError as error:
                return error.code
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            values = list(pool.map(attempt, range(2)))
        assert sorted(values) == ["challenge_invalid", "ok"], values
        assert counts(store, "sessions") == 1
        return {"results": sorted(values)}
    run("concurrent_challenge_consumption_atomic", race_challenge)

    def revoke_race(store, _, action):
        user(store, slots=2)
        original = login(store, challenge(store))
        pending = challenge(store, device="pending-revocation")
        old_user = store.get_user("customer")
        def verifier(*arguments):
            answer = pending[2](*arguments)
            action(store)
            return answer
        rejected(store, lambda: login(store, pending, verifier=verifier), "challenge_invalid")
        assert counts(store, "sessions") == counts(store, "challenges") == 0
        current = store.get_user("customer")
        assert current["expires_at"] == old_user["expires_at"]
        assert current["auth_epoch"] == old_user["auth_epoch"] + 1
        return old_user, current
    def clear_race(store, folder):
        old, new = revoke_race(store, folder, lambda actual: actual.reset_devices("customer"))
        assert (old["password_salt"], old["password_hash"]) == (new["password_salt"], new["password_hash"])
        assert new["active_devices"] == new["total_devices"] == 0
    run("clear_preserves_term_hash_revokes_inflight", clear_race)
    def password_race(store, folder):
        revoke_race(store, folder, lambda actual: actual.set_user_password("customer", "new-synthetic-password"))
        assert store.validate_credentials("customer", "new-synthetic-password")[0]
        assert not store.validate_credentials("customer", "synthetic-secret")[0]
    run("password_change_revokes_inflight", password_race)

    def epoch_before_proof(store, _):
        user(store)
        pending = challenge(store)
        store.reset_devices("customer")
        rejected(store, lambda: login(store, pending), "challenge_invalid")
        assert counts(store, "devices") == 0
    run("old_challenge_rejected_after_clear", epoch_before_proof)

    def session_cache(store, _):
        user(store)
        first = challenge(store)
        response = login(store, first)
        session_id = response["session"]["session_id"]
        with store.connect() as connection:
            connection.execute("INSERT INTO auth_responses VALUES (?, 'request-1', 'hash', '{}', ?)", (session_id, store.now() + 90))
        again = login(store, challenge(store, key=first[3]))
        assert again["session"]["session_id"] != session_id
        with store.connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM auth_responses").fetchone()[0] == 0
            assert not connection.execute("PRAGMA foreign_key_check").fetchall()
    run("new_session_aba_id_and_fk_cache_cascade", session_cache)

    def admin(store, _):
        store.set_user_password("admin", "fixture-admin-password")
        before = store.get_user("admin")
        assert before["max_devices"] == 5 and before["active_devices"] == 1
        assert 315359995 <= before["expires_at"] - store.now() <= 315360000
        for number in range(4):
            login(store, challenge(store, "admin", "synthetic-admin-" + str(number)), password="fixture-admin-password")
        rejected(store, lambda: challenge(store, "admin", "synthetic-admin-overflow"), "device_limit_reached")
        store.init_db()
        after = store.get_user("admin")
        assert after["expires_at"] == before["expires_at"] and after["total_devices"] == 5
        assert after["password_hash"] == before["password_hash"]
    run("admin_five_slots_ten_year_seed_preserved", admin)

    def remove(store, _):
        user(store)
        item = challenge(store)
        login(store, item)
        started = time.monotonic()
        assert store.remove_device("customer", item[0]["device_id"])
        assert time.monotonic() - started < 2
        assert counts(store, "devices") == counts(store, "sessions") == 0
        assert not store.remove_device("unrelated", item[0]["device_id"])
    run("remove_device_no_nested_writer_lock", remove)

    def concurrent_extensions(store, _):
        original = user(store)
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            list(pool.map(lambda _: store.extend_user_seconds("customer", 60), range(8)))
        assert store.get_user("customer")["expires_at"] == original["expires_at"] + 480
    run("concurrent_extensions_no_lost_updates", concurrent_extensions)

    def wal_busy(store, folder):
        user(store)
        blocker = sqlite3.connect(store.DB_PATH)
        blocker.execute("BEGIN IMMEDIATE")
        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            waiting = pool.submit(store.set_bot_state, "synthetic-key", "value")
            time.sleep(0.15)
            # Readers remain usable while a different writer is pending.
            assert store.get_user("customer")["username"] == "customer"
            blocker.rollback()
            blocker.close()
            waiting.result(timeout=3)
        elapsed = time.monotonic() - start
        assert elapsed >= .15 and elapsed < 3
        destination = folder / "online-snapshot.db"
        store.backup_database(str(destination))
        copy = sqlite3.connect(destination)
        try:
            assert copy.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert copy.execute("SELECT value FROM bot_state WHERE key='synthetic-key'").fetchone()[0] == "value"
        finally:
            copy.close()
        return {"bounded_writer_wait_observed": True, "backup_integrity": "ok"}
    run("wal_readers_bounded_writer_wait_online_backup", wal_busy)

    def confirmations(store, _):
        code = store.create_confirmation("owner", "delete", {"username": "synthetic"})
        try:
            store.consume_confirmation("stranger", code)
        except ValueError:
            pass
        else:
            raise AssertionError("Foreign actor consumed confirmation")
        assert store.consume_confirmation("owner", code) == ("delete", {"username": "synthetic"})
        try:
            store.consume_confirmation("owner", code)
        except ValueError:
            pass
        else:
            raise AssertionError("Confirmation replay accepted")
    run("confirmation_actor_and_one_time_consumption", confirmations)

    def malformed_key(store, _):
        user(store)
        rejected(store, lambda: store.save_auth_challenge({"challenge_id": "x", "username": "customer", "device_id": "x", "nonce": "x" * 64, "build": "37"}, "invalid-key"), "invalid_device_key")
    run("invalid_public_key_rejected", malformed_key)

    def migration(store, folder):
        legacy = folder / "legacy.db"
        connection = sqlite3.connect(legacy)
        salt, digest = store.password_hash("legacy-synthetic")
        expires = store.now() + 12345
        connection.executescript("""
            CREATE TABLE users(username TEXT PRIMARY KEY,password_salt TEXT NOT NULL,password_hash TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,expires_at INTEGER NOT NULL,max_devices INTEGER NOT NULL DEFAULT 1,note TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
            CREATE TABLE sessions(device_id TEXT PRIMARY KEY,username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,thumbprint TEXT NOT NULL,access_token TEXT NOT NULL UNIQUE,renewal_token TEXT NOT NULL,current_nonce TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
            CREATE TABLE challenges(challenge_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,username TEXT NOT NULL,thumbprint TEXT NOT NULL,nonce TEXT NOT NULL,expires_at INTEGER NOT NULL);
        """)
        connection.execute("INSERT INTO users VALUES ('legacy',?,?,1,?,1,'',?,?)", (salt, digest, expires, store.now(), store.now()))
        connection.execute("INSERT INTO sessions VALUES ('legacy-device','legacy','thumb','legacy-token','legacy-renewal','nonce',?,?)", (expires, store.now()))
        connection.execute("INSERT INTO challenges VALUES ('legacy-challenge','legacy-device','legacy','thumb','nonce',?)", (store.now() + 90,))
        connection.commit()
        connection.close()
        store.DB_PATH = str(legacy)
        store.init_db()
        migrated = store.get_user("legacy")
        assert migrated["expires_at"] == expires and migrated["password_hash"] == digest
        assert migrated["auth_epoch"] == 1
        with store.connect() as connection:
            row = connection.execute("SELECT * FROM sessions WHERE device_id='legacy-device'").fetchone()
            assert len(row["session_id"]) == 48
            old_id = row["session_id"]
            assert not connection.execute("PRAGMA foreign_key_check").fetchall()
        store.init_db()
        with store.connect() as connection:
            assert connection.execute("SELECT session_id FROM sessions WHERE device_id='legacy-device'").fetchone()[0] == old_id
        rejected(store, lambda: store.complete_login("legacy-challenge", "legacy-device", "legacy-synthetic", "nonce", lambda *_: True, device_signature="synthetic"), "challenge_invalid")
    run("legacy_migration_preserves_term_hash_and_invalidates_unproven_challenges", migration)

    results["passed"] = all(result["passed"] for result in results["tests"])
    results["test_count"] = len(results["tests"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    raise SystemExit(0 if results["passed"] else 1)


if __name__ == "__main__":
    main()
