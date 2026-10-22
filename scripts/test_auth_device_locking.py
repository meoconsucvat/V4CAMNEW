"""Isolated integration regression tests for the VCNext username/device contract.

Only byte-identical copies of product modules are executed, in a temporary package
with a fresh database and generated RSA/P-256 keys. No deployment secrets are read.
HTTP is restricted to loopback and the Telegram HTTP transport is replaced locally.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import types
import urllib.parse
from http.server import ThreadingHTTPServer
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/auth_refactor"
NOW = 2_000_000_000
PASSWORD = "Synthetic-Device-Test-Only-Password!"
APP_DIGEST = "4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2"


def canonical(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


class FakeTelegramResponse:
    def __init__(self, method):
        self.method = method

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, *args):
        if self.method == "getMe":
            return b'{"ok":true,"result":{"is_bot":true,"username":"VCAM_V5_ADMIN_BOT"}}'
        return b'{"ok":true,"result":{"message_id":1}}'


class Fixture:
    """Execute copied modules without allowing production paths or egress."""

    def __init__(self, directory, sources):
        self.path = Path(directory)
        self.sources = sources
        for name, source in sources.items():
            (self.path / name).write_bytes(source)
            assert (self.path / name).read_bytes() == source
        (self.path / "__init__.py").write_text("", encoding="utf-8")
        self.authority = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        (self.path / "server_private_key.pem").write_bytes(self.authority.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.package_name = "_vcnext_auth_fixture"
        self.saved_modules = {name: value for name, value in sys.modules.items()
                              if name == self.package_name or name.startswith(self.package_name + ".")}
        self.patchers = []
        self.events = []
        self.httpd = None
        self.thread = None
        self.keys = {}
        self.alerts = []
        self.request_outcomes = []
        self.telegram_requests = []
        self.errors = []
        self.network_attempts = []
        self.secret_values = [PASSWORD]
        # No inherited token, proxy, .env, DB path or authority path is available.
        self._patch(mock.patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "synthetic-token-not-valid-for-telegram",
            "TELEGRAM_OWNER_ID": "123456789",
            "VCNEXT_DB_PATH": str(self.path / "licenses.db"),
        }, clear=True))
        self._patch(mock.patch("time.time", return_value=NOW))
        self._patch(mock.patch("urllib.request.urlopen", side_effect=self.fake_telegram))
        original_connect = socket.socket.connect

        def loopback_connect(sock, address):
            if isinstance(address, tuple) and address[0] not in ("127.0.0.1", "::1", "localhost"):
                self.network_attempts.append("blocked_non_loopback")
                raise RuntimeError("fixture forbids external network")
            return original_connect(sock, address)

        self._patch(mock.patch.object(socket.socket, "connect", loopback_connect))
        package = types.ModuleType(self.package_name)
        package.__path__ = [str(self.path)]
        package.__file__ = str(self.path / "__init__.py")
        sys.modules[self.package_name] = package
        self.store = self.load("store")
        assert Path(self.store.DB_PATH).resolve() == (self.path / "licenses.db").resolve()
        self.notify = self.load("notify")
        self.server = self.load("server")
        assert self.server.store is self.store
        assert Path(self.server.KEY_PATH).resolve() == (self.path / "server_private_key.pem").resolve()
        assert Path(self.server.DB_PATH).resolve() == (self.path / "licenses.db").resolve()
        for method, outcome in (("notify_login_success", "accepted"), ("notify_login_fail", "rejected")):
            original = getattr(self.notify, method)

            def capture(*args, _outcome=outcome, _original=original, **kwargs):
                self.alerts.append({"outcome": _outcome, "args": args, "kwargs": kwargs})
                return _original(*args, **kwargs)

            setattr(self.notify, method, capture)
        handler = self.server.VCNextRequestHandler
        handler.log_message = lambda *args, **kwargs: None
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        self.httpd.handle_error = lambda *args: self.errors.append("unhandled_handler_exception")
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def _patch(self, patcher):
        value = patcher.start()
        self.patchers.append(patcher)
        return value

    def load(self, stem):
        name = self.package_name + "." + stem
        spec = importlib.util.spec_from_file_location(name, self.path / (stem + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def fake_telegram(self, request, *args, **kwargs):
        self.telegram_requests.append({"url": request.full_url,
                                       "body": (request.data or b"").decode("utf-8", "replace")})
        return FakeTelegramResponse(request.full_url.rsplit("/", 1)[-1])

    def close(self):
        for event in self.events:
            event.set()
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)
            assert not self.thread.is_alive()
        if hasattr(self, "notify"):
            assert self.notify.flush(timeout=5)
            assert self.notify.shutdown(timeout=2)
        for name in tuple(sys.modules):
            if name == self.package_name or name.startswith(self.package_name + "."):
                sys.modules.pop(name, None)
        sys.modules.update(self.saved_modules)
        for patcher in reversed(self.patchers):
            patcher.stop()

    def sql(self, query, args=()):
        with self.store.connect() as con:
            return [dict(row) for row in con.execute(query, args).fetchall()]

    def create(self, username, limit=1):
        return self.store.create_user(username, PASSWORD, days=30, max_devices=limit,
                                      actor="isolated-regression")

    def key(self, device):
        if device not in self.keys:
            self.keys[device] = ec.generate_private_key(ec.SECP256R1())
        return self.keys[device]

    def body(self, device, **extra):
        return {"device_id": device, "client_build": "37", "binary_digest": APP_DIGEST, **extra}

    def request(self, route, body, token=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=25)
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        try:
            connection.request("POST", "/api/v2/auth/" + route, canonical(body), headers)
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.request_outcomes.append({"route": route, "status": response.status})
            if response.status == 200 and "lease" in payload:
                self.summary((response.status, payload))
            elif response.status == 200 and route == "challenge":
                signature = base64.b64decode(payload["signature"], validate=True)
                assert len(signature) == 384
                self.authority.public_key().verify(signature, canonical(payload["challenge"]),
                                                   padding.PKCS1v15(), hashes.SHA256())
            return response.status, payload
        finally:
            connection.close()

    def challenge(self, username, device, **overrides):
        raw = self.key(device).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        body = self.body(device, protocol_version=2, request_id=os.urandom(16).hex().upper(),
                         username=username, device_public_key=base64.b64encode(raw).decode("ascii"))
        body.update(overrides)
        return self.request("challenge", body)

    def sign(self, device, payload):
        proof = base64.b64encode(self.key(device).sign(canonical(payload),
                        ec.ECDSA(hashes.SHA256()))).decode("ascii")
        self.secret_values.append(proof)
        return proof

    def login_body(self, username, device, challenge, **overrides):
        payload = challenge["challenge"]
        body = self.body(device, username=username, password=PASSWORD,
            device_name="Synthetic test phone", challenge_id=payload["challenge_id"],
            challenge_nonce=payload["nonce"], device_signature=self.sign(device, payload))
        body.update(overrides)
        return body

    def login(self, username, device, challenge, **overrides):
        return self.request("login", self.login_body(username, device, challenge, **overrides))

    def enroll(self, username, device):
        status, challenge = self.challenge(username, device)
        assert status == 200, (status, challenge.get("error"))
        response = self.login(username, device, challenge)
        assert response[0] == 200, (response[0], response[1].get("error"))
        self.summary(response)
        return response[1]

    def refresh_body(self, route, device, session, **overrides):
        token = session["renewal_token" if route == "renew" else "access_token"]
        wire = self.body(device, request_id=os.urandom(16).hex().upper(),
                         nonce=session["next_nonce"], issued_at=NOW)
        wire.update(overrides)
        proof_obj = {"version": 2, "purpose": "auth." + route,
                     "request_id": wire["request_id"], "nonce": wire["nonce"],
                     "device_id": wire["device_id"], "build": wire["client_build"],
                     "binary_digest": wire["binary_digest"],
                     "session_binding": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                     "issued_at": wire["issued_at"]}
        if "device_signature" not in wire:
            wire["device_signature"] = self.sign(device, proof_obj)
        return wire, token

    def refresh(self, route, device, session, **overrides):
        body, token = self.refresh_body(route, device, session, **overrides)
        return self.request(route, body, token)

    def summary(self, response):
        status, body = response
        if status != 200 or "lease" not in body:
            return {"status": status, "error": body.get("error")}
        signature = base64.b64decode(body["lease_signature"], validate=True)
        self.authority.public_key().verify(signature, canonical(body["lease"]),
                                           padding.PKCS1v15(), hashes.SHA256())
        assert len(signature) == 384
        for field, token in (("session_binding", "access_token"),
                              ("renewal_binding", "renewal_token"), ("next_nonce_hash", "next_nonce")):
            assert body["lease"][field] == hashlib.sha256(body[token].encode()).hexdigest()
        assert set(body["lease"]["capabilities"]) == set(self.server.REQUIRED_CAPABILITIES)
        assert isinstance(body["user"]["username"], str)
        assert type(body["user"]["active_devices"]) is int
        assert type(body["user"]["max_devices"]) is int
        assert 0 < body["lease"]["expires_at"] - body["lease"]["issued_at"] <= 90
        self.secret_values.extend(body.get(key, "") for key in ("access_token", "renewal_token", "next_nonce", "lease_signature"))
        return {"status": status, "rsa3072_signature_valid": True,
                "active_devices": body["user"]["active_devices"],
                "max_devices": body["user"]["max_devices"],
                "ttl": body["lease"]["expires_at"] - body["lease"]["issued_at"]}


def expect_rejected(response, errors=None):
    status, payload = response
    assert 400 <= status < 500, (status, payload.get("error"))
    if errors is not None:
        assert payload.get("error") in errors, (status, payload.get("error"))
    return {"status": status, "error": payload.get("error")}


def handler_io_checks(f):
    """Exercise actual HTTP handler methods with immediate synthetic I/O faults."""
    def handler():
        item = object.__new__(f.server.VCNextRequestHandler)
        item.path = "/api/v2/auth/login"
        item.headers = {"Content-Length": "1"}
        item.client_address = ("127.0.0.1", 12345)
        item.statuses = []
        item.send_response = lambda status: item.statuses.append(status)
        item.send_header = lambda *args: None
        item.end_headers = lambda: None
        return item

    disconnected = handler()
    disconnected.wfile = types.SimpleNamespace(write=mock.Mock(side_effect=BrokenPipeError()))

    def rejected_request():
        disconnected._request_body = {"username": "synthetic-disconnected", "device_id": "synthetic-disconnected"}
        raise f.store.AuthError(403, "invalid_credentials", "Synthetic rejected request")

    disconnected._handle_post = rejected_request
    before = len(f.alerts)
    disconnected.do_POST()
    assert disconnected.statuses == [403]
    assert disconnected.wfile.write.call_count == 1
    assert len(f.alerts) == before + 1 and f.alerts[-1]["outcome"] == "rejected"
    f.request_outcomes.append({"route": "login", "status": 403})

    timed_out = handler()
    timed_out.rfile = types.SimpleNamespace(read=mock.Mock(side_effect=TimeoutError()))
    timed_out.wfile = io.BytesIO()
    before = len(f.alerts)
    timed_out.do_POST()
    assert timed_out.statuses == [408]
    assert json.loads(timed_out.wfile.getvalue())["error"] == "request_timeout"
    assert timed_out.rfile.read.call_count == 1
    assert len(f.alerts) == before + 1 and f.alerts[-1]["outcome"] == "rejected"
    timed_out.wfile.close()
    f.request_outcomes.append({"route": "login", "status": 408})
    return {"disconnected_response": {"statuses": [403], "write_attempts": 1,
                "login_alerts": 1, "unhandled_exception": False},
            "body_read_timeout": {"statuses": [408], "read_attempts": 1,
                "login_alerts": 1, "unhandled_exception": False}}


def run_tests(f):
    tests = {}
    # Each test stores only outcomes, never tokens, credentials or private keys.
    admin = f.store.get_user("admin")
    assert admin["max_devices"] == 5 and admin["expires_at"] - admin["created_at"] == 315360000
    tests["administrator_seed"] = {"max_devices": 5, "grant_seconds": 315360000,
                                    "preseeded_device_count": len(f.store.list_devices("admin"))}

    f.create("owner-one")
    f.create("owner-two")
    first = f.enroll("owner-one", "synthetic-device-a")
    same_device = f.challenge("owner-two", "synthetic-device-a")
    tests["global_device_ownership"] = {"first": f.summary((200, first)),
        "other_user": expect_rejected(same_device, {"device_bound_to_other_user"})}
    quota = f.challenge("owner-one", "synthetic-device-b")
    tests["sequential_quota"] = expect_rejected(quota, {"device_limit_reached"})
    old_key = f.keys["synthetic-device-a"]
    f.keys["synthetic-device-a"] = ec.generate_private_key(ec.SECP256R1())
    try:
        replacement = f.challenge("owner-one", "synthetic-device-a")
    finally:
        f.keys["synthetic-device-a"] = old_key
    tests["enrolled_device_key_replacement_rejected"] = expect_rejected(replacement, {"device_key_mismatch"})
    before = f.store.get_user("owner-one")
    f.store.reset_devices("owner-one", actor="isolated-regression")
    after = f.store.get_user("owner-one")
    assert before["expires_at"] == after["expires_at"] and before["password_hash"] == after["password_hash"]
    second = f.enroll("owner-one", "synthetic-device-b")
    tests["clear_preserves_term_and_password"] = {"new_device": f.summary((200, second)),
        "term_preserved": True, "password_preserved": True}

    f.create("two-slot-user", limit=2)
    two_a = f.enroll("two-slot-user", "synthetic-two-a")
    two_b = f.enroll("two-slot-user", "synthetic-two-b")
    assert two_a["user"]["active_devices"] == 1 and two_b["user"]["active_devices"] == 2
    third = f.challenge("two-slot-user", "synthetic-two-c")
    tests["two_device_positive_contract"] = {"first": f.summary((200, two_a)),
        "second": f.summary((200, two_b)), "third": expect_rejected(third, {"device_limit_reached"})}
    f.create("case-alias-user")
    alias = f.enroll("CASE-ALIAS-USER", "synthetic-case-alias")
    assert alias["user"]["username"] == "case-alias-user"
    assert f.alerts[-1]["outcome"] == "accepted" and f.alerts[-1]["args"][0] == "case-alias-user"
    tests["accepted_alert_uses_canonical_username"] = True

    f.create("proof-test")
    status, challenge = f.challenge("proof-test", "synthetic-proof-device")
    assert status == 200
    attempts = []
    for kind in ("missing-proof", "bad-proof", "missing-nonce", "bad-nonce", "wrong-password"):
        body = f.login_body("proof-test", "synthetic-proof-device", challenge)
        if kind == "missing-proof":
            body.pop("device_signature")
        elif kind == "bad-proof":
            body["device_signature"] = base64.b64encode(b"not-a-DER-signature").decode()
        elif kind == "missing-nonce":
            body.pop("challenge_nonce")
        elif kind == "bad-nonce":
            body["challenge_nonce"] = "synthetic-wrong-nonce"
        else:
            body["password"] = "Synthetic-Wrong-Password!"
        attempts.append({"case": kind, **expect_rejected(f.request("login", body))})
        assert not f.sql("SELECT 1 FROM devices WHERE device_id=?", ("synthetic-proof-device",))
        assert not f.sql("SELECT 1 FROM sessions WHERE device_id=?", ("synthetic-proof-device",))
    valid = f.login("proof-test", "synthetic-proof-device", challenge)
    assert valid[0] == 200
    tests["login_proof_nonce_and_password_mandatory"] = {"rejections": attempts,
        "valid_retry_same_unconsumed_challenge": f.summary(valid)}
    replay = f.login("proof-test", "synthetic-proof-device", challenge)
    tests["consumed_login_challenge_replay"] = expect_rejected(replay)

    f.create("body-user-one")
    f.create("body-user-two")
    status, bound_challenge = f.challenge("body-user-one", "synthetic-body-user")
    assert status == 200
    mismatched = f.login("body-user-two", "synthetic-body-user", bound_challenge)
    tests["login_username_bound_to_challenge"] = expect_rejected(mismatched)
    assert not f.sql("SELECT 1 FROM devices WHERE device_id=?", ("synthetic-body-user",))

    session = valid[1]
    refresh_rejections = []
    for route in ("heartbeat", "renew"):
        for kind in ("missing-token", "bad-token", "missing-proof", "bad-proof", "bad-nonce", "stale-time", "future-time"):
            signed_overrides = {}
            if kind == "bad-nonce":
                signed_overrides["nonce"] = "synthetic-wrong-nonce"
            elif kind == "stale-time":
                signed_overrides["issued_at"] = NOW - 1000
            elif kind == "future-time":
                signed_overrides["issued_at"] = NOW + 1000
            body, token = f.refresh_body(route, "synthetic-proof-device", session, **signed_overrides)
            if kind == "missing-token":
                token = None
            elif kind == "bad-token":
                token = "synthetic-invalid-token"
            elif kind == "missing-proof":
                body.pop("device_signature")
            elif kind == "bad-proof":
                body["device_signature"] = "not-base64"
            refresh_rejections.append({"route": route, "case": kind,
                **expect_rejected(f.request(route, body, token))})
        positive = f.refresh(route, "synthetic-proof-device", session)
        assert positive[0] == 200
        f.summary(positive)
        session = positive[1]
    tests["native_p256_refresh_contract"] = {"rejections": refresh_rejections,
                                             "valid_heartbeat_and_renew": True}
    f.sql("UPDATE users SET expires_at=? WHERE username=?", (NOW + 7, "proof-test"))
    clipped = f.refresh("heartbeat", "synthetic-proof-device", session)
    assert clipped[0] == 200 and clipped[1]["lease"]["expires_at"] == NOW + 7
    tests["lease_clipped_to_account_term"] = f.summary(clipped)
    f.sql("UPDATE users SET expires_at=? WHERE username=?", (NOW, "proof-test"))
    tests["expired_account_refresh_rejected"] = expect_rejected(
        f.refresh("heartbeat", "synthetic-proof-device", clipped[1]))

    f.create("extension-user")
    f.sql("UPDATE users SET expires_at=? WHERE username=?", (NOW + 5, "extension-user"))
    extended_session = f.enroll("extension-user", "synthetic-extended-session")
    f.store.extend_user_seconds("extension-user", 300, actor="isolated-regression")
    with mock.patch.object(f.store, "now", return_value=NOW + 6):
        extended_reply = f.refresh("heartbeat", "synthetic-extended-session", extended_session, issued_at=NOW + 6)
    assert extended_reply[0] == 200
    tests["extension_keeps_existing_session_usable"] = f.summary(extended_reply)

    f.store.set_user_password("admin", "Synthetic-Replaced-Admin-Password!", actor="isolated-regression")
    for number, password in enumerate(("", "1")):
        device = "synthetic-admin-reject-" + str(number)
        status, challenge = f.challenge("admin", device)
        assert status == 200
        response = f.login("admin", device, challenge, password=password)
        expect_rejected(response)
    tests["admin_has_no_legacy_password_bypass"] = True

    f.create("quota-race")
    devices = ("synthetic-quota-a", "synthetic-quota-b")
    challenges = [f.challenge("quota-race", device)[1] for device in devices]
    barrier = threading.Barrier(2)
    verifier = f.server.verify_ecdsa_p256_sha256

    def synchronized_verifier(public_key, message, signature):
        payload = json.loads(message)
        if payload.get("purpose") == "auth.challenge" and payload.get("username") == "quota-race":
            barrier.wait(timeout=20)
        return verifier(public_key, message, signature)

    f.server.verify_ecdsa_p256_sha256 = synchronized_verifier
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(f.login, "quota-race", device, challenge)
                       for device, challenge in zip(devices, challenges)]
            replies = [future.result(timeout=30) for future in futures]
    finally:
        f.server.verify_ecdsa_p256_sha256 = verifier
    assert sorted(reply[0] for reply in replies) == [200, 403]
    assert len(f.store.list_devices("quota-race")) == 1
    tests["concurrent_first_device_quota"] = {"statuses": sorted(reply[0] for reply in replies),
        "persisted_devices": 1, "double_enrollment": False}

    f.create("replay-race", limit=2)
    status, same_challenge = f.challenge("replay-race", "synthetic-replay-race")
    assert status == 200
    barrier = threading.Barrier(2)

    def replay_verifier(public_key, message, signature):
        if json.loads(message).get("username") == "replay-race":
            barrier.wait(timeout=20)
        return verifier(public_key, message, signature)

    f.server.verify_ecdsa_p256_sha256 = replay_verifier
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(f.login, "replay-race", "synthetic-replay-race", same_challenge)
                       for _ in range(2)]
            replay_replies = [future.result(timeout=30) for future in futures]
    finally:
        f.server.verify_ecdsa_p256_sha256 = verifier
    assert sorted(reply[0] for reply in replay_replies) == [200, 403]
    tests["concurrent_same_challenge_consumption"] = {
        "statuses": [200, 403], "valid_leases": 1, "double_spend": False}

    race_users = ("owner-race-one", "owner-race-two")
    for username in race_users:
        f.create(username)
    device = "synthetic-ownership-race"
    ownership_challenges = [f.challenge(username, device)[1] for username in race_users]
    barrier = threading.Barrier(2)

    def ownership_verifier(public_key, message, signature):
        if json.loads(message).get("username") in race_users:
            barrier.wait(timeout=20)
        return verifier(public_key, message, signature)

    f.server.verify_ecdsa_p256_sha256 = ownership_verifier
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(f.login, username, device, challenge)
                       for username, challenge in zip(race_users, ownership_challenges)]
            ownership_replies = [future.result(timeout=30) for future in futures]
    finally:
        f.server.verify_ecdsa_p256_sha256 = verifier
    assert sorted(reply[0] for reply in ownership_replies) == [200, 403]
    loser = next(reply for reply in ownership_replies if reply[0] != 200)
    expect_rejected(loser, {"device_bound_to_other_user"})
    assert len(f.sql("SELECT 1 FROM devices WHERE device_id=?", (device,))) == 1
    tests["concurrent_global_device_ownership"] = {"statuses": [200, 403],
        "rejection": "device_bound_to_other_user", "persisted_owners": 1}

    # Verification finishes after an administrator changes the account epoch.
    # No writer is held while the deterministic pause allows the admin mutation.
    revocation = []
    for mutation in ("clear", "password"):
        username = "inflight-" + mutation
        device = "synthetic-inflight-" + mutation
        f.create(username)
        status, challenge = f.challenge(username, device)
        assert status == 200
        paused = threading.Event()
        release = threading.Event()
        f.events.append(release)

        def paused_verifier(public_key, message, signature):
            payload = json.loads(message)
            if payload.get("purpose") == "auth.challenge" and payload.get("username") == username:
                paused.set()
                assert release.wait(timeout=20)
            return verifier(public_key, message, signature)

        f.server.verify_ecdsa_p256_sha256 = paused_verifier
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(f.login, username, device, challenge)
                assert paused.wait(timeout=15)
                if mutation == "clear":
                    f.store.reset_devices(username, actor="isolated-regression")
                else:
                    f.store.set_user_password(username, "Synthetic-New-Password!", actor="isolated-regression")
                release.set()
                response = future.result(timeout=25)
        finally:
            release.set()
            f.server.verify_ecdsa_p256_sha256 = verifier
        expect_rejected(response)
        assert not f.sql("SELECT 1 FROM sessions WHERE device_id=?", (device,))
        assert not f.sql("SELECT 1 FROM devices WHERE device_id=?", (device,))
        revocation.append({"mutation": mutation, "response": expect_rejected(response),
                           "orphaned_sessions": 0, "recreated_devices": 0})
    tests["inflight_login_revocation"] = revocation

    # Deliberately fail inside the real login transaction after consumption and
    # enrollment, proving the transaction rolls back as one unit.
    f.create("rollback-test")
    device = "synthetic-rollback"
    status, challenge = f.challenge("rollback-test", device)
    assert status == 200
    audit = f.store._audit_in_tx

    def fail_transaction(con, action, target, detail=None, actor="local"):
        if action == "login" and target == "rollback-test":
            raise RuntimeError("synthetic transaction fault")
        return audit(con, action, target, detail, actor)

    f.store._audit_in_tx = fail_transaction
    try:
        failed = f.login("rollback-test", device, challenge)
    finally:
        f.store._audit_in_tx = audit
    assert failed[0] == 500
    assert not f.sql("SELECT 1 FROM devices WHERE device_id=?", (device,))
    assert not f.sql("SELECT 1 FROM sessions WHERE device_id=?", (device,))
    retry = f.login("rollback-test", device, challenge)
    assert retry[0] == 200
    tests["atomic_login_failure_rollback"] = {"injected_failure_status": 500,
        "no_partial_device_or_session": True, "valid_retry": f.summary(retry)}

    # Parallel app/daemon requests keep shared nonce and Bearer tokens stable.
    # Signed request IDs, timestamps and cached responses supply replay controls.
    f.create("refresh-race")
    device = "synthetic-refresh-race"
    active = f.enroll("refresh-race", device)
    snapshot = f.store.get_session_snapshot
    joined = f.server._joined_session
    barrier = threading.Barrier(2)
    seen_threads = set()
    seen_lock = threading.Lock()

    def synchronized_snapshot(con, device_id):
        value = joined(con, device_id)
        identity = threading.get_ident()
        with seen_lock:
            first = identity not in seen_threads
            seen_threads.add(identity)
        if device_id == device and first:
            barrier.wait(timeout=20)
        return value

    f.server._joined_session = synchronized_snapshot
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(f.refresh, "heartbeat", device, active) for _ in range(2)]
            replies = [future.result(timeout=30) for future in futures]
    finally:
        f.server._joined_session = joined
    assert all(reply[0] == 200 for reply in replies)
    assert all(reply[1]["access_token"] == active["access_token"] for reply in replies)
    assert all(reply[1]["renewal_token"] == active["renewal_token"] for reply in replies)
    assert all(reply[1]["next_nonce"] == active["next_nonce"] for reply in replies)
    tests["concurrent_app_daemon_stable_session"] = {"statuses": sorted(reply[0] for reply in replies),
        "accepted_refreshes": 2, "bearer_tokens_and_nonce_stable": True}
    current = replies[-1][1]
    exact_body, token = f.refresh_body("heartbeat", device, current)
    first_reply = f.request("heartbeat", exact_body, token)
    retry_reply = f.request("heartbeat", exact_body, token)
    assert first_reply[0] == retry_reply[0] == 200 and first_reply[1] == retry_reply[1]
    changed = dict(exact_body)
    changed["nonce"] = "synthetic-conflicting-nonce"
    proof_obj = {"version": 2, "purpose": "auth.heartbeat", "request_id": changed["request_id"],
        "nonce": changed["nonce"], "device_id": device, "build": "37", "binary_digest": APP_DIGEST,
        "session_binding": hashlib.sha256(token.encode()).hexdigest(), "issued_at": NOW}
    changed["device_signature"] = f.sign(device, proof_obj)
    conflict = f.request("heartbeat", changed, token)
    tests["signed_request_retry_idempotence"] = {"exact_retry_byte_equivalent_json": True,
        "different_payload_same_request_id": expect_rejected(conflict, {"request_replayed"})}
    with mock.patch.object(f.store, "now", return_value=NOW + 181):
        resumed = f.refresh("heartbeat", device, active, issued_at=NOW + 181)
        assert resumed[0] == 200 and resumed[1]["next_nonce"] == active["next_nonce"]
        old_exact = f.request("heartbeat", exact_body, token)
        unknown = f.refresh("heartbeat", device, active, issued_at=NOW + 181,
                            nonce="synthetic-never-issued-nonce")
        replacement = f.enroll("refresh-race", device)
        assert replacement["access_token"] != active["access_token"]
        assert replacement["renewal_token"] != active["renewal_token"]
        assert replacement["next_nonce"] != active["next_nonce"]
        stale_session = f.refresh("heartbeat", device, active, issued_at=NOW + 181)
    tests["resumed_client_stable_nonce_policy"] = {"accepted_after_seconds": 181,
        "fresh_signed_proof_required": True,
        "old_exact_request": expect_rejected(old_exact, {"request_expired"}),
        "unknown_signed_nonce": expect_rejected(unknown, {"nonce_mismatch"})}
    tests["new_login_rotates_all_session_material"] = {
        "access_renewal_nonce_changed": True,
        "old_token_and_fresh_proof": expect_rejected(stale_session, {"invalid_token"})}
    assert len(f.sql("SELECT 1 FROM auth_responses WHERE session_id=?",
                     (snapshot(device)["session"]["session_id"],))) == 0

    f.create("future-proof-user")
    device = "synthetic-future-proof"
    future_session = f.enroll("future-proof-user", device)
    future_body, future_token = f.refresh_body("heartbeat", device, future_session, issued_at=NOW + 120)
    future_first = f.request("heartbeat", future_body, future_token)
    assert future_first[0] == 200
    with mock.patch.object(f.store, "now", return_value=NOW + 240):
        last_valid = f.request("heartbeat", future_body, future_token)
    assert last_valid == future_first
    assert last_valid[1]["lease"]["issued_at"] == NOW
    with mock.patch.object(f.store, "now", return_value=NOW + 241):
        too_old = f.request("heartbeat", future_body, future_token)
    tests["future_dated_proof_cache_boundary"] = {"first_acceptance_offset": 0,
        "last_valid_cached_offset": 240, "original_lease_not_extended": True,
        "expired_request_offset": 241, "expired_request": expect_rejected(too_old, {"request_expired"})}

    f.create("writer-freshness-user")
    device = "synthetic-writer-freshness"
    fresh_session = f.enroll("writer-freshness-user", device)
    clock = [NOW]
    original_proof = f.server.verify_challenge_proof

    def advance_after_proof(payload, public_key, signature):
        valid = original_proof(payload, public_key, signature)
        if payload.get("purpose") == "auth.heartbeat" and payload.get("device_id") == device:
            clock[0] = NOW + f.server.PROOF_CLOCK_SKEW + 1
        return valid

    f.server.verify_challenge_proof = advance_after_proof
    try:
        with mock.patch.object(f.store, "now", side_effect=lambda: clock[0]):
            delayed = f.refresh("heartbeat", device, fresh_session)
    finally:
        f.server.verify_challenge_proof = original_proof
    tests["writer_acquisition_rechecks_request_time"] = expect_rejected(delayed, {"request_expired"})

    f.create("aba-old-user")
    f.create("aba-new-user")
    device = "synthetic-aba-device"
    active = f.enroll("aba-old-user", device)
    old_session_id = snapshot(device)["session"]["session_id"]
    paused = threading.Event()
    release = threading.Event()
    f.events.append(release)

    has_paused = False

    def paused_snapshot(con, device_id):
        nonlocal has_paused
        value = joined(con, device_id)
        if device_id == device and not has_paused:
            has_paused = True
            paused.set()
            assert release.wait(timeout=20)
        return value

    f.server._joined_session = paused_snapshot
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(f.refresh, "heartbeat", device, active)
            assert paused.wait(timeout=15)
            f.store.reset_devices("aba-old-user", actor="isolated-regression")
            new_active = f.enroll("aba-new-user", device)
            new_session = snapshot(device)["session"]
            assert old_session_id != new_session["session_id"]
            release.set()
            stale_reply = future.result(timeout=25)
    finally:
        release.set()
        f.server._joined_session = joined
    expect_rejected(stale_reply)
    final_session = snapshot(device)["session"]
    assert final_session["username"] == "aba-new-user"
    assert final_session["session_id"] == new_session["session_id"]
    assert final_session["access_token"] == new_active["access_token"]
    tests["revoked_session_aba_race"] = {"stale_response": expect_rejected(stale_reply),
        "unique_session_generation": True, "replacement_session_unchanged": True}
    tests["logout_missing_token_rejected"] = expect_rejected(f.request("logout", f.body(device)), {"invalid_token"})
    logged_out = f.request("logout", f.body(device), new_active["access_token"])
    assert logged_out[0] == 200 and not f.sql("SELECT 1 FROM sessions WHERE device_id=?", (device,))
    tests["authenticated_logout_revokes_session"] = True
    tests["synthetic_handler_io_faults"] = handler_io_checks(f)
    return tests


def main():
    names = ("server.py", "store.py", "notify.py")
    sources = {name: (ROOT / "server" / name).read_bytes() for name in names}
    hashes_before = {name: hashlib.sha256(source).hexdigest() for name, source in sources.items()}
    record = {"source_sha256": hashes_before, "isolation": {
        "byte_identical_product_copies": True, "generated_rsa_bits": 3072,
        "generated_device_keys": "P256 X963 raw65; DER ECDSA SHA256 proof",
        "inherited_environment_cleared": True, "production_database_or_keys_read": False,
        "telegram_transport": "fake urllib transport", "network": "loopback only",
        "foundation_or_ios_runtime_executed": False}, "tests": {}}
    passed = False
    with tempfile.TemporaryDirectory(prefix="vcnext-auth-locking-") as directory:
        fixture = None
        try:
            fixture = Fixture.__new__(Fixture)
            Fixture.__init__(fixture, directory, sources)
            record["tests"] = run_tests(fixture)
            assert not fixture.errors and not fixture.network_attempts
            record["unhandled_handler_exceptions"] = len(fixture.errors)
            record["blocked_external_network_attempts"] = len(fixture.network_attempts)
            record["notification_calls"] = {
                outcome: sum(alert["outcome"] == outcome for alert in fixture.alerts)
                for outcome in ("accepted", "rejected")}
            assert fixture.notify.flush(timeout=5)
            expected_alerts = {
                "accepted": sum(item["route"] == "login" and item["status"] == 200
                                for item in fixture.request_outcomes),
                "rejected": sum((item["route"] == "login" and item["status"] >= 400)
                                 or (item["route"] == "challenge" and item["status"] >= 400)
                                 for item in fixture.request_outcomes)}
            assert expected_alerts == record["notification_calls"], (expected_alerts, record["notification_calls"])
            sent = [item for item in fixture.telegram_requests if item["url"].endswith("/sendMessage")]
            assert len(sent) == sum(expected_alerts.values())
            record["notification_expected_calls"] = expected_alerts
            record["notification_transport_deliveries"] = len(sent)
            # Verify actual rendered Telegram requests omit all fixture secrets.
            alert_text = "\n".join(urllib.parse.parse_qs(item["body"]).get("text", [""])[0]
                                   for item in sent)
            assert all(not secret or secret not in alert_text for secret in fixture.secret_values)
            record["notification_secret_leaks"] = 0
            passed = True
        except Exception as exc:
            record["failure"] = {"type": type(exc).__name__, "message": str(exc)[:300]}
        finally:
            if fixture is not None:
                fixture.close()
    hashes_after = {name: hashlib.sha256((ROOT / "server" / name).read_bytes()).hexdigest() for name in names}
    record["source_unchanged_during_test"] = hashes_after == hashes_before
    passed = passed and record["source_unchanged_during_test"]
    record["passed"] = passed
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "integration_tests.json").write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": passed, "evidence": str(OUT / "integration_tests.json"),
                      "failure": record.get("failure")}, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
