#!/usr/bin/env python3
"""VCNext build 37 authority with account-scoped, authenticated device locking."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import sqlite3
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

try:
    from . import notify, store
except ImportError:
    import notify
    import store

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, "server_private_key.pem")
DB_PATH = store.DB_PATH
APP_TEXT_DIGEST = "4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2"
LEASE_COMPAT_DIGEST = "d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943"
CLIENT_BUILD = "37"
SUPPORTED_APP_DIGESTS = {CLIENT_BUILD: frozenset({APP_TEXT_DIGEST})}
REQUIRED_CAPABILITIES = [
    "camera.fake-frame", "camera.obs", "media.import",
    "camera.controls", "camera.color-sync",
]
MAX_REQUEST_BYTES = 65536
PROOF_CLOCK_SKEW = 120
LOG = logging.getLogger("vcnext.auth")

with open(KEY_PATH, "rb") as key_file:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(key_file.read(), password=None)
if not isinstance(SERVER_PRIVATE_KEY, rsa.RSAPrivateKey) or SERVER_PRIVATE_KEY.key_size != 3072:
    raise ValueError("The configured VCNext authority must use RSA-3072")


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sign_json_payload(payload: dict) -> str:
    signature = SERVER_PRIVATE_KEY.sign(
        canonical_json_bytes(payload), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")


def parse_ec_public_key(value: str) -> ec.EllipticCurvePublicKey:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("invalid device_public_key")
    raw = base64.b64decode(value, validate=True)
    if len(raw) == 65 and raw[0] == 4:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    else:
        key = serialization.load_der_public_key(raw)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("device_public_key must be P-256")
    return key


def verify_ecdsa_p256_sha256(public_key, message: bytes, signature_b64: str) -> bool:
    try:
        if not isinstance(signature_b64, str) or not 1 <= len(signature_b64) <= 256:
            return False
        signature = base64.b64decode(signature_b64, validate=True)
        if not isinstance(public_key.curve, ec.SECP256R1):
            return False
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        return False


def verify_challenge_proof(payload: dict, public_key_b64: str, signature: str) -> bool:
    try:
        return verify_ecdsa_p256_sha256(
            parse_ec_public_key(public_key_b64), canonical_json_bytes(payload), signature)
    except (ValueError, TypeError):
        return False


def supported_client_artifact(body, headers) -> bool:
    if not isinstance(body, dict):
        return False
    build, digest = body.get("client_build"), body.get("binary_digest")
    if not isinstance(build, str) or not isinstance(digest, str):
        return False
    if digest not in SUPPORTED_APP_DIGESTS.get(build, ()):
        return False
    return all(headers.get(name) in (None, expected) for name, expected in (
        ("X-Client-Build", build), ("X-App-Digest", digest)))


def _text(body: dict, key: str, maximum: int, *, optional: bool = False) -> str:
    value = body.get(key, "")
    if not isinstance(value, str) or len(value) > maximum or (not optional and not value):
        raise store.AuthError(400, "invalid_request", f"Trường {key} không hợp lệ!")
    if any(ord(char) < 32 for char in value):
        raise store.AuthError(400, "invalid_request", f"Trường {key} không hợp lệ!")
    return value


def _public_user(user: dict) -> dict:
    return {"username": user["username"], "active_devices": int(user["active_devices"]),
            "max_devices": int(user["max_devices"]), "expires_at": int(user["expires_at"])}


def build_auth_response(user: dict, session: dict, *, issued_at: int | None = None) -> dict:
    issued = store.now() if issued_at is None else issued_at
    expires = min(issued + 90, int(user["expires_at"]))
    if expires <= issued:
        raise store.AuthError(403, "account_expired", "Tài khoản đã hết hạn!")
    access, renewal, nonce = (session[k] for k in ("access_token", "renewal_token", "current_nonce"))
    lease = {
        "version": 2, "purpose": "capability.lease", "issuer": "vcnext-main",
        "audience": "vcnext-ios", "build": CLIENT_BUILD,
        "device_id": session["device_id"], "device_key_thumbprint": session["thumbprint"],
        "binary_digest": LEASE_COMPAT_DIGEST,
        "session_binding": hashlib.sha256(access.encode("utf-8")).hexdigest(),
        "renewal_binding": hashlib.sha256(renewal.encode("utf-8")).hexdigest(),
        "next_nonce_hash": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
        "capabilities": list(REQUIRED_CAPABILITIES), "issued_at": issued, "expires_at": expires,
    }
    return {"ok": True, "protocol_version": 2, "access_token": access,
            "renewal_token": renewal, "next_nonce": nonce, "user": _public_user(user),
            "lease": lease, "lease_signature": sign_json_payload(lease)}


def _joined_session(con, device_id: str):
    return con.execute("""
        SELECT s.*, u.enabled AS account_enabled, u.auth_epoch AS account_epoch,
               u.expires_at AS account_expires, u.max_devices,
               d.username AS device_owner, d.enabled AS device_enabled,
               d.device_public_key AS enrolled_key, d.device_key_thumbprint AS enrolled_thumb
        FROM sessions s JOIN users u ON u.username = s.username
        JOIN devices d ON d.device_id = s.device_id WHERE s.device_id = ?
    """, (device_id,)).fetchone()


def _validate_session(row, token: str, endpoint: str, now: int) -> None:
    if row is None:
        raise store.AuthError(401, "session_not_found", "Phiên làm việc không tồn tại!\nLiên Hệ Telegram: @vcamplus")
    expected = row["renewal_token"] if endpoint == "renew" else row["access_token"]
    if not token or not hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
        raise store.AuthError(401, "invalid_token", "Token xác thực không hợp lệ!\nLiên Hệ Telegram: @vcamplus")
    if row["device_owner"] != row["username"]:
        raise store.AuthError(403, "device_bound_to_other_user", "Thiết bị đã gắn với tài khoản khác!\nLiên Hệ Telegram: @vcamplus")
    if int(row["device_enabled"]) != 1:
        raise store.AuthError(403, "device_disabled", "Thiết bị đang bị tạm khóa!\nLiên Hệ Telegram: @vcamplus")
    if int(row["account_enabled"]) != 1:
        raise store.AuthError(403, "account_disabled", "Tài khoản đang bị tạm khóa!\nLiên Hệ Telegram: @vcamplus")
    if min(int(row["account_expires"]), int(row["expires_at"])) <= now:
        raise store.AuthError(403, "account_expired", "Tài khoản đã hết hạn sử dụng!\nLiên Hệ Telegram: @vcamplus")
    if int(row["auth_epoch"]) != int(row["account_epoch"]):
        raise store.AuthError(401, "session_revoked", "Phiên làm việc đã bị thu hồi!\nLiên Hệ Telegram: @vcamplus")
    if not row["enrolled_key"] or row["enrolled_thumb"] != row["thumbprint"]:
        raise store.AuthError(401, "device_key_required", "Vui lòng đăng nhập lại để xác thực khóa!\nLiên Hệ Telegram: @vcamplus")


def refresh_session(endpoint: str, device_id: str, token: str, body: dict) -> dict:
    """Verify native nine-field proof, atomically refresh and cache exact retries.

    Tokens and nonce remain stable within a session so separately suspended app
    and daemon instances cannot invalidate each other's saved state. Mandatory
    P-256 proof, signed request IDs/timestamps and an exact-response replay cache
    provide freshness; a new login/revocation replaces the entire session.
    """
    now = store.now()
    request_id = _text(body, "request_id", 128)
    nonce = _text(body, "nonce", 256)
    signature = _text(body, "device_signature", 256)
    issued = body.get("issued_at")
    if type(issued) is not int or abs(now - issued) > PROOF_CLOCK_SKEW:
        raise store.AuthError(401, "request_expired", "Thời gian yêu cầu không hợp lệ!")
    with store.connect() as con:
        snapshot = _joined_session(con, device_id)
    _validate_session(snapshot, token, endpoint, now)
    proof = {"version": 2, "purpose": "auth." + endpoint, "request_id": request_id,
             "nonce": nonce, "device_id": device_id, "build": body["client_build"],
             "binary_digest": body["binary_digest"],
             "session_binding": hashlib.sha256(token.encode("utf-8")).hexdigest(), "issued_at": issued}
    if not verify_challenge_proof(proof, snapshot["enrolled_key"], signature):
        raise store.AuthError(401, "device_proof_failed", "Chữ ký thiết bị không hợp lệ!")
    request_hash = hashlib.sha256(canonical_json_bytes(proof)).hexdigest()
    candidate_session = dict(snapshot)
    with store.connect() as con:
        count = con.execute("SELECT COUNT(*) FROM devices WHERE username = ? AND enabled = 1",
                            (snapshot["username"],)).fetchone()[0]
    candidate_user = {"username": snapshot["username"], "active_devices": count,
                      "max_devices": snapshot["max_devices"], "expires_at": snapshot["account_expires"]}
    # Signing stays outside the writer lock; changed authorization is rejected below.
    response = build_auth_response(candidate_user, candidate_session, issued_at=now)
    with store.connect() as con:
        con.execute("BEGIN IMMEDIATE")
        now = store.now()
        if abs(now - issued) > PROOF_CLOCK_SKEW:
            raise store.AuthError(401, "request_expired", "Thời gian yêu cầu không hợp lệ!")
        current = _joined_session(con, device_id)
        _validate_session(current, token, endpoint, now)
        if (current["session_id"] != snapshot["session_id"] or
                current["auth_epoch"] != snapshot["auth_epoch"] or
                current["enrolled_key"] != snapshot["enrolled_key"] or
                current["account_expires"] != snapshot["account_expires"] or
                current["max_devices"] != snapshot["max_devices"]):
            raise store.AuthError(401, "session_changed", "Phiên đã thay đổi, vui lòng thử lại!")
        session_id = current["session_id"]
        con.execute("DELETE FROM auth_responses WHERE expires_at <= ?", (now,))
        cached = con.execute("SELECT request_hash, response_json FROM auth_responses WHERE session_id = ? AND request_id = ?",
                             (session_id, request_id)).fetchone()
        if cached:
            if cached["request_hash"] != request_hash:
                raise store.AuthError(401, "request_replayed", "Mã yêu cầu đã được sử dụng!")
            return json.loads(cached["response_json"])
        if nonce != current["current_nonce"]:
            raise store.AuthError(401, "nonce_mismatch", "Nonce phiên làm việc không hợp lệ!")
        con.execute("UPDATE sessions SET session_version = session_version + 1 WHERE session_id = ? AND auth_epoch = ?",
                    (session_id, current["auth_epoch"]))
        con.execute("UPDATE devices SET last_seen = ? WHERE device_id = ? AND username = ?",
                    (now, device_id, current["username"]))
        response["user"]["active_devices"] = con.execute(
            "SELECT COUNT(*) FROM devices WHERE username = ? AND enabled = 1", (current["username"],)).fetchone()[0]
        con.execute("INSERT INTO auth_responses(session_id, request_id, request_hash, response_json, expires_at) VALUES (?, ?, ?, ?, ?)",
                    (session_id, request_id, request_hash, json.dumps(response, separators=(",", ":")),
                     now + PROOF_CLOCK_SKEW * 2 + 1))
    return response


class VCNextRequestHandler(BaseHTTPRequestHandler):
    timeout = 5.0

    def _client_ip(self):
        peer = self.client_address[0]
        try:
            # Only local Nginx may assert the original address.
            claimed = self.headers.get("X-Real-IP") if ipaddress.ip_address(peer).is_loopback else None
            return str(ipaddress.ip_address(claimed or peer))
        except ValueError:
            return peer

    def _send_json(self, status_code: int, data: dict):
        if getattr(self, "_login_event_pending", False):
            self._login_event_pending = False
            body = getattr(self, "_request_body", {})
            username = body.get("username", "-")
            device_id = self.headers.get("X-Device-ID") or body.get("device_id", "-")
            name = body.get("device_name", "")
            args = (str(username)[:64], str(device_id)[:128], self._client_ip())
            try:
                if status_code == 200 and self._request_path.endswith("/login"):
                    args = (str(data["user"]["username"])[:64], args[1], args[2])
                    notify.notify_login_success(*args, device_name=str(name)[:128])
                elif status_code != 200:
                    notify.notify_login_fail(*args, reason=str(data.get("error", "invalid_request")),
                                             device_name=str(name)[:128])
            except Exception:
                LOG.error("Login notification dispatch failed")
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        if status_code == 503:
            self.send_header("Retry-After", "2")
        try:
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            LOG.warning("Client disconnected during authentication response")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/VCNext-custom-roothide.deb", "/download"):
            package = os.path.join(BASE_DIR, "VCNext-custom-roothide.deb")
            if os.path.isfile(package):
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.debian.binary-package")
                self.send_header("Content-Length", str(os.path.getsize(package)))
                self.send_header("Content-Disposition", 'attachment; filename="VCNext-custom-roothide.deb"')
                self.send_header("Connection", "close")
                self.end_headers()
                with open(package, "rb") as package_file:
                    while chunk := package_file.read(65536):
                        self.wfile.write(chunk)
                return
        self._send_json(200, {})

    def do_POST(self):
        self._request_path = self.path.split("?", 1)[0]
        self._request_body = {}
        self._login_event_pending = self._request_path in ("/api/v2/auth/challenge", "/api/v2/auth/login")
        try:
            self._handle_post()
        except store.AuthError as error:
            self._send_json(error.status, {"ok": False, "error": error.code, "message": error.message})
        except sqlite3.OperationalError:
            LOG.error("Database operation unavailable")
            self._send_json(503, {"ok": False, "error": "server_busy", "message": "Máy chủ đang bận, vui lòng thử lại!"})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            LOG.warning("Client disconnected during authentication response")
            self._send_json(408, {"ok": False, "error": "request_timeout", "message": "Yêu cầu đã hết thời gian!"})
        except Exception:
            LOG.error("Unhandled authentication failure")
            self._send_json(500, {"ok": False, "error": "internal_error", "message": "Lỗi xử lý yêu cầu!"})

    def _handle_post(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise store.AuthError(400, "invalid_request", "Content-Length không hợp lệ!")
        if self.headers.get("Transfer-Encoding") or length < 0:
            raise store.AuthError(400, "invalid_request", "Kiểu truyền yêu cầu không được hỗ trợ!")
        if length > MAX_REQUEST_BYTES:
            raise store.AuthError(413, "request_too_large", "Yêu cầu quá lớn!")
        try:
            body = json.loads(self.rfile.read(length) if length else b"{}")
        except (ValueError, UnicodeDecodeError):
            raise store.AuthError(400, "invalid_json", "JSON không hợp lệ!")
        if not isinstance(body, dict):
            raise store.AuthError(400, "invalid_request", "Yêu cầu phải là JSON object!")
        self._request_body = body
        path = self._request_path
        if path in ("/api/v1/bootstrap", "/api/v1/config", "/api/v1/events", "/api/v2/session"):
            return self._send_json(200, {})
        endpoints = {"/api/v2/auth/" + name for name in ("challenge", "login", "heartbeat", "renew", "logout")}
        if path not in endpoints:
            raise store.AuthError(404, "not_found", "Không tìm thấy API!")
        if not path.endswith("/logout") and not supported_client_artifact(body, self.headers):
            raise store.AuthError(426, "unsupported_client", "Unsupported app build or digest")
        device_id = _text(body, "device_id", 128, optional=True) or self.headers.get("X-Device-ID", "")
        if not device_id or len(device_id) > 128 or any(ord(char) < 33 for char in device_id):
            raise store.AuthError(400, "invalid_request", "device_id không hợp lệ!")
        header_device = self.headers.get("X-Device-ID")
        if header_device and header_device != device_id:
            raise store.AuthError(400, "device_id_mismatch", "Header và body device_id không khớp!")
        if path.endswith("/challenge"):
            username = _text(body, "username", 64).strip()
            if not store.USERNAME_RE.fullmatch(username):
                raise store.AuthError(400, "invalid_request", "Tên tài khoản không hợp lệ!")
            public_key = _text(body, "device_public_key", 2048)
            try:
                parse_ec_public_key(public_key)
                thumbprint = hashlib.sha256(base64.b64decode(public_key, validate=True)).hexdigest()
            except (ValueError, TypeError):
                raise store.AuthError(400, "device_key_invalid", "Khóa P-256 thiết bị không hợp lệ!")
            now = store.now()
            payload = {"version": 2, "purpose": "auth.challenge", "issuer": "vcnext-main",
                       "audience": "vcnext-ios", "username": store.normalize_username(username),
                       "device_id": device_id, "device_key_thumbprint": thumbprint,
                       "build": CLIENT_BUILD, "binary_digest": APP_TEXT_DIGEST,
                       "challenge_id": secrets.token_urlsafe(24), "nonce": secrets.token_hex(32),
                       "client_request_id": _text(body, "request_id", 128, optional=True),
                       "issued_at": now, "expires_at": now + 90}
            payload = store.save_auth_challenge(payload, public_key)
            return self._send_json(200, {"ok": True, "protocol_version": 2,
                                         "challenge": payload, "signature": sign_json_payload(payload)})
        if path.endswith("/login"):
            username = _text(body, "username", 64).strip()
            challenge_id = _text(body, "challenge_id", 128)
            challenge_nonce = _text(body, "challenge_nonce", 256)
            password = _text(body, "password", 128)
            signature = _text(body, "device_signature", 256)
            name = _text(body, "device_name", 128, optional=True)

            def bound_proof(payload, key, proof):
                return (payload.get("username") == store.normalize_username(username)
                        and verify_challenge_proof(payload, key, proof))

            result = store.complete_login(challenge_id, device_id, password, challenge_nonce,
                                          bound_proof, device_name=name, build=CLIENT_BUILD,
                                          device_signature=signature, requested_username=username)
            return self._send_json(200, build_auth_response(result["user"], result["session"]))
        authorization = self.headers.get("Authorization", "")
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or len(parts[1]) > 4096:
            raise store.AuthError(401, "invalid_token", "Yêu cầu cung cấp Bearer token hợp lệ!")
        token = parts[1]
        if path.endswith("/logout"):
            with store.connect() as con:
                con.execute("BEGIN IMMEDIATE")
                row = _joined_session(con, device_id)
                _validate_session(row, token, "logout", store.now())
                con.execute("DELETE FROM sessions WHERE session_id = ?", (row["session_id"],))
            return self._send_json(200, {"status": "revoked"})
        return self._send_json(200, refresh_session(path.rsplit("/", 1)[1], device_id, token, body))


def run():
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("PORT", "8000"))
    host = "127.0.0.1" if port == 8000 else "0.0.0.0"
    httpd = ThreadingHTTPServer((host, port), VCNextRequestHandler)
    httpd.daemon_threads = True
    if port == 443:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain("/etc/letsencrypt/live/vc.huxa.xyz/fullchain.pem",
                                "/etc/letsencrypt/live/vc.huxa.xyz/privkey.pem")
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    LOG.info("VCNext authority listening on %s:%d", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        notify.shutdown()


if __name__ == "__main__":
    run()
