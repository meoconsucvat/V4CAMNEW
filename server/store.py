"""
VCNext Commercial Account & Device Store (PBKDF2-HMAC-SHA256 & SQLite WAL)
Quản trị tài khoản (Username + Password), thiết bị (Devices), phiên (Sessions) và phân quyền Bot.
"""

from __future__ import annotations

import os
import sys
import time
import json
import secrets
import hashlib
import hmac
import sqlite3
import re
import base64
from typing import Any, Callable, Iterator
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "licenses.db")
PBKDF2_ROUNDS = 200_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")


class AuthError(ValueError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

def now() -> int:
    return int(time.time())

def normalize_username(username: str) -> str:
    return username.strip().casefold()

@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    con = sqlite3.connect(DB_PATH, timeout=15.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 5000")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

def password_hash(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ROUNDS)
    return salt, digest.hex()

def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, actual = password_hash(password, salt)
    return hmac.compare_digest(actual, expected_hash)


def validate_credentials(username: str, password: str) -> tuple[bool, dict[str, Any] | None, str | None]:
    """Validate actual credentials, including admin, without a special bypass."""
    user = get_user(username) if isinstance(username, str) else None
    if user is None:
        # Perform the same KDF work for an unknown name; no dummy credential is
        # ever accepted. HTTP decides which details may be exposed publicly.
        verify_password(password if isinstance(password, str) else "", "00" * 16, "00" * 32)
        return False, None, "user_not_found"
    valid = isinstance(password, str) and verify_password(password, user["password_salt"], user["password_hash"])
    if not valid:
        return False, user, "wrong_password"
    if int(user["enabled"]) != 1:
        return False, user, "account_disabled"
    if int(user["expires_at"]) <= now():
        return False, user, "account_expired"
    return True, user, None


def _validated_public_key(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise AuthError(400, "invalid_device_key", "Khóa bảo mật thiết bị không hợp lệ")
    try:
        raw = base64.b64decode(value, validate=True)
        from cryptography.hazmat.primitives.asymmetric import ec
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        if len(raw) != 65 or raw[0] != 4:
            raise ValueError("expected uncompressed P-256 key")
    except (ValueError, TypeError) as error:
        raise AuthError(400, "invalid_device_key", "Khóa bảo mật thiết bị không hợp lệ") from error
    return base64.b64encode(raw).decode("ascii"), hashlib.sha256(raw).hexdigest()


def _require_live_user(user: dict[str, Any] | None, ts: int) -> dict[str, Any]:
    if user is None:
        raise AuthError(403, "invalid_credentials", "Tài khoản chưa được đăng ký!\nLiên Hệ Telegram: @vcamplus")
    if int(user["enabled"]) != 1:
        raise AuthError(403, "account_disabled", "Tài khoản đang bị tạm khóa!\nLiên Hệ Telegram: @vcamplus")
    if int(user["expires_at"]) <= ts:
        raise AuthError(403, "account_expired", "Tài khoản đã hết hạn sử dụng!\nLiên Hệ Telegram: @vcamplus")
    return user


def _check_device_in_tx(con: sqlite3.Connection, user: dict[str, Any], device_id: str,
                        public_key: str = "", thumbprint: str = "") -> sqlite3.Row | None:
    existing = con.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if existing is not None:
        if existing["username"] != user["username"]:
            raise AuthError(403, "device_bound_to_other_user", "Thiết bị đã gắn với tài khoản khác!\nLiên Hệ Telegram: @vcamplus")
        if int(existing["enabled"]) != 1:
            raise AuthError(403, "device_disabled", "Thiết bị đang bị tạm khóa!\nLiên Hệ Telegram: @vcamplus")
        if public_key and existing["device_public_key"] and not hmac.compare_digest(existing["device_public_key"], public_key):
            raise AuthError(403, "device_key_mismatch", "Khóa bảo mật thiết bị không khớp")
        if thumbprint and existing["device_key_thumbprint"] and not hmac.compare_digest(existing["device_key_thumbprint"], thumbprint):
            raise AuthError(403, "device_key_mismatch", "Khóa bảo mật thiết bị không khớp")
        return existing
    count = con.execute("SELECT COUNT(*) FROM devices WHERE username = ? AND enabled = 1", (user["username"],)).fetchone()[0]
    if int(count) >= int(user["max_devices"]):
        raise AuthError(403, "device_limit_reached", "Đã đủ số thiết bị đăng ký!\nLiên Hệ Telegram: @vcamplus")
    return None


def save_auth_challenge(payload: dict[str, Any], device_public_key: str) -> dict[str, Any]:
    """Persist exactly what the client signs, with the current account epoch."""
    if not isinstance(payload, dict):
        raise AuthError(400, "challenge_invalid", "Thử thách bảo mật không hợp lệ")
    required = ("challenge_id", "device_id", "username", "nonce", "build")
    if any(not isinstance(payload.get(name), str) or not payload[name] for name in required):
        raise AuthError(400, "challenge_invalid", "Thử thách bảo mật không hợp lệ")
    if len(payload["device_id"]) > 256 or len(payload["nonce"]) < 32:
        raise AuthError(400, "challenge_invalid", "Thử thách bảo mật không hợp lệ")
    username = normalize_username(payload["username"])
    if username != payload["username"] or not USERNAME_RE.fullmatch(username):
        raise AuthError(400, "challenge_invalid", "Thử thách bảo mật không hợp lệ")
    public_key, thumbprint = _validated_public_key(device_public_key)
    if payload.get("device_key_thumbprint") != thumbprint:
        raise AuthError(400, "device_key_mismatch", "Khóa bảo mật thiết bị không khớp")
    ts = now()
    issued, expires = payload.get("issued_at"), payload.get("expires_at")
    if (type(issued) is not int or type(expires) is not int or issued > ts + 120
            or expires <= ts or expires <= issued or expires - issued > 90):
        raise AuthError(403, "challenge_invalid", "Thử thách bảo mật không hợp lệ")
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        ts = now()
        if expires <= ts:
            raise AuthError(403, "challenge_invalid", "Thử thách bảo mật không hợp lệ")
        user = _require_live_user(_user_in_tx(con, username), ts)
        _check_device_in_tx(con, user, payload["device_id"], public_key, thumbprint)
        con.execute("""
            INSERT INTO challenges(challenge_id, device_id, username, thumbprint, nonce, expires_at,
                                   payload_json, device_public_key, auth_epoch)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (payload["challenge_id"], payload["device_id"], username, thumbprint, payload["nonce"], expires,
              encoded, public_key, int(user["auth_epoch"])))
    return dict(payload)


def complete_login(challenge_id: str, device_id: str, password: str, challenge_nonce: str,
                   proof_verifier: Callable[[dict[str, Any], str, str], bool],
                   device_name: str = "", build: str = "", *, device_signature: str = "",
                   requested_username: str | None = None) -> dict[str, Any]:
    """Verify outside the write lock, then consume/enroll/issue in one transaction."""
    if not isinstance(challenge_id, str) or not challenge_id or not isinstance(device_id, str) or not device_id:
        raise AuthError(403, "challenge_invalid", "Thử thách bảo mật không hợp lệ")
    with connect() as con:
        con.execute("BEGIN")
        challenge = con.execute("SELECT * FROM challenges WHERE challenge_id = ? AND device_id = ?",
                                (challenge_id, device_id)).fetchone()
        user = _user_in_tx(con, challenge["username"]) if challenge else None
        before = dict(challenge) if challenge else None
    if before is None or not before["payload_json"] or not before["device_public_key"] or before["expires_at"] <= now():
        raise AuthError(403, "challenge_invalid", "Thử thách bảo mật không hợp lệ")
    if requested_username is not None and (not isinstance(requested_username, str)
            or normalize_username(requested_username) != before["username"]):
        raise AuthError(403, "challenge_invalid", "Thử thách không thuộc tài khoản yêu cầu")
    if (not isinstance(challenge_nonce, str) or not challenge_nonce
            or not hmac.compare_digest(challenge_nonce.encode("utf-8"), before["nonce"].encode("utf-8"))):
        raise AuthError(403, "nonce_mismatch", "Challenge nonce không hợp lệ")
    if user is None or not isinstance(password, str) or not verify_password(password, user["password_salt"], user["password_hash"]):
        raise AuthError(403, "wrong_password", "Sai mật khẩu đăng nhập!\nLiên Hệ Telegram: @vcamplus")
    _require_live_user(user, now())
    if int(user["auth_epoch"]) != int(before["auth_epoch"]):
        raise AuthError(403, "challenge_invalid", "Thử thách đã bị thu hồi")
    if not isinstance(device_signature, str) or not device_signature:
        raise AuthError(403, "device_proof_invalid", "Bằng chứng thiết bị không hợp lệ")
    try:
        valid_proof = proof_verifier(json.loads(before["payload_json"]), before["device_public_key"], device_signature)
    except Exception as error:
        raise AuthError(403, "device_proof_invalid", "Bằng chứng thiết bị không hợp lệ") from error
    if valid_proof is not True:
        raise AuthError(403, "device_proof_invalid", "Bằng chứng thiết bị không hợp lệ")
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        ts = now()
        current = con.execute("SELECT * FROM challenges WHERE challenge_id = ? AND device_id = ?",
                              (challenge_id, device_id)).fetchone()
        live = _require_live_user(_user_in_tx(con, user["username"]), ts)
        if (current is None or dict(current) != before or current["expires_at"] <= ts
                or int(live["auth_epoch"]) != int(before["auth_epoch"])
                or (live["password_salt"], live["password_hash"]) != (user["password_salt"], user["password_hash"])):
            raise AuthError(403, "challenge_invalid", "Thử thách đã bị thu hồi hoặc tiêu thụ")
        _check_device_in_tx(con, live, device_id, current["device_public_key"], current["thumbprint"])
        consumed = con.execute("DELETE FROM challenges WHERE challenge_id = ? AND device_id = ? AND auth_epoch = ?",
                               (challenge_id, device_id, live["auth_epoch"]))
        if consumed.rowcount != 1:
            raise AuthError(403, "challenge_invalid", "Thử thách đã được tiêu thụ")
        con.execute("""
            INSERT INTO devices(device_id, username, enabled, first_seen, last_seen, device_name, build,
                                device_public_key, device_key_thumbprint)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET last_seen = excluded.last_seen,
                device_name = excluded.device_name, build = excluded.build,
                device_public_key = excluded.device_public_key, device_key_thumbprint = excluded.device_key_thumbprint
        """, (device_id, live["username"], ts, ts, str(device_name), str(build),
              current["device_public_key"], current["thumbprint"]))
        session = {"device_id": device_id, "username": live["username"], "thumbprint": current["thumbprint"],
                   "access_token": "at_" + secrets.token_hex(32), "renewal_token": "rn_" + secrets.token_hex(32),
                   "current_nonce": secrets.token_hex(32), "expires_at": int(live["expires_at"]),
                   "created_at": ts, "session_version": 1, "auth_epoch": int(live["auth_epoch"]),
                   "session_id": secrets.token_hex(24)}
        # A new authenticated login revokes the prior session and its replay/
        # response cache. Delete before insertion rather than changing a referenced
        # session_id in place.
        con.execute("DELETE FROM sessions WHERE device_id = ?", (device_id,))
        con.execute("""
            INSERT INTO sessions(device_id, username, thumbprint, access_token, renewal_token, current_nonce,
                                 expires_at, created_at, session_version, auth_epoch, session_id)
            VALUES (:device_id, :username, :thumbprint, :access_token, :renewal_token, :current_nonce,
                    :expires_at, :created_at, :session_version, :auth_epoch, :session_id)
        """, session)
        _audit_in_tx(con, "login", live["username"], {"device_id": device_id}, "api")
        return {"user": _user_in_tx(con, live["username"]), "session": session}


def record_device_login(username: str, body: Any, con: sqlite3.Connection | None = None) -> tuple[bool, str | None]:
    """Compatibility device-enrollment API; HTTP authentication uses complete_login."""
    if not isinstance(body, dict) or not isinstance(body.get("device_id"), str) or not body["device_id"]:
        return False, "invalid_device"
    username = normalize_username(username)
    def enroll(connection: sqlite3.Connection) -> tuple[bool, str | None]:
        user = _require_live_user(_user_in_tx(connection, username), now())
        pub = str(body.get("device_public_key") or "")
        thumb = str(body.get("device_key_thumbprint") or "")
        if pub:
            pub, measured = _validated_public_key(pub)
            if thumb and thumb != measured:
                return False, "device_key_mismatch"
            thumb = measured
        _check_device_in_tx(connection, user, body["device_id"], pub, thumb)
        ts = now()
        connection.execute("""
            INSERT INTO devices(device_id, username, enabled, first_seen, last_seen, device_name, build,
                                device_public_key, device_key_thumbprint)
            VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET last_seen = excluded.last_seen,
                device_name = excluded.device_name, build = excluded.build
        """, (body["device_id"], username, ts, ts, str(body.get("device_name") or ""),
              str(body.get("client_build") or ""), pub, thumb))
        return True, None
    try:
        if con is not None:
            if not con.in_transaction:
                return False, "transaction_required"
            return enroll(con)
        with connect() as owned:
            owned.execute("BEGIN IMMEDIATE")
            return enroll(owned)
    except AuthError as error:
        return False, error.code


def get_session_snapshot(device_id: str) -> dict[str, Any] | None:
    with connect() as con:
        con.execute("BEGIN")
        row = con.execute("SELECT * FROM sessions WHERE device_id = ?", (device_id,)).fetchone()
        if row is None:
            return None
        user = _user_in_tx(con, row["username"])
        device = con.execute("SELECT * FROM devices WHERE device_id = ? AND username = ?",
                             (device_id, row["username"])).fetchone()
        return {"session": dict(row), "user": user, "device": dict(device) if device else None}

def init_db() -> None:
    with connect() as con:
        # WAL is persistent; changing journal mode on every request can itself
        # contend with active transactions. Establish it during initialization.
        con.execute("PRAGMA journal_mode = WAL")
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            expires_at INTEGER NOT NULL,
            max_devices INTEGER NOT NULL DEFAULT 1,
            auth_epoch INTEGER NOT NULL DEFAULT 1,
            note TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
            enabled INTEGER NOT NULL DEFAULT 1,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            device_name TEXT NOT NULL DEFAULT '',
            build TEXT NOT NULL DEFAULT '',
            device_public_key TEXT NOT NULL DEFAULT '',
            device_key_thumbprint TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS sessions (
            device_id TEXT PRIMARY KEY,
            username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
            thumbprint TEXT NOT NULL,
            access_token TEXT NOT NULL UNIQUE,
            renewal_token TEXT NOT NULL,
            current_nonce TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            session_version INTEGER NOT NULL DEFAULT 1,
            auth_epoch INTEGER NOT NULL DEFAULT 1,
            session_id TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS challenges (
            challenge_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            username TEXT NOT NULL,
            thumbprint TEXT NOT NULL,
            nonce TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '',
            device_public_key TEXT NOT NULL DEFAULT '',
            auth_epoch INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS admin_confirmations (
            code TEXT PRIMARY KEY,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS bot_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            detail_json TEXT NOT NULL
        );
        """)

        # Migration cho các cột mới nếu bảng đã tồn tại từ trước
        con.execute("BEGIN IMMEDIATE")
        cur = con.execute("PRAGMA table_info(users)")
        u_cols = {r["name"] for r in cur.fetchall()}
        if "auth_epoch" not in u_cols:
            con.execute("ALTER TABLE users ADD COLUMN auth_epoch INTEGER NOT NULL DEFAULT 1")

        cur = con.execute("PRAGMA table_info(sessions)")
        s_cols = {r["name"] for r in cur.fetchall()}
        if "session_version" not in s_cols:
            con.execute("ALTER TABLE sessions ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")
        if "auth_epoch" not in s_cols:
            con.execute("ALTER TABLE sessions ADD COLUMN auth_epoch INTEGER NOT NULL DEFAULT 1")
        if "session_id" not in s_cols:
            con.execute("ALTER TABLE sessions ADD COLUMN session_id TEXT NOT NULL DEFAULT ''")
        for row in con.execute("SELECT device_id FROM sessions WHERE session_id = '' OR session_id IS NULL").fetchall():
            con.execute("UPDATE sessions SET session_id = ? WHERE device_id = ?", (secrets.token_hex(24), row["device_id"]))
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS auth_responses (
                session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
                request_id TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY(session_id, request_id)
            )
        """)

        c_cols = {r["name"] for r in con.execute("PRAGMA table_info(challenges)")}
        for name, declaration in (
            ("payload_json", "TEXT NOT NULL DEFAULT ''"),
            ("device_public_key", "TEXT NOT NULL DEFAULT ''"),
            ("auth_epoch", "INTEGER NOT NULL DEFAULT 0"),
        ):
            if name not in c_cols:
                con.execute(f"ALTER TABLE challenges ADD COLUMN {name} {declaration}")

        # Optional admin seed if explicitly requested via environment
        seed_admin = os.environ.get("VCNEXT_SEED_ADMIN", "0").strip().lower() in ("1", "true", "yes")
        if seed_admin:
            cur = con.execute("SELECT username FROM users WHERE username = 'admin'")
            if not cur.fetchone():
                initial_password = os.environ.get("VCNEXT_ADMIN_INITIAL_PASSWORD") or secrets.token_urlsafe(24)
                salt, hashed = password_hash(initial_password)
                ts = now()
                con.execute("""
                INSERT INTO users (username, password_salt, password_hash, enabled, expires_at, max_devices, auth_epoch, note, created_at, updated_at)
                VALUES ('admin', ?, ?, 1, ?, 5, 1, 'Master Developer Account', ?, ?)
                """, (salt, hashed, ts + 315360000, ts, ts))
                con.execute("""
                INSERT OR IGNORE INTO devices (device_id, username, enabled, first_seen, last_seen, device_name, device_key_thumbprint)
                VALUES ('935BB480-D9F3-4154-861C-8B4F38CF0237', 'admin', 1, ?, ?, 'iPhone 8 Plus (Dev)', '2a8f42ce22b48ddcde25656c2018e12475b11cf963b12d180867dbc424247364')
                """, (ts, ts))

def backup_database(dest_path: str) -> None:
    """Sao lưu database an toàn 100% khi đang chạy SQLite WAL mode bằng API online backup"""
    with connect() as src:
        dest = sqlite3.connect(dest_path)
        try:
            src.backup(dest)
        finally:
            dest.close()

def audit(action: str, target: str, detail: dict[str, Any] | None = None, actor: str = "local") -> None:
    with connect() as con:
        _audit_in_tx(con, action, target, detail, actor)


def _audit_in_tx(con: sqlite3.Connection, action: str, target: str,
                 detail: dict[str, Any] | None = None, actor: str = "local") -> None:
    con.execute(
        "INSERT INTO audit_logs(created_at, actor, action, target, detail_json) VALUES (?, ?, ?, ?, ?)",
        (now(), actor, action, target, json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)),
    )


_USER_SNAPSHOT_SQL = """
SELECT u.*,
       (SELECT COUNT(*) FROM devices d WHERE d.username = u.username AND d.enabled = 1) AS active_devices,
       (SELECT COUNT(*) FROM devices d WHERE d.username = u.username) AS total_devices
  FROM users u
"""


def _user_in_tx(con: sqlite3.Connection, username: str) -> dict[str, Any] | None:
    row = con.execute(_USER_SNAPSHOT_SQL + " WHERE u.username = ?", (username,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["expires_in"] = max(0, int(result["expires_at"]) - now())
    return result

def create_user(
    username: str,
    password: str,
    days: int = 30,
    max_devices: int = 1,
    note: str = "",
    actor: str = "local",
    replace: bool = False,
    duration_seconds: int | None = None,
) -> dict[str, Any]:
    username = normalize_username(username)
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Tên tài khoản cần 3-64 ký tự: chữ cái, chữ số, dấu gạch ngang hoặc gạch dưới")
    if not password:
        raise ValueError("Mật khẩu không được để trống")
    ttl = int(duration_seconds) if duration_seconds is not None else int(days) * 86400
    if ttl <= 0:
        raise ValueError("Thời hạn phải lớn hơn 0")
    if max_devices <= 0:
        raise ValueError("Số thiết bị phải lớn hơn 0")

    salt, hashed = password_hash(password)
    ts = now()
    expires_at = ts + ttl

    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        exists = con.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists and not replace:
            raise ValueError(f"Tài khoản đã tồn tại: {username}")
        if exists:
            con.execute("""
            UPDATE users
               SET password_salt = ?, password_hash = ?, enabled = 1,
                   expires_at = ?, max_devices = ?, note = ?, updated_at = ?
                   , auth_epoch = auth_epoch + 1
             WHERE username = ?
            """, (salt, hashed, expires_at, max_devices, note, ts, username))
            con.execute("DELETE FROM sessions WHERE username = ?", (username,))
            con.execute("DELETE FROM challenges WHERE username = ?", (username,))
        else:
            con.execute("""
            INSERT INTO users(username, password_salt, password_hash, enabled, expires_at, max_devices, auth_epoch, note, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?, 1, ?, ?, ?)
            """, (username, salt, hashed, expires_at, max_devices, note, ts, ts))
        _audit_in_tx(con, "replace_user" if exists else "create_user", username, {"duration_seconds": ttl, "max_devices": max_devices}, actor)
        return _user_in_tx(con, username)

def get_user(username: str) -> dict[str, Any] | None:
    username = normalize_username(username)
    with connect() as con:
        return _user_in_tx(con, username)

def list_users(limit: int = 50) -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute(_USER_SNAPSHOT_SQL + " ORDER BY u.updated_at DESC LIMIT ?", (limit,)).fetchall()
        ts = now()
        return [dict(row, expires_in=max(0, int(row["expires_at"]) - ts)) for row in rows]

def extend_user_seconds(username: str, duration_seconds: int, actor: str = "local") -> dict[str, Any]:
    if duration_seconds <= 0:
        raise ValueError("Thời gian gia hạn phải lớn hơn 0")
    username = normalize_username(username)
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        user = _user_in_tx(con, username)
        if user is None:
            raise ValueError(f"Không tìm thấy tài khoản: {username}")
        expires_at = max(now(), int(user["expires_at"])) + int(duration_seconds)
        con.execute("UPDATE users SET expires_at = ?, updated_at = ? WHERE username = ?", (expires_at, now(), username))
        con.execute("UPDATE sessions SET expires_at = ? WHERE username = ?", (expires_at, username))
        _audit_in_tx(con, "extend_user", username, {"duration_seconds": int(duration_seconds)}, actor)
        return _user_in_tx(con, username)

def set_user_password(username: str, password: str, actor: str = "local") -> dict[str, Any]:
    if not password:
        raise ValueError("Mật khẩu không được để trống")
    username = normalize_username(username)
    salt, hashed = password_hash(password)
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        if _user_in_tx(con, username) is None:
            raise ValueError(f"Không tìm thấy tài khoản: {username}")
        # Tăng auth_epoch để vô hiệu hóa mọi login in-flight
        con.execute("UPDATE users SET password_salt = ?, password_hash = ?, auth_epoch = auth_epoch + 1, updated_at = ? WHERE username = ?", (salt, hashed, now(), username))
        con.execute("DELETE FROM sessions WHERE username = ?", (username,))
        con.execute("DELETE FROM challenges WHERE username = ?", (username,))
        _audit_in_tx(con, "set_user_password", username, {}, actor)
        return _user_in_tx(con, username)

def set_max_devices(username: str, max_devices: int, actor: str = "local") -> dict[str, Any]:
    if max_devices <= 0:
        raise ValueError("Số thiết bị phải lớn hơn 0")
    username = normalize_username(username)
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        if _user_in_tx(con, username) is None:
            raise ValueError(f"Không tìm thấy tài khoản: {username}")
        con.execute("UPDATE users SET max_devices = ?, updated_at = ? WHERE username = ?", (max_devices, now(), username))
        _audit_in_tx(con, "set_max_devices", username, {"max_devices": max_devices}, actor)
        return _user_in_tx(con, username)

def set_user_enabled(username: str, enabled: bool, actor: str = "local") -> dict[str, Any]:
    username = normalize_username(username)
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        if _user_in_tx(con, username) is None:
            raise ValueError(f"Không tìm thấy tài khoản: {username}")
        con.execute("UPDATE users SET enabled = ?, auth_epoch = auth_epoch + 1, updated_at = ? WHERE username = ?", (1 if enabled else 0, now(), username))
        con.execute("DELETE FROM sessions WHERE username = ?", (username,))
        con.execute("DELETE FROM challenges WHERE username = ?", (username,))
        _audit_in_tx(con, "enable_user" if enabled else "disable_user", username, {}, actor)
        return _user_in_tx(con, username)

def delete_user(username: str, actor: str = "local") -> None:
    username = normalize_username(username)
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        if _user_in_tx(con, username) is None:
            raise ValueError(f"Không tìm thấy tài khoản: {username}")
        con.execute("DELETE FROM users WHERE username = ?", (username,))
        con.execute("DELETE FROM devices WHERE username = ?", (username,))
        con.execute("DELETE FROM sessions WHERE username = ?", (username,))
        con.execute("DELETE FROM challenges WHERE username = ?", (username,))
        _audit_in_tx(con, "delete_user", username, {}, actor)

def list_devices(username: str) -> list[dict[str, Any]]:
    username = normalize_username(username)
    with connect() as con:
        rows = con.execute("SELECT d.* FROM devices d JOIN users u ON u.username = d.username WHERE u.username = ? ORDER BY d.last_seen DESC", (username,)).fetchall()
    return [dict(row) for row in rows]

def list_expired_users(limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with connect() as con:
        ts = now()
        rows = con.execute(_USER_SNAPSHOT_SQL + " WHERE u.expires_at <= ? ORDER BY u.expires_at ASC LIMIT ?", (ts, limit)).fetchall()
        return [dict(row, expires_in=max(0, int(row["expires_at"]) - ts)) for row in rows]

def delete_expired_users(actor: str = "local") -> list[str]:
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        rows = con.execute("SELECT username FROM users WHERE expires_at <= ?", (now(),)).fetchall()
        usernames = [str(row["username"]) for row in rows]
        if usernames:
            con.executemany("DELETE FROM users WHERE username = ?", ((name,) for name in usernames))
            con.executemany("DELETE FROM devices WHERE username = ?", ((name,) for name in usernames))
            con.executemany("DELETE FROM sessions WHERE username = ?", ((name,) for name in usernames))
            con.executemany("DELETE FROM challenges WHERE username = ?", ((name,) for name in usernames))
        _audit_in_tx(con, "delete_expired_users", "expired", {"count": len(usernames)}, actor)
        return usernames

def reset_devices(username: str, actor: str = "local") -> int:
    """Mở khóa đổi máy: xóa devices và sessions của user, tăng auth_epoch, bảo lưu ngày dùng và mật khẩu"""
    username = normalize_username(username)
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        if _user_in_tx(con, username) is None:
            raise ValueError(f"Không tìm thấy tài khoản: {username}")
        cur = con.execute("DELETE FROM devices WHERE username = ?", (username,))
        deleted = cur.rowcount
        con.execute("DELETE FROM sessions WHERE username = ?", (username,))
        con.execute("DELETE FROM challenges WHERE username = ?", (username,))
        con.execute("UPDATE users SET auth_epoch = auth_epoch + 1, updated_at = ? WHERE username = ?", (now(), username))
        _audit_in_tx(con, "reset_devices", username, {"deleted_devices": deleted}, actor)
        return int(deleted)

def remove_device(username: str, device_id: str, actor: str = "local") -> bool:
    username = normalize_username(username)
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        cur = con.execute("DELETE FROM devices WHERE username = ? AND device_id = ?", (username, device_id))
        deleted = cur.rowcount > 0
        if deleted:
            con.execute("DELETE FROM sessions WHERE username = ? AND device_id = ?", (username, device_id))
            con.execute("DELETE FROM challenges WHERE username = ? AND device_id = ?", (username, device_id))
            _audit_in_tx(con, "remove_device", username, {"device_id": device_id}, actor)
    return deleted

def resolve_device_id(username: str, prefix: str) -> str:
    devices = list_devices(username)
    matches = [d["device_id"] for d in devices if str(d["device_id"]).lower().startswith(prefix.lower())]
    if not matches:
        raise ValueError(f"Không tìm thấy thiết bị khớp tiền tố '{prefix}'")
    if len(matches) > 1:
        raise ValueError(f"Có nhiều hơn 1 thiết bị khớp '{prefix}', hãy nhập chi tiết hơn")
    return matches[0]

# --- Admin Confirmations & Bot State ---
def create_confirmation(actor: str, action: str, payload: dict[str, Any], ttl: int = 90) -> str:
    code = secrets.token_hex(8).upper() # 64-bit entropy
    ts = now()
    with connect() as con:
        con.execute("""
        INSERT INTO admin_confirmations(code, actor, action, payload_json, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (code, actor, action, json.dumps(payload, ensure_ascii=False), ts, ts + ttl))
    return code

def consume_confirmation(actor: str, code: str) -> tuple[str, dict[str, Any]]:
    code = code.strip().upper()
    ts = now()
    with connect() as con:
        # Atomic consume strictly bound to actor
        cur = con.execute("""
        UPDATE admin_confirmations
           SET consumed = 1
         WHERE code = ? AND actor = ? AND consumed = 0 AND expires_at >= ?
        """, (code, actor, ts))
        if cur.rowcount == 0:
            raise ValueError("Mã xác nhận không hợp lệ, không đúng người thao tác hoặc đã hết hạn")
        row = con.execute("SELECT action, payload_json FROM admin_confirmations WHERE code = ?", (code,)).fetchone()
    return str(row["action"]), json.loads(row["payload_json"])

def cancel_confirmation(actor: str, code: str) -> bool:
    code = code.strip().upper()
    with connect() as con:
        cur = con.execute("UPDATE admin_confirmations SET consumed = 1 WHERE code = ? AND actor = ? AND consumed = 0", (code, actor))
        return cur.rowcount > 0

def set_bot_state(key: str, value: str) -> None:
    with connect() as con:
        con.execute("""
        INSERT INTO bot_state(key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """, (key, value, now()))

def get_bot_state(key: str, default: str = "") -> str:
    with connect() as con:
        row = con.execute("SELECT value FROM bot_state WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

def delete_bot_state(key: str) -> None:
    with connect() as con:
        con.execute("DELETE FROM bot_state WHERE key = ?", (key,))

def recent_audit(limit: int = 15) -> list[dict[str, Any]]:
    with connect() as con:
        rows = con.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

init_db()
