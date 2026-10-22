#!/usr/bin/env python3
"""
VCNext Telegram Administration Bot (Fully Hardened Edition)
Quản trị tài khoản, thiết bị, gia hạn, đổi mật khẩu và đổi máy trực tiếp qua Telegram.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))

try:
    from . import store
except ImportError:
    import store

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
API_TIMEOUT = max(5, min(int(os.environ.get("TELEGRAM_POLL_TIMEOUT", "25")), 50))
LOCK_PATH = Path(os.environ.get("TELEGRAM_BOT_LOCK_PATH", "/tmp/vcnext_telegram_bot.lock" if os.name != "nt" else os.path.join(BASE_DIR, "telegram_bot.lock")))
PRIVATE_ONLY = True
OWNER_ID = 5137016124
EXPECTED_BOT_USERNAME = "VCAM_V5_ADMIN_BOT"
CONFIRM_TTL = max(30, min(int(os.environ.get("TELEGRAM_CONFIRM_TTL", "90")), 300))
WIZARD_TTL = max(120, min(int(os.environ.get("TELEGRAM_WIZARD_TTL", "600")), 1800))
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
DURATION_RE = re.compile(r"^(\d+)\s*(h|hr|hrs|hour|hours|d|day|days)?$", re.IGNORECASE)

ROLE_RANK = {"viewer": 1, "operator": 2, "owner": 3}
STOP = False
LOCK_HANDLE: Any = None

# This deployment has exactly one administrator. Environment variables cannot
# silently grant access to an additional user or enable group administration.
OWNER_IDS = {OWNER_ID}
OPERATOR_IDS: set[int] = set()
VIEWER_IDS: set[int] = set()

BTN_USERS = "👥 Tài khoản"
BTN_DEVICES = "📱 Thiết bị"
BTN_CREATE = "➕ Tạo tài khoản"
BTN_FIND = "🔎 Tìm tài khoản"
BTN_EXTEND = "⏳ Gia hạn"
BTN_PASSWORD = "🔑 Đổi mật khẩu"
BTN_RESET = "🧹 Đổi máy"
BTN_DELETE = "🗑 Xóa tài khoản"
BTN_EXPIRED = "⌛ Đã hết hạn"
BTN_STATUS = "📊 Hệ thống"
BTN_BACKUP = "💾 Sao lưu"
BTN_HELP = "❓ Trợ giúp"
BTN_CANCEL = "❌ Hủy"
BTN_RANDOM = "🎲 Tự tạo"
BTN_MANUAL = "⌨️ Tự nhập"

MAIN_KEYBOARD = {
    "keyboard": [
        [{"text": BTN_USERS}, {"text": BTN_DEVICES}],
        [{"text": BTN_CREATE}, {"text": BTN_FIND}],
        [{"text": BTN_EXTEND}, {"text": BTN_PASSWORD}],
        [{"text": BTN_RESET}, {"text": BTN_DELETE}],
        [{"text": BTN_EXPIRED}, {"text": BTN_STATUS}],
        [{"text": BTN_BACKUP}, {"text": BTN_HELP}],
    ],
    "resize_keyboard": True,
    "is_persistent": True,
    "input_field_placeholder": "Chọn chức năng quản trị",
}

def choice_keyboard(rows: list[list[str]]) -> dict[str, Any]:
    return {
        "keyboard": [[{"text": label} for label in row] for row in rows] + [[{"text": BTN_CANCEL}]],
        "resize_keyboard": True,
        "one_time_keyboard": True,
    }

DURATION_KEYBOARD = choice_keyboard([["1 giờ", "1 ngày"], ["7 ngày", "30 ngày"], ["90 ngày", "365 ngày"]])
DEVICE_KEYBOARD = choice_keyboard([["1 máy", "2 máy", "3 máy"]])
PASSWORD_KEYBOARD = choice_keyboard([[BTN_RANDOM, BTN_MANUAL]])
CANCEL_KEYBOARD = choice_keyboard([])

HELP = """<b>VCAMPLUS Admin Bot (@VCAM_V5_ADMIN_BOT)</b>

Dùng các nút bên dưới hoặc lệnh nhanh:
/add &lt;user&gt; &lt;mật_khẩu&gt; &lt;thời_hạn&gt; &lt;số_máy&gt;
/find &lt;user&gt;
/extend &lt;user&gt; &lt;thời_hạn&gt;
/setpass &lt;user&gt; [mật_khẩu_mới]
/clear &lt;user&gt;
/del &lt;user&gt;
/expired
/delexpired
/status
/backup

Ví dụ: <code>/add usertest 1 30 1</code>
Thời hạn: số ngày hoặc 5h, 1d, 7d, 30d. Mật khẩu tự nhập: 1-128 ký tự.
Các thao tác xóa/reset dùng nút Xác nhận hoặc Hủy.
"""

class ConfirmationReply(str):
    code: str

    def __new__(cls, text: str, code: str) -> "ConfirmationReply":
        instance = super().__new__(cls, text)
        instance.code = code
        return instance

@dataclass
class MessageReply:
    text: str
    markup: dict[str, Any] | None = None
    delete_source: bool = False
    parse_mode: str | None = None

def role_for(user_id: int) -> str | None:
    if user_id in OWNER_IDS:
        return "owner"
    if user_id in OPERATOR_IDS:
        return "operator"
    if user_id in VIEWER_IDS:
        return "viewer"
    return None

def require_role(role: str, minimum: str) -> None:
    if ROLE_RANK.get(role, 0) < ROLE_RANK[minimum]:
        raise PermissionError(f"cần quyền {minimum}")

def api_url(method: str) -> str:
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is required")
    return f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"

def request_json(method: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    encoded = urllib.parse.urlencode(payload or {}).encode("utf-8")
    request = urllib.request.Request(api_url(method), data=encoded)
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT + 10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            description = str(json.loads(body).get("description") or f"HTTP {exc.code}")
        except Exception:
            description = f"HTTP {exc.code}"
        raise RuntimeError(f"Telegram API: {description}") from exc
    if not result.get("ok"):
        raise RuntimeError(f"Telegram API: {result.get('description', 'request failed')}")
    return result

def send_message(chat_id: int, text: str, markup: dict[str, Any] | None = None, parse_mode: str | None = None) -> None:
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "text": text[:3900],
        "disable_web_page_preview": "true",
    }
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if markup is not None:
        payload["reply_markup"] = json.dumps(markup, ensure_ascii=False)
    request_json("sendMessage", payload)

def send_document(chat_id: int, file_path: Path | str, caption: str = "") -> None:
    boundary = "----WebKitFormBoundary" + secrets.token_hex(16)
    with open(file_path, "rb") as f:
        file_bytes = f.read()
    filename = Path(file_path).name

    body = bytearray()
    body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat_id}\r\n".encode("utf-8"))
    if caption:
        body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{caption}\r\n".encode("utf-8"))
    body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{filename}\"\r\nContent-Type: application/x-sqlite3\r\n\r\n".encode("utf-8"))
    body.extend(file_bytes)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request(api_url("sendDocument"), data=bytes(body), headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if not data.get("ok"):
                raise RuntimeError(f"Telegram sendDocument rejected: {data.get('description')}")
    except Exception as exc:
        raise RuntimeError(f"Không thể gửi file backup: {exc}") from exc

def delete_message(chat_id: int, message_id: int) -> None:
    try:
        request_json("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
    except RuntimeError:
        pass

def answer_callback(callback_id: str, text: str = "") -> None:
    payload = {"callback_query_id": callback_id}
    if text:
        payload["text"] = text[:180]
    request_json("answerCallbackQuery", payload)

def confirmation_markup(code: str) -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "✅ Xác nhận", "callback_data": f"confirm:{code}"},
                {"text": "❌ Hủy", "callback_data": f"cancel:{code}"},
            ]
        ]
    }

def parse_positive(value: str, label: str, maximum: int = 100_000) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{label} phải là số nguyên") from exc
    if parsed <= 0 or parsed > maximum:
        raise ValueError(f"{label} phải từ 1 đến {maximum}")
    return parsed

def parse_duration(value: str) -> tuple[int, str]:
    normalized = value.strip().lower().replace("giờ", "h").replace("ngày", "d").replace("máy", "")
    match = DURATION_RE.fullmatch(normalized.strip())
    if not match:
        raise ValueError("thời hạn không hợp lệ; dùng 5h, 1d, 7d hoặc 30d")
    amount = int(match.group(1))
    unit = (match.group(2) or "d").lower()
    if amount <= 0:
        raise ValueError("thời hạn phải lớn hơn 0")
    if unit in {"h", "hr", "hrs", "hour", "hours"}:
        seconds = amount * 3600
        label = f"{amount} giờ"
    else:
        seconds = amount * 86400
        label = f"{amount} ngày"
    if seconds > 36500 * 86400:
        raise ValueError("thời hạn quá lớn")
    return seconds, label

def validate_username(username: str) -> str:
    username = store.normalize_username(username)
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("username cần 3-64 ký tự: chữ, số, dấu chấm, gạch ngang hoặc gạch dưới")
    return username

def validate_password(password: str) -> str:
    if not 1 <= len(password) <= 128 or any(char in password for char in "\r\n"):
        raise ValueError("mật khẩu cần từ 1 đến 128 ký tự, không chứa xuống dòng")
    return password

def generated_password() -> str:
    return secrets.token_urlsafe(12)

def remaining_text(user: dict[str, Any]) -> str:
    seconds = int(user["expires_at"]) - store.now()
    if seconds <= 0:
        return "đã hết hạn"
    days, remainder = divmod(seconds, 86400)
    hours = remainder // 3600
    if days:
        return f"{days} ngày {hours} giờ"
    return f"{max(1, hours)} giờ"

def format_epoch(value: int) -> str:
    return datetime.fromtimestamp(int(value), timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

def user_line(user: dict[str, Any]) -> str:
    status = "🟢 BẬT" if int(user["enabled"]) == 1 else "🔴 TẮT"
    total = int(user.get("total_devices", user["active_devices"]))
    disabled = max(0, total - int(user["active_devices"]))
    return (
        f"{status} <code>{escape(user['username'])}</code> | {remaining_text(user)} | "
        f"máy bật {user['active_devices']}/{user['max_devices']}, tắt {disabled}, tổng {total}"
    )

def format_user(username: str) -> str:
    user = store.get_user(validate_username(username))
    if user is None:
        raise ValueError(f"không tìm thấy tài khoản: {username}")
    u_esc = escape(user['username'])
    status = "🟢 BẬT" if int(user["enabled"]) == 1 else "🔴 Đang bị khóa (TẮT)"
    total = int(user.get("total_devices", user["active_devices"]))
    return "\n".join(
        [
            f"<b>🔎 CHI TIẾT TÀI KHOẢN:</b> <code>{u_esc}</code>",
            "━━━━━━━━━━━━━━━━━━━━━━",
            f"• <b>Trạng thái:</b> {status}",
            f"• <b>Còn lại:</b> {remaining_text(user)}",
            f"• <b>Ngày hết hạn:</b> {format_epoch(int(user['expires_at']))}",
            f"• <b>Thiết bị:</b> {user['active_devices']}/{user['max_devices']} máy bật; "
            f"{max(0, total - int(user['active_devices']))} tắt; tổng {total}",
            f"• <b>Ghi chú:</b> {escape(user.get('note') or '-')}",
            "━━━━━━━━━━━━━━━━━━━━━━",
            "<i>Lệnh nhanh:</i>",
            f"/clear {u_esc} (Đổi máy) | /extend {u_esc} 30d (Gia hạn)",
            f"/setpass {u_esc} (Đổi pass) | /del {u_esc} (Xóa)"
        ]
    )

def format_devices(username: str) -> str:
    username = validate_username(username)
    user = store.get_user(username)
    if user is None:
        raise ValueError(f"không tìm thấy tài khoản: {username}")
    devices = store.list_devices(username)
    if not devices:
        return (f"<code>{escape(username)}</code>: Bật: 0/{user['max_devices']} | Tắt: 0 | Tổng: 0\n"
                "chưa ghi nhận thiết bị nào đăng nhập")
    enabled = sum(int(device.get("enabled", 1)) == 1 for device in devices)
    lines = [f"<b>📱 Thiết bị của {escape(username)}</b>",
             f"Bật: {enabled}/{user['max_devices']} | Tắt: {len(devices) - enabled} | Tổng: {len(devices)}",
             "━━━━━━━━━━━━━━━━━━━━━━"]
    shown = 0
    for index, device in enumerate(devices[:50], 1):
        device_id = str(device["device_id"])
        entry = (
            f"{index}. {'🟢 BẬT' if int(device.get('enabled', 1)) == 1 else '🔴 TẮT'} "
            f"<b>{escape(str(device.get('device_name') or 'iPhone')[:64])}</b>\n"
            f"   HWID: <code>{escape(device_id[:128])}</code>\n"
            f"   Online lúc: {format_epoch(int(device['last_seen']))}"
        )
        if sum(len(line) + 1 for line in lines) + len(entry) > 3650:
            break
        lines.append(entry)
        shown += 1
    if len(devices) > shown:
        lines.append(f"... còn {len(devices) - shown} thiết bị chưa hiển thị.")
    return "\n".join(lines)

def format_users(page: int) -> str:
    users = store.list_users(10_000)
    page_size = 10
    pages = max(1, (len(users) + page_size - 1) // page_size)
    if page < 1 or page > pages:
        raise ValueError(f"trang phải từ 1 đến {pages}")
    start = (page - 1) * page_size
    lines = [f"<b>👥 Danh sách tài khoản: {len(users)} | trang {page}/{pages}</b>", "━━━━━━━━━━━━━━━━━━━━━━"]
    lines.extend(user_line(user) for user in users[start : start + page_size])
    if pages > 1:
        lines.append(f"\nDùng /users {min(page + 1, pages)} để xem trang tiếp theo.")
    return "\n".join(lines)

def format_expired() -> str:
    users = store.list_expired_users(100)
    if not users:
        return "✅ Không có tài khoản nào hết hạn."
    lines = [f"<b>⌛ Tài khoản hết hạn: {len(users)}</b>", "━━━━━━━━━━━━━━━━━━━━━━"]
    lines.extend(f"• <code>{escape(user['username'])}</code> | hết hạn: {format_epoch(int(user['expires_at']))}" for user in users[:80])
    if len(users) > 80:
        lines.append(f"... và {len(users) - 80} tài khoản khác")
    lines.append("\nDùng <code>/delexpired</code> để xóa sạch tài khoản hết hạn.")
    return "\n".join(lines)

def format_status() -> str:
    users = store.list_users(10_000)
    enabled = sum(int(user["enabled"]) == 1 for user in users)
    expired = sum(int(user["expires_at"]) <= store.now() for user in users)
    with store.connect() as con:
        total_devices = con.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        active_sessions = con.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", (store.now(),)).fetchone()[0]

    disk_str = "N/A"
    try:
        total_b, used_b, free_b = shutil.disk_usage("/")
        disk_str = f"{used_b // (1024**3)}GB / {total_b // (1024**3)}GB ({int(used_b * 100 / total_b)}%)"
    except Exception:
        pass

    mem_str = "N/A"
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()
            mem_total = int([l for l in lines if "MemTotal:" in l][0].split()[1]) // 1024
            mem_avail = int([l for l in lines if "MemAvailable:" in l][0].split()[1]) // 1024
            mem_used = mem_total - mem_avail
            mem_str = f"{mem_used}MB / {mem_total}MB ({int(mem_used * 100 / mem_total)}%)"
        except Exception:
            pass

    load_str = "N/A"
    if os.path.exists("/proc/loadavg"):
        try:
            with open("/proc/loadavg", "r") as f:
                load_str = ", ".join(f.read().split()[:3])
        except Exception:
            pass

    return (
        "<b>📊 BÁO CÁO HỆ THỐNG VC.HUXA.XYZ</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "🖥 <b>MÁY CHỦ VPS:</b>\n"
        f"• CPU Load: <code>{load_str}</code>\n"
        f"• RAM: <code>{mem_str}</code>\n"
        f"• Ổ đĩa: <code>{disk_str}</code>\n\n"
        "👥 <b>TÀI KHOẢN & PHIÊN HOẠT ĐỘNG:</b>\n"
        f"• Tổng tài khoản: <b>{len(users)}</b> (Bật: <b>{enabled}</b> | Hết hạn: <b>{expired}</b>)\n"
        f"• Thiết bị đã gán: <b>{total_devices}</b> máy\n"
        f"• Phiên active: <b>{active_sessions}</b>\n"
        f"• Thời gian hệ thống: {format_epoch(store.now())}\n"
        "━━━━━━━━━━━━━━━━━━━━━━"
    )

def request_confirmation(actor: str, action: str, payload: dict[str, Any], description: str) -> ConfirmationReply:
    code = store.create_confirmation(actor, action, payload, ttl=CONFIRM_TTL)
    return ConfirmationReply(
        f"⚠️ <b>{escape(description)}</b>\nKiểm tra kỹ rồi chọn Xác nhận hoặc Hủy trong {CONFIRM_TTL} giây.",
        code,
    )

def execute_confirmation(actor: str, role: str, code: str) -> str:
    require_role(role, "owner")
    action, payload = store.consume_confirmation(actor, code)
    username = str(payload.get("username") or "")
    if action == "user_delete":
        require_role(role, "owner")
        store.delete_user(username, actor=actor)
        return f"✅ Đã xóa vĩnh viễn tài khoản: <code>{escape(username)}</code>"
    if action == "devices_reset":
        require_role(role, "owner")
        deleted = store.reset_devices(username, actor=actor)
        # Re-read committed state; never repeat counts retained by a wizard or
        # confirmation created before concurrent logins/admin changes.
        user = store.get_user(username)
        if user is None:
            return f"✅ Đã xóa {deleted} liên kết cũ; tài khoản hiện không còn tồn tại."
        return (f"✅ Đã mở khóa đổi máy cho <code>{escape(user['username'])}</code> "
                f"(xóa {deleted} thiết bị cũ).\n"
                f"Hiện tại: {user['active_devices']}/{user['max_devices']} máy bật; "
                f"tổng {user.get('total_devices', user['active_devices'])}.\n"
                f"Ngày hết hạn giữ nguyên: {format_epoch(int(user['expires_at']))}.")
    if action == "device_unbind":
        require_role(role, "operator")
        device_id = str(payload["device_id"])
        if not store.remove_device(username, device_id, actor=actor):
            raise ValueError("thiết bị đã được gỡ trước đó")
        return f"✅ Đã gỡ thiết bị {escape(device_id[:8])} khỏi <code>{escape(username)}</code>"
    if action == "delete_expired":
        require_role(role, "owner")
        deleted = store.delete_expired_users(actor=actor)
        return f"✅ Đã xóa {len(deleted)} tài khoản đã hết hạn."
    raise ValueError(f"thao tác xác nhận không được hỗ trợ: {action}")

def created_message(user: dict[str, Any], password: str, duration_label: str) -> str:
    u_esc = escape(user['username'])
    p_esc = escape(password)
    exp_str = format_epoch(int(user['expires_at']))
    return (
        "<b>🌟 THÔNG TIN KÍCH HOẠT VCAMPLUS VIP 🌟</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 <b>Tài khoản:</b> <code>{u_esc}</code>\n"
        f"🔑 <b>Mật khẩu:</b> <code>{p_esc}</code>\n"
        f"⏳ <b>Thời hạn:</b> {duration_label} (Hết hạn: {exp_str})\n"
        f"📱 <b>Số thiết bị:</b> {user['max_devices']} máy (Khóa phần cứng chống share)\n"
        "📦 <b>Link tải Deb:</b> https://vc.huxa.xyz/download\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "📖 <b>HƯỚNG DẪN KÍCH HOẠT:</b>\n"
        "1. Tải và cài đặt file .deb qua <b>Sileo / Zebra / Filza</b>.\n"
        "2. Mở ứng dụng <b>VCAMPLUS</b> trên iPhone.\n"
        "3. Nhập đúng <b>Tài khoản</b> và <b>Mật khẩu</b> ở trên ➔ Bấm <b>Sign In</b>.\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "💬 <b>Hỗ trợ kỹ thuật:</b> @vcamplus\n"
        "<i>(Chạm vào tài khoản hoặc mật khẩu để sao chép nhanh)</i>"
    )

def handle_command(text: str, actor: str, role: str, chat_id: int = 0) -> str:
    parts = text.strip().split()
    if not parts:
        return HELP
    command = parts[0].split("@", 1)[0].lower()
    aliases = {
        "/start": "/help",
        "/menu": "/help",
        "/list": "/users",
        "/find": "/user",
        "/extend": "/user_extend",
        "/setpass": "/user_password",
        "/clear": "/devices_reset",
        "/del": "/user_delete",
        "/resetdev": "/devices_reset",
        "/stats": "/status",
    }
    command = aliases.get(command, command)

    if command == "/help":
        return f"Quyền hiện tại: <b>{role}</b>\n\n{HELP}"

    if command == "/status":
        require_role(role, "viewer")
        return format_status()

    if command == "/backup":
        require_role(role, "owner")
        if chat_id:
            with tempfile.TemporaryDirectory(prefix="vcnext-telegram-backup-") as temporary:
                tmp_backup = Path(temporary) / "licenses_backup.db"
                store.backup_database(str(tmp_backup))
                send_document(chat_id, tmp_backup, caption=f"💾 Bản sao lưu cơ sở dữ liệu VCNext ({format_epoch(store.now())})")
                return "✅ Đã tạo snapshot WAL nhất quán và gửi file backup về chat."
        return "💾 Không tìm thấy database."

    if command == "/users":
        require_role(role, "viewer")
        page = parse_positive(parts[1], "trang", 10_000) if len(parts) == 2 else 1
        if len(parts) > 2:
            raise ValueError("cú pháp: /users [trang]")
        return format_users(page)

    if command == "/user":
        require_role(role, "viewer")
        if len(parts) != 2:
            raise ValueError("cú pháp: /find <username>")
        return format_user(parts[1])

    if command == "/devices":
        require_role(role, "viewer")
        if len(parts) != 2:
            raise ValueError("cú pháp: /devices <username>")
        return format_devices(parts[1])

    if command in {"/add", "/user_create"}:
        require_role(role, "operator")
        if command == "/add" and len(parts) != 5:
            raise ValueError("cú pháp: /add <username> <mật_khẩu> <thời_hạn> <số_máy>; ví dụ: /add usertest 1 30 1")
        if command == "/user_create" and len(parts) not in {3, 4}:
            raise ValueError("cú pháp: /user_create <username> <5h|30d> [số_máy]")
        username = validate_username(parts[1])
        if store.get_user(username) is not None:
            raise ValueError("tài khoản đã tồn tại; dùng /extend hoặc /setpass")
        if command == "/add":
            password = validate_password(parts[2])
            seconds, label = parse_duration(parts[3])
            max_devices = parse_positive(parts[4], "số máy", 1000)
        else:
            seconds, label = parse_duration(parts[2])
            max_devices = parse_positive(parts[3], "số máy", 1000) if len(parts) == 4 else 1
            password = generated_password()
        user = store.create_user(
            username,
            password,
            30,
            max_devices,
            actor=actor,
            duration_seconds=seconds,
        )
        return created_message(user, password, label)

    if command == "/user_extend":
        require_role(role, "operator")
        if len(parts) != 3:
            raise ValueError("cú pháp: /extend <username> <5h|30d>")
        username = validate_username(parts[1])
        seconds, label = parse_duration(parts[2])
        user = store.extend_user_seconds(username, seconds, actor)
        return f"✅ Đã gia hạn <code>{escape(user['username'])}</code> thêm {label}.\nCòn lại: {remaining_text(user)}"

    if command == "/user_password":
        require_role(role, "operator")
        if len(parts) not in {2, 3}:
            raise ValueError("cú pháp: /setpass <username> [mật_khẩu_mới]")
        username = validate_username(parts[1])
        password = validate_password(parts[2]) if len(parts) == 3 else generated_password()
        store.set_user_password(username, password, actor)
        return (
            f"✅ Đã đổi mật khẩu cho <code>{escape(username)}</code> và thu hồi phiên cũ.\n"
            f"Mật khẩu mới: <code>{escape(password)}</code>\n<i>(Chạm để sao chép)</i>"
        )

    if command == "/devices_reset":
        require_role(role, "owner")
        if len(parts) != 2:
            raise ValueError("cú pháp: /clear <username>")
        username = validate_username(parts[1])
        if store.get_user(username) is None:
            raise ValueError(f"không tìm thấy tài khoản: {username}")
        return request_confirmation(
            actor,
            "devices_reset",
            {"username": username},
            f"Mở khóa đổi máy và thu hồi session của {username}?",
        )

    if command == "/user_delete":
        require_role(role, "owner")
        if len(parts) != 2:
            raise ValueError("cú pháp: /del <username>")
        username = validate_username(parts[1])
        if store.get_user(username) is None:
            raise ValueError(f"không tìm thấy tài khoản: {username}")
        return request_confirmation(
            actor, "user_delete", {"username": username}, f"Xóa vĩnh viễn tài khoản {username}?"
        )

    if command == "/expired":
        require_role(role, "viewer")
        return format_expired()

    if command == "/delexpired":
        require_role(role, "owner")
        expired = store.list_expired_users(1000)
        if not expired:
            return "Không có tài khoản hết hạn để xóa."
        return request_confirmation(
            actor,
            "delete_expired",
            {},
            f"Xóa {len(expired)} tài khoản đã hết hạn?",
        )

    if command == "/confirm":
        if len(parts) != 2:
            raise ValueError("cú pháp: /confirm <mã>")
        return execute_confirmation(actor, role, parts[1])

    return "Không nhận ra lệnh. Dùng /help hoặc chọn menu."

def wizard_key(actor: str) -> str:
    return f"telegram_wizard:{actor.split(':', 2)[1]}"

def set_wizard(actor: str, flow: str, stage: str, data: dict[str, Any] | None = None) -> None:
    store.set_bot_state(
        wizard_key(actor),
        json.dumps(
            {
                "flow": flow,
                "stage": stage,
                "data": data or {},
                "expires_at": store.now() + WIZARD_TTL,
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

def get_wizard(actor: str) -> dict[str, Any] | None:
    raw = store.get_bot_state(wizard_key(actor), "")
    if not raw:
        return None
    try:
        state = json.loads(raw)
    except json.JSONDecodeError:
        store.delete_bot_state(wizard_key(actor))
        return None
    if int(state.get("expires_at", 0)) <= store.now():
        store.delete_bot_state(wizard_key(actor))
        return None
    return state

def clear_wizard(actor: str) -> None:
    store.delete_bot_state(wizard_key(actor))

def start_wizard(flow: str, actor: str, role: str) -> MessageReply:
    required = "viewer" if flow in {"find", "devices"} else "operator"
    if flow in {"reset", "delete"}:
        required = "owner"
    require_role(role, required)
    set_wizard(actor, flow, "username")
    prompts = {
        "create": "Nhập username mới:",
        "find": "Nhập username cần tìm:",
        "devices": "Nhập username cần xem thiết bị:",
        "extend": "Nhập username cần gia hạn:",
        "password": "Nhập username cần đổi mật khẩu:",
        "reset": "Nhập username cần mở khóa đổi máy:",
        "delete": "Nhập username cần xóa:",
    }
    return MessageReply(prompts[flow], CANCEL_KEYBOARD)

def finish_create(actor: str, data: dict[str, Any], password: str) -> str:
    user = store.create_user(
        str(data["username"]),
        password,
        30,
        int(data["max_devices"]),
        actor=actor,
        duration_seconds=int(data["duration_seconds"]),
    )
    return created_message(user, password, str(data["duration_label"]))

def handle_wizard(text: str, actor: str, role: str) -> MessageReply:
    if text == BTN_CANCEL:
        clear_wizard(actor)
        return MessageReply("Đã hủy thao tác.", MAIN_KEYBOARD)
    state = get_wizard(actor)
    if state is None:
        return MessageReply("Phiên nhập liệu đã hết hạn. Chọn lại chức năng.", MAIN_KEYBOARD)
    flow = str(state["flow"])
    stage = str(state["stage"])
    data = dict(state.get("data") or {})
    required_roles = {"find": "viewer", "devices": "viewer", "create": "operator",
                      "extend": "operator", "password": "operator",
                      "reset": "owner", "delete": "owner"}
    if flow not in required_roles:
        clear_wizard(actor)
        raise ValueError("trạng thái nhập liệu không hợp lệ")
    # A persisted wizard must not preserve privileges after a role is revoked.
    try:
        require_role(role, required_roles[flow])
    except PermissionError:
        clear_wizard(actor)
        raise

    if stage == "username":
        username = validate_username(text)
        user = store.get_user(username)
        if flow == "create":
            require_role(role, "operator")
            if user is not None:
                raise ValueError("tài khoản đã tồn tại")
            data["username"] = username
            set_wizard(actor, flow, "duration", data)
            return MessageReply("Chọn thời hạn hoặc nhập 5h, 7d, 30d:", DURATION_KEYBOARD)
        if user is None:
            raise ValueError(f"không tìm thấy tài khoản: {username}")
        if flow == "find":
            clear_wizard(actor)
            return MessageReply(format_user(username), MAIN_KEYBOARD, parse_mode="HTML")
        if flow == "devices":
            clear_wizard(actor)
            return MessageReply(format_devices(username), MAIN_KEYBOARD, parse_mode="HTML")
        if flow == "extend":
            require_role(role, "operator")
            data["username"] = username
            set_wizard(actor, flow, "duration", data)
            return MessageReply("Chọn thời gian gia hạn hoặc nhập 5h, 7d, 30d:", DURATION_KEYBOARD)
        if flow == "password":
            require_role(role, "operator")
            data["username"] = username
            set_wizard(actor, flow, "password_mode", data)
            return MessageReply("Chọn cách đặt mật khẩu:", PASSWORD_KEYBOARD)
        if flow == "reset":
            require_role(role, "owner")
            clear_wizard(actor)
            reply = request_confirmation(
                actor,
                "devices_reset",
                {"username": username},
                f"Mở khóa đổi máy và thu hồi session của {username}?",
            )
            return MessageReply(str(reply), confirmation_markup(reply.code), parse_mode="HTML")
        if flow == "delete":
            require_role(role, "owner")
            clear_wizard(actor)
            reply = request_confirmation(
                actor, "user_delete", {"username": username}, f"Xóa vĩnh viễn tài khoản {username}?"
            )
            return MessageReply(str(reply), confirmation_markup(reply.code), parse_mode="HTML")

    if stage == "duration":
        seconds, label = parse_duration(text)
        if flow == "extend":
            user = store.extend_user_seconds(str(data["username"]), seconds, actor)
            clear_wizard(actor)
            return MessageReply(
                f"✅ Đã gia hạn <code>{escape(user['username'])}</code> thêm {label}.\nCòn lại: {remaining_text(user)}",
                MAIN_KEYBOARD,
                parse_mode="HTML",
            )
        data["duration_seconds"] = seconds
        data["duration_label"] = label
        set_wizard(actor, flow, "max_devices", data)
        return MessageReply("Chọn số thiết bị tối đa hoặc nhập một số:", DEVICE_KEYBOARD)

    if stage == "max_devices":
        normalized = text.lower().replace("máy", "").strip()
        data["max_devices"] = parse_positive(normalized, "số máy", 1000)
        set_wizard(actor, flow, "password_mode", data)
        return MessageReply("Chọn cách tạo mật khẩu:", PASSWORD_KEYBOARD)

    if stage == "password_mode":
        if text == BTN_RANDOM:
            password = generated_password()
            if flow == "create":
                result = finish_create(actor, data, password)
            else:
                store.set_user_password(str(data["username"]), password, actor)
                result = (
                    f"✅ Đã đổi mật khẩu cho <code>{escape(data['username'])}</code> và thu hồi session cũ.\n"
                    f"Mật khẩu mới: <code>{escape(password)}</code>\n<i>(Chạm để sao chép)</i>"
                )
            clear_wizard(actor)
            return MessageReply(result, MAIN_KEYBOARD, parse_mode="HTML")
        if text == BTN_MANUAL:
            set_wizard(actor, flow, "password_manual", data)
            return MessageReply(
                "Nhập mật khẩu mới từ 1 đến 128 ký tự. Bot sẽ xóa tin nhắn bạn vừa nhập sau khi xử lý.",
                CANCEL_KEYBOARD,
            )
        raise ValueError("hãy chọn Tự tạo hoặc Tự nhập")

    if stage == "password_manual":
        password = validate_password(text)
        if flow == "create":
            result = finish_create(actor, data, password)
        else:
            store.set_user_password(str(data["username"]), password, actor)
            result = (
                f"✅ Đã đổi mật khẩu cho <code>{escape(data['username'])}</code> và thu hồi session cũ.\n"
                f"Mật khẩu mới: <code>{escape(password)}</code>\n<i>(Chạm để sao chép)</i>"
            )
        clear_wizard(actor)
        return MessageReply(result, MAIN_KEYBOARD, delete_source=True, parse_mode="HTML")

    clear_wizard(actor)
    raise ValueError("trạng thái nhập liệu không hợp lệ; hãy chọn lại chức năng")

def message_reply(value: str) -> MessageReply:
    if isinstance(value, ConfirmationReply):
        return MessageReply(str(value), confirmation_markup(value.code), parse_mode="HTML")
    return MessageReply(str(value), MAIN_KEYBOARD, parse_mode="HTML")

def handle_text(text: str, actor: str, role: str, chat_id: int = 0) -> MessageReply:
    menu_commands = {
        BTN_USERS: "/users",
        BTN_EXPIRED: "/expired",
        BTN_STATUS: "/status",
        BTN_BACKUP: "/backup",
        BTN_HELP: "/help",
    }
    wizard_flows = {
        BTN_CREATE: "create",
        BTN_FIND: "find",
        BTN_DEVICES: "devices",
        BTN_EXTEND: "extend",
        BTN_PASSWORD: "password",
        BTN_RESET: "reset",
        BTN_DELETE: "delete",
    }
    if text in menu_commands:
        clear_wizard(actor)
        return message_reply(handle_command(menu_commands[text], actor, role, chat_id=chat_id))
    if text in wizard_flows:
        clear_wizard(actor)
        return start_wizard(wizard_flows[text], actor, role)
    if get_wizard(actor) is not None or text == BTN_CANCEL:
        return handle_wizard(text, actor, role)
    return MessageReply("Chọn một chức năng trong menu hoặc dùng /help.", MAIN_KEYBOARD)

def get_updates(offset: int | None) -> list[dict[str, Any]]:
    payload: dict[str, Any] = {
        "timeout": API_TIMEOUT,
        "allowed_updates": json.dumps(["message", "callback_query"]),
    }
    if offset is not None:
        payload["offset"] = offset
    return list(request_json("getUpdates", payload).get("result", []))

def acquire_lock() -> None:
    global LOCK_HANDLE
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_HANDLE = LOCK_PATH.open("a+", encoding="ascii")
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(LOCK_HANDLE.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(LOCK_HANDLE.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise RuntimeError(f"Một phiên Telegram bot khác đang chạy: {LOCK_PATH}") from exc
    LOCK_HANDLE.seek(0)
    LOCK_HANDLE.truncate()
    LOCK_HANDLE.write(str(os.getpid()))
    LOCK_HANDLE.flush()

def stop_signal(_signum: int, _frame: Any) -> None:
    global STOP
    STOP = True

def configure_commands() -> None:
    commands = [
        {"command": "add", "description": "Tạo tài khoản"},
        {"command": "find", "description": "Tìm tài khoản"},
        {"command": "extend", "description": "Gia hạn tài khoản"},
        {"command": "setpass", "description": "Đổi mật khẩu"},
        {"command": "clear", "description": "Mở khóa đổi máy"},
        {"command": "users", "description": "Danh sách tài khoản"},
        {"command": "status", "description": "Trạng thái hệ thống"},
        {"command": "backup", "description": "Tải file backup database"},
        {"command": "help", "description": "Menu và trợ giúp"},
    ]
    try:
        request_json("setMyCommands", {"commands": json.dumps(commands, ensure_ascii=False)})
    except Exception:
        pass

def reject_update(kind: str, user_id: int, chat_id: int) -> None:
    try:
        store.audit("telegram_unauthorized", str(user_id),
                    {"chat_id": chat_id, "kind": kind}, "telegram")
    except Exception:
        print("Telegram authorization rejection could not be audited", file=sys.stderr)

def process_callback(callback: dict[str, Any]) -> None:
    callback_id = str(callback.get("id") or "")
    sender = callback.get("from") or {}
    user_id = int(sender.get("id", 0))
    role = role_for(user_id)
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = int(chat.get("id", 0))
    if (role is None or user_id != OWNER_ID or chat_id != OWNER_ID
            or str(chat.get("type") or "") != "private"):
        reject_update("callback", user_id, chat_id)
        return
    actor = f"telegram:{user_id}:{role}"
    data = str(callback.get("data") or "")
    action, _, code = data.partition(":")
    try:
        if action == "confirm" and code:
            result = execute_confirmation(actor, role, code)
            answer_callback(callback_id, "Đã thực hiện")
        elif action == "cancel" and code:
            if not store.cancel_confirmation(actor, code):
                raise ValueError("xác nhận không còn hiệu lực")
            result = "Đã hủy thao tác."
            answer_callback(callback_id, "Đã hủy")
        else:
            raise ValueError("nút không hợp lệ")
    except Exception as exc:
        result = f"Lỗi: {escape(str(exc))}"
        answer_callback(callback_id, "Không thể thực hiện")
    if chat_id:
        send_message(chat_id, result, MAIN_KEYBOARD, parse_mode="HTML")

def process_message(message: dict[str, Any]) -> None:
    text = str(message.get("text") or "").strip()
    if not text:
        return
    chat = message.get("chat") or {}
    chat_id = int(chat.get("id", 0))
    user_id = int((message.get("from") or {}).get("id", 0))
    role = role_for(user_id)
    if (role is None or user_id != OWNER_ID or chat_id != OWNER_ID
            or str(chat.get("type") or "") != "private"):
        reject_update("message", user_id, chat_id)
        return
    actor = f"telegram:{user_id}:{role}"
    try:
        if text.startswith("/"):
            raw = handle_command(text, actor, role, chat_id=chat_id)
            reply = message_reply(raw)
            command_parts = text.split()
            command_name = command_parts[0].split("@", 1)[0].lower()
            if (command_name == "/setpass" and len(command_parts) == 3) or (command_name == "/add" and len(command_parts) == 5):
                reply.delete_source = True
        else:
            reply = handle_text(text, actor, role, chat_id=chat_id)
    except PermissionError as exc:
        reply = MessageReply(f"Từ chối: {exc}", MAIN_KEYBOARD)
    except Exception as exc:
        reply = MessageReply(f"Lỗi: {exc}", MAIN_KEYBOARD)
    if reply.delete_source and chat_id:
        delete_message(chat_id, int(message.get("message_id", 0)))
    if chat_id:
        send_message(chat_id, reply.text, reply.markup, parse_mode=reply.parse_mode)

def main() -> int:
    if not BOT_TOKEN:
        print("TELEGRAM_BOT_TOKEN is required", file=sys.stderr)
        return 2
    acquire_lock()
    signal.signal(signal.SIGINT, stop_signal)
    signal.signal(signal.SIGTERM, stop_signal)
    identity = request_json("getMe").get("result") or {}
    bot_username = identity.get("username", "-") if isinstance(identity, dict) else "-"
    if (not isinstance(identity, dict) or identity.get("is_bot") is not True or
            str(bot_username).casefold() != EXPECTED_BOT_USERNAME.casefold()):
        print("Telegram bot identity does not match the configured production bot", file=sys.stderr)
        return 2
    configure_commands()
    stored = store.get_bot_state("telegram_update_offset", "")
    offset = int(stored) if stored.isdigit() else None
    print(
        f"[+] VCNext Telegram bot started: @{bot_username} "
        f"(Owners: {len(OWNER_IDS)})"
    )
    backoff = 2
    while not STOP:
        try:
            updates = get_updates(offset)
            for update in updates:
                next_offset = int(update["update_id"]) + 1
                try:
                    if update.get("callback_query"):
                        process_callback(update["callback_query"])
                    elif update.get("message"):
                        process_message(update["message"])
                finally:
                    offset = next_offset
                    store.set_bot_state("telegram_update_offset", str(offset))
            backoff = 2
        except (urllib.error.URLError, TimeoutError, RuntimeError):
            print("Telegram polling failed; retrying with bounded backoff", file=sys.stderr)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
    print("VCNext Telegram bot stopped")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
