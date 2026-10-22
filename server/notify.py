"""Bounded, asynchronous login alerts for the production VCNext owner.

Public calls only enqueue an alert. Telegram I/O is confined to one daemon worker;
accepted alerts remain best effort (the in-memory queue is not a durable outbox).
The only credential source is TELEGRAM_BOT_TOKEN. No store import or database I/O.
"""
from __future__ import annotations

import atexit
import html
import json
import logging
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

OWNER_ID = 5137016124
OWNER_IDS = {OWNER_ID}
EXPECTED_BOT_USERNAME = "VCAM_V5_ADMIN_BOT"
QUEUE_CAPACITY = 256
REQUEST_TIMEOUT = 3.0
MAX_ATTEMPTS = 3
LOG = logging.getLogger(__name__)
try:
    LOCAL_TIMEZONE = ZoneInfo("Asia/Ho_Chi_Minh")
except ZoneInfoNotFoundError:
    # This timezone has no daylight saving time; also works without host tzdata.
    LOCAL_TIMEZONE = timezone(timedelta(hours=7), "Asia/Ho_Chi_Minh")

ERROR_LABELS = {
    "missing_username": "Chưa nhập tài khoản",
    "invalid_request": "Yêu cầu không hợp lệ",
    "user_not_found": "Tài khoản chưa đăng ký",
    "wrong_password": "Sai mật khẩu",
    "account_disabled": "Tài khoản bị khóa",
    "account_expired": "Tài khoản hết hạn",
    "device_disabled": "Thiết bị bị khóa",
    "device_bound_to_other_user": "Thiết bị thuộc tài khoản khác",
    "device_limit_reached": "Đã đủ số thiết bị",
    "device_proof_failed": "Chữ ký thiết bị không hợp lệ",
    "invalid_challenge": "Thử thách không hợp lệ hoặc đã sử dụng",
    "challenge_invalid": "Thử thách không hợp lệ hoặc đã sử dụng",
    "invalid_device_key": "Khóa thiết bị không hợp lệ",
    "device_key_mismatch": "Khóa thiết bị không khớp",
    "device_proof_invalid": "Chữ ký thiết bị không hợp lệ",
    "nonce_mismatch": "Mã thử thách không khớp",
    "unsupported_client": "Phiên bản ứng dụng không được hỗ trợ",
    "server_busy": "Máy chủ đang bận",
    "device_rejected": "Thiết bị bị từ chối",
}
_TOKEN_PATTERN = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b")


def _esc(value: Any, limit: int = 160) -> str:
    text = str(value or "-")
    text = _TOKEN_PATTERN.sub("[redacted]", text)
    text = text.encode("utf-8", "replace").decode("utf-8")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    text = " ".join(text.split())[:limit]
    return html.escape(text, quote=True)


def _message(success: bool, username: str, device_id: str, ip: str,
             device_name: str = "", reason: str = "") -> str:
    title = "🟢 ĐĂNG NHẬP THÀNH CÔNG" if success else "🔴 ĐĂNG NHẬP BỊ TỪ CHỐI"
    lines = [f"<b>{title}</b>", "<b>VCAMPLUS · vc.huxa.xyz</b>",
             f"👤 Tài khoản: <code>{_esc(username, 64)}</code>",
             f"📱 Tên máy: <code>{_esc(device_name)}</code>",
             f"🆔 HWID: <code>{_esc(device_id)}</code>",
             f"🌐 IP: <code>{_esc(ip, 80)}</code>"]
    if not success:
        # Only stable, non-secret codes are permitted. Never relay exceptions,
        # passwords, request bodies or arbitrary failure strings to Telegram.
        label = ERROR_LABELS.get(str(reason).lower(), "Đăng nhập không hợp lệ")
        lines.append(f"⚠️ Lý do: <b>{html.escape(label)}</b>")
    stamp = datetime.now(LOCAL_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S %z")
    lines.append(f"🕒 <code>{stamp}</code> (Asia/Ho_Chi_Minh)")
    return "\n".join(lines)


class DeliveryError(Exception):
    """Only sanitized classification is logged; never include Telegram URLs."""
    def __init__(self, retryable: bool = True, retry_after: float = 0.0,
                 disable: bool = False):
        super().__init__("telegram delivery failed")
        self.retryable = retryable
        self.retry_after = min(max(float(retry_after), 0.0), 2.0)
        self.disable = disable


Transport = Callable[[str, dict[str, Any], str, float], dict[str, Any]]


def _transport(method: str, payload: dict[str, Any], token: str,
               timeout: float) -> dict[str, Any]:
    """Called by the worker only. The URL and exception text are never logged."""
    data = urllib.parse.urlencode(payload).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(65_537)
        if len(raw) > 65_536:
            raise DeliveryError(False)
        parsed = json.loads(raw)
    except urllib.error.HTTPError as exc:
        retry_after = 0.0
        if exc.code == 429:
            try:
                details = json.loads(exc.read(4096))
                retry_after = float(details.get("parameters", {}).get("retry_after", 0))
            except Exception:
                pass
        raise DeliveryError(exc.code == 429 or exc.code >= 500, retry_after,
                            exc.code in {401, 403}) from None
    except DeliveryError:
        raise
    except Exception:
        raise DeliveryError() from None
    if not isinstance(parsed, dict):
        raise DeliveryError(False)
    return parsed


class _Dispatcher:
    def __init__(self, token: str, transport: Transport = _transport,
                 capacity: int = QUEUE_CAPACITY, attempts: int = MAX_ATTEMPTS,
                 timeout: float = REQUEST_TIMEOUT):
        self.token = token
        self.transport = transport
        self.attempts = max(1, min(attempts, MAX_ATTEMPTS))
        self.timeout = max(0.01, min(timeout, REQUEST_TIMEOUT))
        self.queue: queue.Queue[str] = queue.Queue(maxsize=max(1, capacity))
        self.admission_lock = threading.Lock()
        self.stop = threading.Event()
        self.disabled = False
        self.verified_identity = False
        self.worker = threading.Thread(target=self._run, name="vcnext-login-alerts", daemon=True)
        self.worker.start()

    def enqueue(self, text: str) -> bool:
        with self.admission_lock:
            if self.disabled or self.stop.is_set():
                LOG.error("Telegram login alert not accepted: delivery disabled")
                return False
            try:
                self.queue.put_nowait(text)
                return True
            except queue.Full:
                LOG.error("Telegram login alert not accepted: queue full")
                return False

    def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        result = self.transport(method, payload, self.token, self.timeout)
        if not isinstance(result, dict) or result.get("ok") is not True:
            code = result.get("error_code", 0) if isinstance(result, dict) else 0
            parameters = result.get("parameters", {}) if isinstance(result, dict) else {}
            retry_after = parameters.get("retry_after", 0) if isinstance(parameters, dict) else 0
            raise DeliveryError(code == 429 or (isinstance(code, int) and code >= 500),
                                retry_after, code in {401, 403})
        return result

    def _deliver(self, text: str) -> None:
        for attempt in range(self.attempts):
            if self.stop.is_set():
                return
            try:
                if not self.verified_identity:
                    identity = self._call("getMe", {}).get("result") or {}
                    if (not isinstance(identity, dict) or identity.get("is_bot") is not True
                            or str(identity.get("username", "")).casefold()
                            != EXPECTED_BOT_USERNAME.casefold()):
                        raise DeliveryError(False, disable=True)
                    self.verified_identity = True
                self._call("sendMessage", {"chat_id": OWNER_ID, "text": text,
                                          "parse_mode": "HTML",
                                          "disable_web_page_preview": "true"})
                return
            except Exception as exc:
                error = exc if isinstance(exc, DeliveryError) else DeliveryError()
                if error.disable:
                    self.disabled = True
                    LOG.error("Telegram login alerts disabled: credential, owner access or bot identity rejected")
                if not error.retryable or attempt + 1 >= self.attempts:
                    LOG.error("Telegram login alert delivery failed after bounded attempts")
                    return
                if self.stop.wait(max(error.retry_after, min(0.25 * (2 ** attempt), 2.0))):
                    return

    def _run(self) -> None:
        while not self.stop.is_set():
            try:
                text = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if not self.disabled:
                    self._deliver(text)
                else:
                    LOG.error("Telegram login alert dropped: delivery disabled")
            finally:
                self.queue.task_done()
        # Mark discarded queued work complete so bounded flush never hangs.
        while True:
            try:
                self.queue.get_nowait()
            except queue.Empty:
                break
            else:
                self.queue.task_done()
                LOG.error("Telegram login alert dropped: worker shutdown")

    def flush(self, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self.queue.all_tasks_done:
            while self.queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.queue.all_tasks_done.wait(remaining)
        return True

    def shutdown(self, timeout: float = 0.5) -> bool:
        with self.admission_lock:
            self.stop.set()
        self.worker.join(max(0.0, min(timeout, 5.0)))
        return not self.worker.is_alive()


_dispatcher: _Dispatcher | None = None
_dispatcher_lock = threading.Lock()


def _enqueue(text: str) -> bool:
    global _dispatcher
    try:
        with _dispatcher_lock:
            if _dispatcher is None:
                token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
                if not token:
                    LOG.error("Telegram login alert not accepted: TELEGRAM_BOT_TOKEN missing")
                    return False
                _dispatcher = _Dispatcher(token, transport=_transport)
            dispatcher = _dispatcher
        return dispatcher.enqueue(text)
    except Exception:
        LOG.error("Telegram login alert not accepted: worker unavailable")
        return False


def notify_login_success(username: str, device_id: str, ip: str,
                         device_name: str = "") -> bool:
    return _enqueue(_message(True, username, device_id, ip, device_name))


def notify_login_fail(username: str, device_id: str, ip: str, reason: str,
                      device_name: str = "") -> bool:
    return _enqueue(_message(False, username, device_id, ip, device_name, reason))


def flush(timeout: float = 2.0) -> bool:
    """Wait for attempted delivery only; True is not a delivery receipt."""
    dispatcher = _dispatcher
    return dispatcher.flush(timeout) if dispatcher is not None else True


def shutdown(timeout: float = 0.5) -> bool:
    dispatcher = _dispatcher
    return dispatcher.shutdown(timeout) if dispatcher is not None else True


atexit.register(shutdown)
