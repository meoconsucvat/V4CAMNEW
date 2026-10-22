#!/usr/bin/env python3
"""
VCNext Commercial Licensing Authority Admin CLI
Công cụ quản trị giấy phép thương mại, tạo khóa bản quyền, khóa HWID, gia hạn và thu hồi.
"""

import sys
import os
import sqlite3
import time
import uuid
import secrets

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.db")
if not os.path.exists(DB_PATH):
    if os.path.exists("/opt/vcnext_server/licenses.db"):
        DB_PATH = "/opt/vcnext_server/licenses.db"

def get_connection():
    return sqlite3.connect(DB_PATH, timeout=10.0)

PLAN_DAYS = {
    "1d": 1,
    "trial": 1,
    "7d": 7,
    "week": 7,
    "30d": 30,
    "month": 30,
    "90d": 90,
    "3m": 90,
    "365d": 365,
    "year": 365,
    "life": 3650,
    "lifetime": 3650
}

def generate_key_string(plan_tag: str) -> str:
    # Format: VCN-30D-A8F2-9C1E-7D4B
    tag = plan_tag.upper()
    part1 = secrets.token_hex(2).upper()
    part2 = secrets.token_hex(2).upper()
    part3 = secrets.token_hex(2).upper()
    return f"VCN-{tag}-{part1}-{part2}-{part3}"

def cmd_gen(plan: str, customer_name: str = "Customer", count: int = 1):
    plan_clean = plan.lower()
    if plan_clean not in PLAN_DAYS:
        print(f"[-] Gói cước không hợp lệ: '{plan}'. Các gói hỗ trợ: 1d, 7d, 30d, 90d, 365d, lifetime")
        return

    days = PLAN_DAYS[plan_clean]
    tag = "1D" if days == 1 else "7D" if days == 7 else "30D" if days == 30 else "90D" if days == 90 else "365D" if days == 365 else "LIFE"

    conn = get_connection()
    cur = conn.cursor()
    now = int(time.time())

    created_keys = []
    for _ in range(count):
        key = generate_key_string(tag)
        cur.execute("""
        INSERT INTO licenses (license_key, customer_name, plan_type, duration_days, bound_device_id, device_name, status, activated_at, expires_at, created_at)
        VALUES (?, ?, ?, ?, NULL, NULL, 'active', 0, 0, ?)
        """, (key, customer_name, plan_clean, days, now))
        created_keys.append(key)

    conn.commit()
    conn.close()

    print(f"\n[+] ĐÃ TẠO THÀNH CÔNG {len(created_keys)} MÃ GIẤY PHÉP ({tag} - {days} NGÀY):")
    print("-" * 65)
    for k in created_keys:
        print(f"  Key: {k:<30} | Khách: {customer_name}")
    print("-" * 65)
    print("  (*) Hướng dẫn: Khách hàng nhập mã Key này vào ô 'Account' / 'Username' trong VCNext App để kích hoạt.\n")

def cmd_licenses():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT license_key, customer_name, plan_type, duration_days, bound_device_id, device_name, status, activated_at, expires_at
    FROM licenses
    ORDER BY created_at DESC
    """)
    rows = cur.fetchall()
    conn.close()

    print(f"\n{'='*115}")
    print(f"{'DANH SÁCH GIẤY PHÉP THƯƠNG MẠI (LICENSES)':^115}")
    print(f"{'='*115}")
    if not rows:
        print("  (Chưa có mã giấy phép nào)")
        return

    print(f"{'License Key':<26} | {'Khách hàng':<15} | {'Gói':<8} | {'Trạng thái':<10} | {'Thiết bị đã khóa':<24} | {'Hạn dùng'}")
    print(f"{'-'*26}-+-{'-'*15}-+-{'-'*8}-+-{'-'*10}-+-{'-'*24}-+-{'-'*20}")
    now = int(time.time())
    for key, cust, plan, days, hwid, dname, status, act_at, exp_at in rows:
        cust_str = (cust or "N/A")[:15]
        hwid_str = (hwid[:12] + "..." if hwid else "Chưa kích hoạt")
        if status != "active":
            st_str = f"[{status.upper()}]"
        elif act_at == 0:
            st_str = "SẴN SÀNG"
        elif exp_at < now:
            st_str = "[HẾT HẠN]"
        else:
            st_str = "HOẠT ĐỘNG"

        if exp_at == 0:
            exp_str = f"{days} ngày sau KH"
        else:
            exp_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(exp_at))

        print(f"{key:<26} | {cust_str:<15} | {plan:<8} | {st_str:<10} | {hwid_str:<24} | {exp_str}")
    print(f"{'='*115}\n")

def cmd_sessions():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT device_id, license_key, username, expires_at, created_at
    FROM sessions
    ORDER BY created_at DESC
    """)
    rows = cur.fetchall()
    conn.close()

    print(f"\n{'='*95}")
    print(f"{'PHIÊN ĐANG KẾT NỐI (ACTIVE RUNTIME SESSIONS)':^95}")
    print(f"{'='*95}")
    if not rows:
        print("  (Không có thiết bị nào đang giữ phiên)")
        return

    print(f"{'Device ID (HWID)':<38} | {'Key / User':<24} | {'Hạn phiên bản quyền'}")
    print(f"{'-'*38}-+-{'-'*24}-+-{'-'*25}")
    now = int(time.time())
    for dev_id, lkey, user, exp, cr in rows:
        key_show = (lkey or user)[:24]
        exp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp))
        status_tag = " [HẾT HẠN]" if exp < now else " [OK]"
        print(f"{dev_id:<38} | {key_show:<24} | {exp_str}{status_tag}")
    print(f"{'='*95}\n")

def cmd_revoke(identifier: str):
    conn = get_connection()
    cur = conn.cursor()
    # Thử tìm theo license_key hoặc device_id
    cur.execute("SELECT license_key, bound_device_id FROM licenses WHERE UPPER(license_key) = UPPER(?)", (identifier,))
    row = cur.fetchone()
    if row:
        lkey, hwid = row
        cur.execute("UPDATE licenses SET status = 'revoked' WHERE license_key = ?", (lkey,))
        if hwid:
            cur.execute("DELETE FROM sessions WHERE device_id = ?", (hwid,))
        cur.execute("DELETE FROM sessions WHERE license_key = ?", (lkey,))
        cur.execute("DELETE FROM challenges WHERE UPPER(username) = UPPER(?)", (lkey,))
        conn.commit()
        conn.close()
        print(f"[+] ĐÃ THU HỒI giấy phép '{lkey}' và hủy mọi phiên/thử thách liên quan.")
        return

    # Thử tìm theo device_id
    cur.execute("SELECT device_id, license_key FROM sessions WHERE device_id = ?", (identifier,))
    s_row = cur.fetchone()
    if s_row:
        dev_id, lkey = s_row
        cur.execute("DELETE FROM sessions WHERE device_id = ?", (dev_id,))
        cur.execute("DELETE FROM challenges WHERE device_id = ?", (dev_id,))
        if lkey:
            cur.execute("UPDATE licenses SET status = 'revoked' WHERE license_key = ?", (lkey,))
        conn.commit()
        conn.close()
        print(f"[+] ĐÃ HỦY PHIÊN và khóa thiết bị HWID '{dev_id}'.")
        return

    conn.close()
    print(f"[-] Không tìm thấy giấy phép hoặc thiết bị mang định danh: {identifier}")

def cmd_unbind(license_key: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT license_key, bound_device_id, activated_at, expires_at FROM licenses WHERE UPPER(license_key) = UPPER(?)", (license_key,))
    row = cur.fetchone()
    if not row:
        conn.close()
        print(f"[-] Không tìm thấy mã giấy phép: {license_key}")
        return

    lkey, old_hwid, act_at, exp_at = row
    cur.execute("UPDATE licenses SET bound_device_id = NULL, bound_thumbprint = NULL, device_name = NULL WHERE UPPER(license_key) = UPPER(?)", (lkey,))
    cur.execute("DELETE FROM sessions WHERE UPPER(license_key) = UPPER(?) OR (license_key IS NULL AND UPPER(username) = UPPER(?))", (lkey, lkey))
    cur.execute("DELETE FROM challenges WHERE UPPER(username) = UPPER(?)", (lkey,))
    conn.commit()
    conn.close()
    print(f"[+] ĐÃ MỞ KHÓA HWID (Unbound) cho giấy phép '{lkey}'.")
    if act_at > 0:
        exp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp_at))
        print(f"    (Thời hạn còn lại được bảo lưu đến: {exp_str})")

def cmd_extend(license_key: str, days: int):
    if days <= 0:
        print("[-] Số ngày gia hạn phải lớn hơn 0!")
        return
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT license_key, duration_days, activated_at, expires_at, status FROM licenses WHERE UPPER(license_key) = UPPER(?)", (license_key,))
    row = cur.fetchone()
    if not row:
        conn.close()
        print(f"[-] Không tìm thấy mã giấy phép: {license_key}")
        return

    lkey, cur_days, act_at, exp_at, st = row
    now = int(time.time())
    if act_at == 0:
        new_days = cur_days + days
        cur.execute("UPDATE licenses SET duration_days = ? WHERE license_key = ?", (new_days, lkey))
        conn.commit()
        conn.close()
        print(f"[+] Đã tăng thời lượng giấy phép chưa kích hoạt '{lkey}' lên {new_days} ngày.")
    else:
        base_time = max(exp_at, now)
        new_exp = base_time + (days * 86400)
        cur.execute("UPDATE licenses SET expires_at = ?, status = 'active' WHERE license_key = ?", (new_exp, lkey,))
        cur.execute("UPDATE sessions SET expires_at = ? WHERE license_key = ?", (new_exp, lkey,))
        conn.commit()
        conn.close()
        new_exp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(new_exp))
        print(f"[+] ĐÃ GIA HẠN THÊM {days} NGÀY cho giấy phép '{lkey}'. Hạn mới: {new_exp_str}")

def print_help():
    print("""
========================================================================
     VCNext Commercial Licensing Authority Admin CLI - Hướng dẫn
========================================================================
LỆNH QUẢN TRỊ:
  python admin_cli.py list                   - Xem các phiên thiết bị đang kết nối
  python admin_cli.py keys                   - Xem toàn bộ danh sách mã giấy phép
  python admin_cli.py gen <gói> [tên_khách]   - Tạo mã giấy phép mới
      Các gói hỗ trợ: 1d, 7d, 30d, 90d, 365d, lifetime
      Ví dụ: python admin_cli.py gen 30d "NguyenVanA"
      Ví dụ: python admin_cli.py gen lifetime "KhachVIP" 5   (tạo 5 key vĩnh viễn)

  python admin_cli.py unbind <KEY>           - Mở khóa HWID để đổi máy cho khách
  python admin_cli.py extend <KEY> <số_ngày> - Gia hạn thêm số ngày sử dụng
  python admin_cli.py revoke <KEY_hoặc_HWID> - Thu hồi bản quyền và ngắt kết nối ngay lập tức
========================================================================
    """)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)

    action = sys.argv[1].lower()
    if action in ("list", "sessions"):
        cmd_sessions()
    elif action in ("keys", "licenses"):
        cmd_licenses()
    elif action == "gen":
        if len(sys.argv) < 3:
            print("Cú pháp: python admin_cli.py gen <gói: 1d|7d|30d|90d|365d|lifetime> [tên_khách] [số_lượng]")
            sys.exit(1)
        plan = sys.argv[2]
        cust = sys.argv[3] if len(sys.argv) > 3 else "Customer"
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 1
        cmd_gen(plan, cust, count)
    elif action in ("unbind", "reset-hwid"):
        if len(sys.argv) < 3:
            print("Cú pháp: python admin_cli.py unbind <KEY>")
            sys.exit(1)
        cmd_unbind(sys.argv[2])
    elif action == "extend":
        if len(sys.argv) < 4:
            print("Cú pháp: python admin_cli.py extend <KEY> <số_ngày>")
            sys.exit(1)
        cmd_extend(sys.argv[2], int(sys.argv[3]))
    elif action == "revoke":
        if len(sys.argv) < 3:
            print("Cú pháp: python admin_cli.py revoke <KEY_hoặc_HWID>")
            sys.exit(1)
        cmd_revoke(sys.argv[2])
    else:
        print_help()
