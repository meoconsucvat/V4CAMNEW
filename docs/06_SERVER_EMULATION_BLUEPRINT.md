# BẢN ĐẶC TẢ VÀ TRIỂN KHAI THỰC TẾ MÁY CHỦ CẤP PHÉP (SERVER PRODUCTION BLUEPRINT)
Trạng thái: **ĐÃ TRIỂN KHAI & ĐANG HOẠT ĐỘNG 100% TRÊN LIVE VPS**  
Tên miền chính thức: `https://vc.huxa.xyz` (IP: `13.238.38.121`)  
Mã nguồn đồng bộ trong kho lưu trữ: [server/server.py](server/server.py) | Quản trị: [server/admin_cli.py](server/admin_cli.py)

---

## 1. TỔNG QUAN HỆ THỐNG MÁY CHỦ ĐANG HOẠT ĐỘNG (LIVE SYSTEM ARCHITECTURE)

Hệ thống máy chủ cấp phép thương mại đã được triển khai thực tế trên máy chủ AWS EC2 Ubuntu 26.04 LTS (Sydney), thay thế hoàn toàn hạ tầng cũ `anix204.xyz`:

```
+---------------------------------------------------------------------------------------+
|                                  CLIENT LAYER (iOS)                                  |
|   VCNNetworkDaemon / VCNext.app                                                       |
|   - Định danh phần cứng: device_id (UUID v4)                                          |
|   - Khóa ký thiết bị: ECDSA P-256 (secp256r1) Private Key                             |
+---------------------------------------------------------------------------------------+
                                  |
                                  | HTTPS (TLS with Pinned Certificate / Custom Domain)
                                  v
+---------------------------------------------------------------------------------------+
|                              EDGE / REVERSE PROXY LAYER                               |
|   Nginx / Caddy / Cloudflare                                                          |
|   - SSL Termination (Sử dụng chứng chỉ X.509 khớp RSA-2048 Tag 3)                     |
|   - Rate Limiting chống spam/bruteforce challenge                                     |
+---------------------------------------------------------------------------------------+
                                  |
                                  v
+---------------------------------------------------------------------------------------+
|                               API ENGINE (FastAPI / Go)                               |
|   Mô đun 1: State Machine Xác thực & Handshake (/challenge, /login, /logout)          |
|   Mô đun 2: Heartbeat & Token Renewal Manager (/heartbeat, /renew)                    |
|   Mô đun 3: Crypto Signing Core (RSA-2048 PKCS#1 v1.5 Binary Plist Signer)            |
+---------------------------------------------------------------------------------------+
                                  |
                                  v
+---------------------------------------------------------------------------------------+
|                                  DATA STORAGE LAYER                                   |
|   PostgreSQL / SQLite + Redis (In-memory Challenge Nonce Cache)                       |
|   - Bảng Quản trị Thiết bị (Devices, HWID, P-256 Thumbprints)                         |
|   - Bảng Giấy phép Thương mại (Licenses, Gói cước ngày/tháng/vĩnh viễn)              |
|   - Bảng Mã băm Nhị phân Hợp lệ (Approved Binary Digests for arm64 & arm64e)          |
+---------------------------------------------------------------------------------------+
```

---

## 2. BẢN ĐỒ GIAO DIỆN LẬP TRÌNH REST v2 (API CONTRACTS)

Căn cứ trên dữ liệu giải mã Tag 1 của nhị phân, toàn bộ các route bắt buộc phải triển khai đúng chuẩn:

### 2.1. `POST /api/v2/auth/challenge`
* **Mục đích:** Khởi tạo phiên thử thách chống tấn công phát lại (Replay-Attack Protection).
* **Request Headers:**
  ```http
  Content-Type: application/json
  X-Device-ID: 4A9F21B3-8D12-4E56-91A2-F02BCDE91044
  X-Client-Build: 37
  ```
* **Request Body:**
  ```json
  {
    "device_id": "4A9F21B3-8D12-4E56-91A2-F02BCDE91044",
    "build": 37,
    "platform": "ios"
  }
  ```
* **Server Logic:**
  1. Kiểm tra `device_id` có nằm trong danh sách đen (Blacklist) hay không.
  2. Sinh chuỗi `challenge_id` (UUID v4) và `nonce` ngẫu nhiên 32 byte (Hex 64 ký tự).
  3. Lưu `challenge_id` vào Redis/Memory với TTL = 60 giây.
* **Response Body (200 OK):**
  ```json
  {
    "challenge_id": "c8a14b52-9f33-4e89-b1a5-001122334455",
    "nonce": "7f8e3d2a1c0b9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b",
    "timestamp": 1792345678,
    "purpose": "auth.challenge"
  }
  ```

---

### 2.2. `POST /api/v2/auth/login`
* **Mục đích:** Xác thực danh tính thiết bị và cấp phát CapabilityLease lần đầu.
* **Request Headers:**
  ```http
  Content-Type: application/json
  X-Device-ID: 4A9F21B3-8D12-4E56-91A2-F02BCDE91044
  X-Client-Build: 37
  X-App-Digest: c8bf380af153d58f8a64e717bd739005c009fe5178aa47039726cfd14f3fff30
  ```
* **Request Body:**
  ```json
  {
    "device_id": "4A9F21B3-8D12-4E56-91A2-F02BCDE91044",
    "challenge_id": "c8a14b52-9f33-4e89-b1a5-001122334455",
    "device_public_key": "04a1b2...65 bytes hex (X9.62 uncompressed)...",
    "device_key_thumbprint": "273b81f5e79116c3a4fe4ce1743482baf1418485d2aea0ed76226ff60c0e4572",
    "device_signature": "Base64(ECDSA-P256 signature over nonce)",
    "build": 37,
    "binary_digest": "c8bf380af153d58f8a64e717bd739005c009fe5178aa47039726cfd14f3fff30"
  }
  ```
* **Server Logic:**
  1. Lấy `nonce` từ `challenge_id`, kiểm tra còn hạn trong 60 giây không.
  2. Xác minh chữ ký `device_signature` bằng `device_public_key` (ECDSA P-256 with SHA-256).
  3. Kiểm tra tính toàn vẹn: Tính $\text{SHA-256}(\text{device\_public\_key})$, đối chiếu với `device_key_thumbprint`.
  4. Kiểm tra quyền sở hữu giấy phép: Tài khoản/thiết bị này có gói cước active không.
  5. Kiểm tra `binary_digest`: Phải nằm trong danh sách băm của các bản build hợp lệ (chống bản mod không mong muốn).
  6. Sinh `session_binding` và `renewal_binding`.
  7. Xây dựng dictionary `lease`, serialize thành Binary Plist v1.0.
  8. Ký bằng Server RSA-2048 Private Key (PKCS#1 v1.5 SHA-256).
* **Response Body (200 OK):**
  ```json
  {
    "status": "active",
    "access_token": "at_90e1f3a2b4c5...",
    "renewal_token": "rn_81a2b3c4d5e6...",
    "lease": {
      "version": 2,
      "purpose": "capability.lease",
      "issuer": "vcnext-main",
      "audience": "vcnext-ios",
      "build": 37,
      "device_id": "4A9F21B3-8D12-4E56-91A2-F02BCDE91044",
      "device_key_thumbprint": "273b81f5e79116c3a4fe4ce1743482baf1418485d2aea0ed76226ff60c0e4572",
      "binary_digest": "c8bf380af153d58f8a64e717bd739005c009fe5178aa47039726cfd14f3fff30",
      "session_binding": "c8a14b52-9f33-4e89-b1a5-001122334455",
      "renewal_binding": "f1e2d3c4-b5a6-7890-1234-56789abcdef0",
      "next_nonce_hash": "a4b3c2...64 ký tự hex...",
      "capabilities": {
        "virtual_camera": true,
        "rtmp_streaming": true,
        "vision_alignment": true,
        "custom_resolution": true
      },
      "issued_at": "2026-10-19T00:00:00Z",
      "expires_at": "2036-10-19T00:00:00Z"
    },
    "signature": "Base64(RSA-2048 signature)",
    "server_time": 1792345700
  }
  ```

---

### 2.3. `POST /api/v2/auth/heartbeat`
* **Mục đích:** Thiết bị gửi định kỳ mỗi 120-150 giây để duy trì trạng thái active trước khi hết hạn cửa sổ 185 giây.
* **Request Headers:**
  ```http
  Authorization: Bearer <access_token>
  X-Device-ID: 4A9F21B3-8D12-4E56-91A2-F02BCDE91044
  ```
* **Request Body:**
  ```json
  {
    "session_binding": "c8a14b52-9f33-4e89-b1a5-001122334455",
    "nonce_proof": "Base64(ECDSA signature over current nonce)"
  }
  ```
* **Response Body (200 OK):**
  - Trả về cấu trúc `lease` đã gia hạn thời gian `expires_at` mới kèm chữ ký số mới.

---

### 2.4. `POST /api/v2/auth/renew`
* **Mục đích:** Khi `access_token` hết hạn nhưng `renewal_token` còn hiệu lực.
* **Body:** Chứa `renewal_token`, `device_id`.
* **Response:** Cấp cặp token mới và giấy phép gia hạn.

---

### 2.5. `POST /api/v2/auth/logout`
* **Mục đích:** Hủy phiên, đưa `session_binding` vào blacklist.

---

## 3. THIẾT KẾ CƠ SỞ DỮ LIỆU THƯƠNG MẠI (DATABASE SCHEMA)

```sql
-- 1. Bảng Quản trị Người dùng / Khách hàng
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(128) UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role VARCHAR(16) DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Bảng Quản lý Gói cước Giấy phép (License Plans)
CREATE TABLE licenses (
    id SERIAL PRIMARY KEY,
    license_key VARCHAR(64) UNIQUE NOT NULL,
    customer_id INTEGER REFERENCES customers(id),
    plan_type VARCHAR(32) NOT NULL, -- 'daily', 'monthly', 'lifetime'
    max_devices INTEGER DEFAULT 1,
    status VARCHAR(16) DEFAULT 'active', -- 'active', 'suspended', 'expired'
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 3. Bảng Thiết bị đã đăng ký (Devices)
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    license_id INTEGER REFERENCES licenses(id),
    device_id VARCHAR(64) UNIQUE NOT NULL,
    device_key_thumbprint VARCHAR(64) NOT NULL,
    device_public_key_hex TEXT NOT NULL,
    model_name VARCHAR(64),
    ios_version VARCHAR(32),
    jailbreak_tool VARCHAR(64), -- 'Dopamine RootHide', 'Bootstrap', 'Relaxin'
    last_seen_ip VARCHAR(45),
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    is_blocked BOOLEAN DEFAULT FALSE
);

-- 4. Bảng Phiên xác thực đang chạy (Active Sessions)
CREATE TABLE active_sessions (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(64) REFERENCES devices(device_id),
    session_binding VARCHAR(64) UNIQUE NOT NULL,
    renewal_binding VARCHAR(64) UNIQUE NOT NULL,
    access_token_hash VARCHAR(64) NOT NULL,
    renewal_token_hash VARCHAR(64) NOT NULL,
    current_nonce VARCHAR(64) NOT NULL,
    next_nonce VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Bảng Whitelist Mã băm nhị phân hợp lệ (Approved Builds)
CREATE TABLE approved_binary_digests (
    id SERIAL PRIMARY KEY,
    build_number INTEGER NOT NULL,
    binary_name VARCHAR(64) NOT NULL, -- 'VCNextCamera.dylib', 'VCNStreamDaemon'
    architecture VARCHAR(16) NOT NULL, -- 'arm64', 'arm64e'
    sha256_digest VARCHAR(64) NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    release_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. CHIẾN LƯỢC XỬ LÝ SSL PINNING KHI TRIỂN KHAI THỰC TẾ

Khi mày vận hành server thương mại riêng, `VCNNetworkDaemon` gốc của tweak sẽ từ chối kết nối nếu chứng chỉ HTTPS không khớp với chứng chỉ nhúng cứng trong khối Tag 3. Có 2 mô hình triển khai:

### MÔ HÌNH 1: Server Pinned Authority (Khuyên dùng khi phân phối Deb riêng)
1. Dùng cặp khóa RSA-2048 (`mocks/test_server_private_key.pem`) tạo chứng chỉ TLS tự ký hoặc chứng chỉ CA cho tên miền của mày (ví dụ `api.vcnext-license.com`).
2. Thay thế khối Tag 3 của cả 5 binary bằng chứng chỉ mới này.
3. Thay thế domain `anix204.xyz` trong khối Tag 1 thành tên miền máy chủ mới của mày.
4. **Kết quả:** Client kết nối trực tiếp đến máy chủ của mày, SSL Pinning native vượt qua 100% hợp lệ, không cần can thiệp trust store của hệ điều hành.

### MÔ HÌNH 2: Local DNS Loopback với RootHide Certificate Store
1. Trỏ DNS `anix204.xyz` trên router hoặc file `/etc/hosts` của iPhone về IP server nội bộ.
2. Cài đặt Root CA vào Profiles của iOS và bật cờ "Full Trust for Root Certificates".
3. Patch phương thức delegate `URLSession:didReceiveChallenge:completionHandler:` để luôn gọi completion handler với `NSURLSessionAuthChallengeUseCredential`.
