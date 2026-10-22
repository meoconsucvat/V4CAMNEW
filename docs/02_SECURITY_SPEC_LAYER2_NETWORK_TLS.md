# TẦNG 2: GIAO THỨC MẠNG, GIẢI MÃ TĨNH & SSL PINNING (LAYER 2 SPEC)
Mô đun: `VCNNetworkDaemon` | Máy chủ: `https://anix204.xyz`

---

## 1. KIẾN TRÚC LÀM RỐI & MÃ HÓA CHUỖI NHỊ PHÂN (OBFUSCATION SCHEME)

Tác giả không để lộ bất kỳ URL, tên miền hay chứng chỉ nào ở dạng văn bản thường (Plaintext). Thay vào đó, toàn bộ dữ liệu nhạy cảm được bảo vệ bằng một cấu trúc mã hóa xác thực hai lớp (Authenticated Encryption with Derived Keys):

### 1.1. Khóa gốc dùng chung (Hardcoded Master Key):
Khóa bí mật 256-bit (32 byte) được nhúng tại phân vùng `__TEXT,__const`:
- **VCNNetworkDaemon offset:** `0x10000a0f0`
- **VCNextCamera.dylib offset:** `0x165a0`
- **Giá trị Hex:**
  ```hex
  14 df 1f bc b8 33 23 1a ec 28 2c de 08 b5 11 04
  a0 e7 7d 6b 33 f4 be 35 ad 3f 46 86 02 f1 df fb
  ```

### 1.2. Thuật toán dẫn xuất khóa & Giải mã:
Mỗi khối dữ liệu được gán một thẻ nhận diện (Tag: 1, 2 hoặc 3):
1. **Dẫn xuất Khóa AES 1 ($K_1$):**
   $$K_1 = \text{HMAC-SHA256}(K_{\text{master}}, \text{0x02} \parallel \text{Tag} \parallel \text{0xa1} \parallel \text{Salt})$$
2. **Dẫn xuất Khóa MAC ($K_2$):**
   $$K_2 = \text{HMAC-SHA256}(K_{\text{master}}, \text{0x02} \parallel \text{Tag} \parallel \text{0xb2} \parallel \text{Salt})$$
3. **Kiểm tra tính toàn vẹn (Integrity MAC Check):**
   $$\text{MAC}_{\text{calc}} = \text{HMAC-SHA256}(K_2, \text{0x02} \parallel \text{Tag} \parallel \text{Salt} \parallel \text{IV}_2 \parallel \text{IV}_1 \parallel C)$$
   Nếu $\text{MAC}_{\text{calc}} \ne \text{MAC}_{\text{expected}}$ thì hủy bỏ ngay lập tức (Constant-time comparison).
4. **Giải mã 2 lớp (Double AES-256-CBC with PKCS7 Padding):**
   $$P_{\text{temp}} = \text{AES-CBC-Decrypt}(K_1, \text{IV}_1, C)$$
   $$P_{\text{final}} = \text{AES-CBC-Decrypt}(K_{\text{master}}, \text{IV}_2, P_{\text{temp}})$$

---

## 2. KẾT QUẢ GIẢI MÃ TĨNH CÁC KHỐI DỮ LIỆU

### 2.1. Khối Tag 1: Cấu hình Endpoint Máy chủ
```json
{
  "api_base_url": "https://anix204.xyz",
  "api_host": "anix204.xyz",
  "audience": "vcnext-ios",
  "challenge_path": "/api/v2/auth/challenge",
  "heartbeat_path": "/api/v2/auth/heartbeat",
  "issuer": "vcnext-main",
  "login_path": "/api/v2/auth/login",
  "logout_path": "/api/v2/auth/logout",
  "renew_path": "/api/v2/auth/renew"
}
```

### 2.2. Khối Tag 2: Thumbprint khóa công khai (32 bytes)
```hex
27 3b 81 f5 e7 91 16 c3 a4 fe 4c e1 74 34 82 ba
f1 41 84 85 d2 ae a0 ed 76 22 6f f6 0c 0e 45 72
```

### 2.3. Khối Tag 3: Chứng chỉ X.509 DER ghim cứng (1,071 bytes)
- **Subject / Issuer:** `CN = VCNext Main Online Signing`
- **Khóa công khai máy chủ:** RSA 3072-bit (Exponent: 65537)
- **Hiệu lực:** 2026-08-05 đến 2036-08-02
- **Mục đích:** Dùng cho SSL Pinning và xác minh chữ ký `CapabilityLease.plist`.

---

## 3. ĐẶC TẢ GIAO THỨC REST API v2

Mọi request từ thiết bị gửi tới `https://anix204.xyz` đều phải tuân theo cấu trúc chuẩn:

### 3.1. HTTP Request Headers bắt buộc:
```http
POST /api/v2/auth/heartbeat HTTP/1.1
Host: anix204.xyz
Content-Type: application/json
Accept: application/json
Authorization: Bearer <access_token>
X-Device-ID: 4A9F21B3-8D12-4E56-91A2-F02BCDE91044
X-Client-Build: 37
X-App-Digest: <64_char_hex_binary_digest>
```

### 3.2. Quy trình xác thực (Authentication State Machine):

```
Thiết bị (VCNNetworkDaemon)                             Máy chủ (anix204.xyz)
       |                                                         |
       |----- (1) POST /api/v2/auth/challenge ------------------>|
       |      Body: { device_id, build: 37 }                     |
       |                                                         |
       |<---- (2) 200 OK: { challenge_id, nonce, timestamp } ----|
       |                                                         |
       | [Thiết bị ký nonce bằng Private Key ECDSA P-256]        |
       |                                                         |
       |----- (3) POST /api/v2/auth/login hoặc /heartbeat ------>|
       |      Body: {                                            |
       |        device_id,                                       |
       |        challenge_id,                                    |
       |        device_signature,                                |
       |        build: 37,                                       |
       |        binary_digest                                    |
       |      }                                                  |
       |                                                         |
       |<---- (4) 200 OK: Trả về CapabilityLease và Tokens ------|
       |      Response Body: {                                   |
       |        access_token,                                    |
       |        renewal_token,                                   |
       |        lease: { ... },                                  |
       |        signature: "Base64(RSA-2048 signature)"          |
       |      }                                                  |
       v                                                         v
```

---

## 4. CƠ CHẾ SSL PINNING TẦNG NATIVE (`URLSessionDelegate`)

Trong `VCNNetworkDaemon`, class `VCNAuthHeartbeatDelegate` triển khai phương thức delegate:
`URLSession:didReceiveChallenge:completionHandler:`

### Logic kiểm tra:
1. Nhận `NSURLAuthenticationChallenge` với phương thức `NSURLAuthenticationMethodServerTrust`.
2. Trích xuất `SecTrustRef` từ challenge.
3. Đánh giá tính toàn vẹn chuỗi chứng chỉ bằng `SecTrustEvaluateWithError`.
4. Gọi `SecTrustCopyKey` để lấy khóa công khai của máy chủ từ chứng chỉ TLS thực tế trên đường truyền.
5. So sánh khóa này với khóa công khai trong chứng chỉ `VCNext Main Online Signing` (hoặc đối chiếu SHA-256 thumbprint khối Tag 2).
6. **Kết quả:** Nếu khóa không khớp 100%, hủy request và ghi log `"Server identity verification failed"`. Điều này vô hiệu hóa các công cụ can thiệp proxy thông thường.
