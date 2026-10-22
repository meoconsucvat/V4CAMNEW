# TẦNG 1: ĐỊNH DANH THIẾT BỊ & HẠ TẦNG KHÓA CỤC BỘ (LAYER 1 SPEC)
Mô đun: `VCNNetworkDaemon` | Cơ chế: ECDSA P-256 & Hardware Identity

---

## 1. MÔ HÌNH KHÓA ĐỊNH DANH THIẾT BỊ (DEVICE ASYMMETRIC KEYPAIR)

Thay vì chỉ dựa vào `device_id` (UUID) thông thường vốn dễ bị giả lập hoặc chỉnh sửa, VCNext áp dụng mô hình xác thực dựa trên chứng minh sở hữu khóa phần cứng (Proof of Possession - PoP):

1. **Thuật toán sinh khóa:**
   - Chuẩn: **ECDSA P-256 (secp256r1)**.
   - Hằng số hệ thống Apple Security:
     - `kSecAttrKeyType` = `kSecAttrKeyTypeECSECPrimeRandom`
     - `kSecAttrKeySizeInBits` = `256`
     - `kSecAttrKeyClass` = `kSecAttrKeyClassPrivate`
2. **Xuất khóa công khai (Public Key Export):**
   - Sử dụng hàm native `SecKeyCopyExternalRepresentation` để lấy mảng byte X9.62 thô (định dạng uncompressed 65 byte: byte dẫn xuất `0x04` kèm 32 byte tọa độ X và 32 byte tọa độ Y).
3. **Mã băm khóa công khai (`device_key_thumbprint`):**
   - Tính toán trực tiếp bằng `CC_SHA256`:
     $$\text{Thumbprint} = \text{SHA-256}(\text{Raw PublicKey Bytes})$$
   - Chiều dài: 32 byte (thường được biểu diễn dưới dạng Hex String 64 ký tự).

---

## 2. CẤU TRÚC TỆP `AuthSession.plist`

Tệp tin này được khởi tạo và bảo vệ độc quyền bởi `VCNNetworkDaemon` (chạy quyền `root`), lưu trữ tại:
`/var/jb/var/mobile/Library/VCNext/AuthSession.plist`

### 2.1. Quyền hạn bảo mật tệp:
- Sở hữu: `mobile:mobile` (để `VCNext.app` có thể đọc thông tin người dùng hiển thị lên UI).
- Thuộc tính bảo vệ dữ liệu iOS: `NSFileProtectionCompleteUntilFirstUserAuthentication`.

### 2.2. Schema định dạng Plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Định danh duy nhất của thiết bị (UUID v4 hoặc HWID) -->
    <key>device_id</key>
    <string>4A9F21B3-8D12-4E56-91A2-F02BCDE91044</string>

    <!-- Khóa riêng ECDSA P-256 (Dạng Data nhị phân hoặc chuỗi mã hóa) -->
    <key>device_private_key</key>
    <data>
    ... (Private Key DER / Raw Scalar 32 bytes) ...
    </data>

    <!-- SHA-256 thumbprint của Public Key P-256 tương ứng -->
    <key>device_key_thumbprint</key>
    <string>a4f5c2...64 ký tự hex...</string>

    <!-- Token truy cập sau khi login thành công -->
    <key>access_token</key>
    <string>eyJhbGciOi...</string>

    <!-- Token dùng để gia hạn phiên (/api/v2/auth/renew) -->
    <key>renewal_token</key>
    <string>rn_89af31bc...</string>

    <!-- Tên tài khoản người dùng đăng ký -->
    <key>user</key>
    <string>v4hcam_customer_01</string>

    <!-- Dấu thời gian cập nhật phiên gần nhất -->
    <key>updated_at</key>
    <date>2026-10-18T10:30:00Z</date>
</dict>
</plist>
```

---

## 3. CƠ CHẾ CAN THIỆP CHÍNH SÁCH MẠNG COMMCENTER (PRIVILEGE ESCALATION)

Do `VCNNetworkDaemon` chạy ở quyền `root` với entitlement đặc quyền cao:
- `com.apple.CommCenter.fine-grained`
- `com.apple.private.security.no-sandbox`

Nó thực hiện gọi trực tiếp vào các hàm Private Framework của `CoreTelephony` để can thiệp chính sách mạng:
1. `_CTServerConnectionCreate` / `_CTServerConnectionSetCellularDataUsagePolicy`:
   - Gán `kCTCellularDataUsagePolicy` = `kCTCellularDataUsagePolicyAlwaysAllow` cho Bundle ID `com.vcnext.app`.
2. Gán `kCTWiFiDataUsagePolicy` = `AlwaysAllow`.
3. **Mục đích:** Đảm bảo `VCNext.app` và daemon luôn luôn có kết nối Internet thông suốt mà không bao giờ bị iOS hiện popup: *"Bạn có muốn cho phép ứng dụng này sử dụng dữ liệu di động không?"* (tránh sự chú ý của người dùng hoặc các công cụ giám sát sandbox).
