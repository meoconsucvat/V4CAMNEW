# TẦNG 3: THẨM ĐỊNH GIẤY PHÉP VÀ CÁC CƠ CHẾ BẢO VỆ PHÂN TÁN (LAYER 3 SPEC)
Mục tiêu phân tích: `VCNextCamera.dylib`, `VCNStreamDaemon`, `VCNext.app`, `VCNextOverlay.dylib`, `VCNNetworkDaemon`

---

## 1. MÔ HÌNH PHÒNG THỦ PHÂN TÁN 5 ĐIỂM (5-POINT DISTRIBUTED DRM)

Hệ thống VCNext triển khai cơ chế kiểm tra phân tán trên cả 5 file thực thi:

### 1.1. Hàm Thẩm định Master: `_VCN5d92c005b0c38441000a`
Được biên dịch tĩnh (statically linked) vào cả 5 file:
- **`VCNNetworkDaemon`:** `0x10000783c`
- **`VCNStreamDaemon`:** `0x1000072d4`
- **`VCNext` (App UI):** `0x100020cc4` (Caller tại `0x100007a8c`)
- **`VCNextCamera.dylib`:** `0x10e1c` (Hàm export, có giới hạn thời gian 185s nhưng không có caller nội bộ trực tiếp trên luồng render)
- **`VCNextOverlay.dylib`:** `0xb0f8` (Hàm export, không có caller nội bộ trực tiếp trên luồng UI)

### 1.2. Hai Hàm Thẩm định Thực thi Active Reader (Giới hạn TTL 95.0 Giây):
Trên thực tế runtime, cả Camera và Overlay đều sử dụng active reader riêng biệt với hằng số thời gian khắt khe `95.0s` (`0x4057c00000000000`):
1. **`VCNextOverlay.dylib` (`0xc48c`):**
   - Kích hoạt bởi `NSTimer` lặp **mỗi 1.0 giây** trên main runloop (`0x4ba8`).
   - Yêu cầu: $0 < \text{expires\_at} - \text{issued\_at} \le 95.0\text{s}$ và $\text{uptime} - \text{received\_uptime} < \text{TTL}$.
   - Nếu vi phạm, gọi `0x6fe0` (`clearOverlay`) gỡ bỏ nút nổi khỏi SpringBoard.
2. **`VCNextCamera.dylib` (`0x121b0`):**
   - Kích hoạt mỗi khi cấu hình camera được nạp (`0xa6f4`).
   - Kiểm tra hằng số `95.0` tại `0x126bc`–`0x126c0` và ràng buộc uptime tại `0x126ec`.
   - Nếu vi phạm, toàn bộ các cờ quyền stream/import bị khóa và rơi về camera gốc.

---

## 2. QUY TRÌNH KIỂM SOÁT SCHEMA VÀ CẤU TRÚC TỆP `CapabilityLease.plist`

Tệp `CapabilityLease.plist` tại `/var/jb/var/mobile/Library/VCNext/CapabilityLease.plist` gồm 2 tầng dữ liệu:

### 2.1. Cấu trúc Vỏ bọc Ngoài (Envelope Dictionary):
```xml
<dict>
    <key>lease</key>
    <dict> ... (Payload cấp phép bên dưới) ... </dict>

    <key>signature</key>
    <string>Base64(RSA-3072 PKCS#1 v1.5 SHA-256)</string>

    <!-- Uptime thực của hệ thống (processInfo.systemUptime) tại thời điểm ghi lease -->
    <key>received_uptime</key>
    <real>120.45</real>

    <!-- Ràng buộc danh tính phần cứng (Bắt buộc khớp với bên trong lease) -->
    <key>device_id</key>
    <string>4A9F21B3-8D12-4E56-91A2-F02BCDE91044</string>

    <key>device_key_thumbprint</key>
    <string>6cb81e...64 hex ký tự...</string>
</dict>
```

### 2.2. Danh sách 5 Quyền Năng Sinh Tử trong Mảng `capabilities`:
Mảng `capabilities` trong `lease` bắt buộc phải là `NSArray` chứa đủ 5 chuỗi định danh quyền:
1. **`"camera.fake-frame"`** (Camera `0xa8f0`): Kích hoạt pipeline tráo khung hình trong `mediaserverd`. Thiếu quyền này -> Camera hiển thị màn hình đen hoặc camera thật.
2. **`"camera.obs"`** (Camera `0xa904`): Cho phép nhận luồng video RTMP từ OBS Studio qua cổng 1935.
3. **`"media.import"`** (Camera `0xa914`): Cho phép nạp tệp video MP4 hoặc ảnh tĩnh từ thư viện máy.
4. **`"camera.controls"`** (Overlay `0x1224d`): Cho phép hiển thị nút bấm điều khiển nổi trên SpringBoard.
5. **`"camera.color-sync"`** (Camera `0x178dd` & Overlay `0x1225d`): Cho phép đồng bộ màu và cân chỉnh khung hình.

---

## 3. THUẬT TOÁN KÝ VÀ KIỂM TRA CHỮ KÝ SỐ NATIVE

Tại `0x103b8` (Camera) và `0xa694` (Overlay):
Dữ liệu được ký số **BẮT BUỘC là chuỗi JSON đã sắp xếp khóa (Sorted-Key JSON)**, không phải binary plist:

```
[NSDictionary *leaseDict]
          |
          v (0x103b0 / 0xa69c)
[NSJSONSerialization dataWithJSONObject:leaseDict options:NSJSONWritingSortedKeys (2) error:&error]
          |
          v
[NSData *signedJSONBytes]
          |
          v (0x1049c / 0xa778)
SecKeyVerifySignature(
    serverPublicKey,                                    // Khóa công khai RSA 3072-bit từ Tag 3
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,  // RSA PKCS#1 v1.5 with SHA-256
    signedJSONBytes,
    signatureData,
    &error
)
```

---

## 4. BẢN CHẤT CƠ CHẾ SELF-INTEGRITY HASH CỦA CÁC BINARY

Tại `0x116b4` trong `VCNextCamera.dylib` và `0x100007b6c` trong `VCNStreamDaemon`:
- Hàm tự băm chỉ quét và tính `CC_SHA256` trên **DUY NHẤT phân vùng `__TEXT,__text`** (đo đạc độc lập bằng LIEF):
  * **`VCNextCamera.dylib` (arm64 slice):** `d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943`
  * **`VCNextCamera.dylib` (arm64e slice):** `60e7f7328417c91f4dd21bf27077d5196b11d8aa698ce7f0c6f78217736a6bba`
- Phân vùng chứa các chuỗi mã hóa Tag 1, Tag 2, Tag 3 là **`__TEXT,__const`** (`0x15ce0` - `0x16ce8`).
- **Ý nghĩa sống còn:** Việc thay thế chứng chỉ Tag 3 trong `__TEXT,__const` **hoàn toàn không làm thay đổi giá trị SHA-256 của `__TEXT,__text`**. Cơ chế tự kiểm tra tính toàn vẹn nhị phân vẫn vượt qua 100%!

---

## 5. THIẾT KẾ DỊCH VỤ GIA HẠN CỤC BỘ (OPTION A: LOCAL RENEWAL SERVICE)

Để thỏa mãn cả 2 active reader (TTL 90s, kiểm tra uptime mỗi 1.0s) trên iPhone 8 Plus (A11 Dopamine 2 RootHide):

1. **Dịch vụ Giám sát Nền (Supervised Native Renewal Service):**
   - Đặt tại `/Library/LaunchDaemons/com.vcnext.networkd.plist` (thay thế vai trò của daemon cũ).
   - Khởi động cùng hệ thống (`RunAtLoad = true`, `KeepAlive = true`).
2. **Quy trình Gia hạn mỗi 45 Giây:**
   - Đọc `NSProcessInfo.processInfo.systemUptime` thực tế của thiết bị tại thời điểm chạy.
   - Lấy thời gian epoch hiện tại: $\text{issued\_at} = \text{now}$, $\text{expires\_at} = \text{now} + 90.0\text{s}$ ($\text{TTL} = 90.0\text{s} \le 95.0\text{s}$).
   - Sinh chuỗi JSON sorted-keys và ký bằng RSA-3072 Private Key cục bộ.
   - Ghi **nguyên tử (atomic transaction)** vào tệp tạm thời rồi đổi tên (`rename`) đè lên `/var/jb/var/mobile/Library/VCNext/CapabilityLease.plist` với quyền `mobile:mobile` (0644).
   - Phát Darwin notification: `notify_post("com.vcnext.capability.changed")`.
3. **Kết quả đạt được:**
   - Cả 5 binary giữ nguyên 100% mã máy, không dính lỗi PAC, không crash SpringBoard.
   - Cửa sổ 95 giây luôn được làm mới trước 45 giây -> Tweak chạy vĩnh cửu không bao giờ tắt.
   - Hoàn toàn độc lập với Internet, không rò rỉ dữ liệu lên máy chủ lạ.
