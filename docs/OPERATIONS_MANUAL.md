# SỔ TAY VẬN HÀNH TOÀN DIỆN HỆ THỐNG VCNEXT (OPERATIONS MANUAL)

Hệ thống: VCNext (v4hcam next) | Phiên bản build: 37 | Nền tảng: iOS 15/16 RootHide (Dopamine 2)

---

## 1. TỔNG QUAN HẠ TẦNG TOÀN CỤC (GLOBAL ARCHITECTURE)

Hệ thống đã được thiết kế và triển khai khép kín 100%, bao gồm 3 phân hệ chính:

```
+---------------------------------------------------------------------------------------+
|                                MÁY CHỦ CẤP PHÉP (VPS)                                 |
|   Địa chỉ: https://vc.huxa.xyz (IP: 13.238.38.121)                                    |
|   - Dịch vụ: vcnext.service (Python 3.14 + HTTPS 443 + Let's Encrypt RSA 2048)        |
|   - Cơ sở dữ liệu: /opt/vcnext_server/licenses.db (SQLite)                            |
|   - Khóa thẩm quyền: RSA 3072-bit (server_private_key.pem)                            |
|   - Quản trị: admin_cli.py (liệt kê thiết bị, thu hồi license)                        |
+---------------------------------------------------------------------------------------+
                                  ^
                                  | HTTPS REST v2 (/challenge, /login, /heartbeat, /renew)
                                  v
+---------------------------------------------------------------------------------------+
|                         THIẾT BỊ CLIENT (IPHONE 8 PLUS A11)                           |
|                                                                                       |
|   1. Giao diện (VCNext.app):                                                          |
|      - Gửi yêu cầu đăng nhập và nhận giấy phép hợp lệ từ https://vc.huxa.xyz          |
|      - Tự động ghi AuthSession.plist (0600) và CapabilityLease.plist (0644)           |
|                                                                                       |
|   2. Hệ thống Hook Camera (VCNextCamera.dylib):                                       |
|      - Inject vào mediaserverd và cameracaptured                                      |
|      - Thẩm định chữ ký RSA-3072 trên JSON sorted-keys                                |
|      - Kiểm tra tính toàn vẹn nhị phân (__TEXT,__text SHA-256)                        |
|      - Tráo khung hình camera thật bằng CVPixelBuffer từ video hoặc RTMP              |
|                                                                                       |
|   3. Hệ thống Nút nổi SpringBoard (VCNextOverlay.dylib):                              |
|      - Tạo floating button điều khiển camera trực tiếp trên màn hình                  |
|      - Thẩm định TTL <= 95s và uptime hệ thống mỗi 1.0 giây                           |
|                                                                                       |
|   4. Daemon Mạng & Daemon Stream (LaunchDaemons):                                     |
|      - VCNNetworkDaemon: Định kỳ gửi heartbeat làm mới lease                          |
|      - VCNStreamDaemon: Mở TCP Port 1935 nhận luồng video từ OBS Studio               |
+---------------------------------------------------------------------------------------+
```

---

## 2. QUẢN TRỊ MÁY CHỦ CẤP PHÉP TRÊN VPS

### 2.1. Vị trí tệp tin trên VPS:
Toàn bộ mã nguồn và dữ liệu máy chủ nằm tại thư mục:
`/opt/vcnext_server/`
* `server.py`: Mã nguồn chính xử lý REST v2 API và cấp phát chữ ký số.
* `server_private_key.pem`: Khóa riêng RSA-3072 dùng để ký CapabilityLease và Challenge.
* `licenses.db`: Cơ sở dữ liệu SQLite lưu trữ danh sách phiên hoạt động (`sessions`) và các thử thách (`challenges`).
* `VCNext-custom-roothide.deb`: Gói cài đặt deb được host trực tiếp để tải về.

### 2.2. Quản lý tiến trình dịch vụ (`systemd`):
Dịch vụ được cấu hình tự động khởi động cùng hệ thống và tự phục hồi khi gặp sự cố:
```bash
# Kiểm tra trạng thái hoạt động:
sudo systemctl status vcnext.service

# Khởi động lại dịch vụ:
sudo systemctl restart vcnext.service

# Xem nhật ký truy cập (live logs) theo thời gian thực:
sudo journalctl -u vcnext.service -f -n 50
```

### 2.3. Quản trị Toàn diện qua Telegram Bot (@VCAM_V5_ADMIN_BOT):
Hệ thống bot quản trị chạy ngầm 24/7 dưới dạng dịch vụ `vcnext-bot.service` trên VPS.
Mày chỉ cần mở Telegram chat trực tiếp với bot: **`@VCAM_V5_ADMIN_BOT`**

#### A. Menu Phím Bấm Điều Khiển:
* `➕ Tạo tài khoản`: Wizard tạo nhanh (hỏi username $\rightarrow$ chọn thời hạn $\rightarrow$ chọn số máy $\rightarrow$ chọn mật khẩu).
* `👥 Tài khoản`: Xem danh sách tất cả các tài khoản, số ngày còn lại và số máy.
* `📱 Thiết bị`: Xem danh sách thiết bị iPhone của từng tài khoản.
* `⏳ Gia hạn`: Cộng thêm ngày dùng cho tài khoản.
* `🔑 Đổi mật khẩu`: Đổi mật khẩu mới cho tài khoản.
* `🧹 Đổi máy`: Mở khóa đổi máy (xóa liên kết HWID cũ, bảo lưu trọn vẹn số ngày còn lại).
* `🗑 Xóa tài khoản`: Xóa tài khoản có hộp thoại xác nhận.
* `⌛ Đã hết hạn`: Xem danh sách tài khoản đã hết hạn.
* `📊 Hệ thống`: Xem thống kê tổng tài khoản, thiết bị, phiên online, tài nguyên RAM/CPU VPS.
* `💾 Sao lưu`: Tự động tạo snapshot WAL nhất quán và gửi thẳng file database `licenses.db` về tin nhắn Telegram!

#### B. Các Lệnh Nhanh Bằng Dòng Chat:
```text
/add <user> <mật_khẩu> <thời_hạn> <số_máy>
/find <user>
/extend <user> <thời_hạn>
/setpass <user> [mật_khẩu_mới]
/clear <user>
/del <user>
/expired
/delexpired
/status
/backup

Ví dụ tạo tài khoản 30 ngày cho 1 máy:
/add usertest 1 30 1    (hoặc /add usertest 123456 30d 1)

Thời hạn hỗ trợ: số ngày (ví dụ 30) hoặc 5h, 1d, 7d, 30d, 90d, 365d.
Mật khẩu: từ 1 đến 128 ký tự.
Các thao tác xóa/reset đều có nút [ ✅ Xác nhận ] hoặc [ ❌ Hủy ].
```

### 2.4. Quy trình Khách hàng Đăng nhập trên iPhone:
1. Cài đặt file deb lên iPhone jailbreak bằng Sileo / Zebra / Filza.
2. Mở ứng dụng **VCNext**.
3. Tại màn hình Đăng nhập:
   - **Tài khoản / Account:** Nhập username mày đã cấp (ví dụ: `usertest`).
   - **Mật khẩu / Password:** Nhập mật khẩu đã cấp (ví dụ: `1`).
4. Bấm **Sign In**:
   - Hệ thống xác thực mật khẩu qua mã băm PBKDF2-HMAC-SHA256, kiểm tra thời hạn và số thiết bị.
   - Cấp phát CapabilityLease 90s rolling và kích hoạt toàn bộ tính năng Camera/Nút nổi.
   - Tài khoản developer (`admin` / mật khẩu: `1`) được cấp quyền trọn đời (10 năm) cho máy iPhone 8 Plus của mày.

### 2.5. Sao lưu dữ liệu (Backup):
Cơ sở dữ liệu là tệp SQLite độc lập, sao lưu cực kỳ đơn giản:
```bash
# Kéo file database từ VPS về máy tính bất cứ lúc nào:
scp -i "NGUYEN VAN HIEU.pem" ubuntu@13.238.38.121:/opt/vcnext_server/licenses.db server/licenses.db
```

---

## 3. CƠ CHẾ BẢO MẬT SSL & GIA HẠN CHỨNG CHỈ (LET'S ENCRYPT)

* Chứng chỉ SSL của tên miền `vc.huxa.xyz` được cấp phát bởi Let's Encrypt và được quản lý tự động bởi `certbot`.
* **Cờ bắt buộc đã kích hoạt:** `--key-type rsa --rsa-key-size 2048 --reuse-key`.
* **Lý do:** Khối Tag 2 trong nhị phân của tweak ghim cứng mã băm PKCS#1 của Public Key chứng chỉ này. Nhờ cờ `--reuse-key`, khi `certbot` tự động gia hạn sau mỗi 60-90 ngày, cặp khóa RSA được **giữ nguyên vẹn 100%**, đảm bảo ứng dụng trên iPhone không bao giờ bị đứt kết nối do đổi khóa.

---

## 4. VỊ TRÍ GÓI CÀI ĐẶT DEB VÀ QUY TRÌNH BUILD LẠI

### 4.1. Vị trí file deb thành phẩm mới nhất:
- **Trên máy tính cá nhân:**
  * File chính: `C:\Users\Admin\Desktop\vcnextnew\VCNext-custom-roothide.deb` (496,292 bytes, SHA-256: `4d1f8bf5...`)
  * Bản mirror máy chủ: `server/VCNext-custom-roothide.deb`
- **Trên máy chủ VPS:**
  * File lưu trữ: `/opt/vcnext_server/VCNext-custom-roothide.deb`
- **Link tải trực tiếp tốc độ cao từ iPhone (Safari / Sileo):**
  * `https://vc.huxa.xyz/VCNext-custom-roothide.deb`
  * Hoặc rút gọn: `https://vc.huxa.xyz/download`

### 4.2. Quy trình build lại file deb (khi cần thay đổi cấu hình):
1. Sửa file `scripts/patch_production_binaries.py` với thông số mới.
2. Chạy lệnh vá 14 slice nhị phân và cập nhật lại CodeDirectory page hashes:
   ```bash
   python scripts/patch_production_binaries.py --apply
   ```
3. Chạy script đóng gói deb chuẩn RootHide (tạo real POSIX symlinks, nén zstd và chuẩn hóa header AR `100644  `):
   ```bash
   python scripts/build_custom_deb.py
   ```
4. Đẩy file `VCNext-custom-roothide.deb` mới lên VPS:
   ```bash
   scp -i "NGUYEN VAN HIEU.pem" VCNext-custom-roothide.deb ubuntu@13.238.38.121:/opt/vcnext_server/VCNext-custom-roothide.deb
   ```

---

## 5. HƯỚNG DẪN KẾT NỐI VIRTUAL CAMERA VỚI OBS STUDIO

### Cách 1: Qua mạng Wi-Fi (Cùng một mạng)
1. Mở app **VCNext** trên iPhone $\rightarrow$ Bật **Virtual Camera** $\rightarrow$ Chọn nguồn phát: **RTMP Stream**.
2. Xem địa chỉ IP của iPhone trong Cài đặt Wi-Fi (ví dụ: `192.168.1.150`).
3. Mở **OBS Studio** trên máy tính:
   - Cài đặt (Settings) -> Phát luồng (Stream):
     * Dịch vụ: `Tùy chỉnh...` (Custom)
     * Máy chủ: `rtmp://192.168.1.150:1935/live`
     * Khóa luồng: `live` (hoặc chuỗi bất kỳ)
   - Đầu ra (Output): Bitrate 2500 - 3500 Kbps, Encoder H.264.
   - Video: Độ phân giải `1080x1920` (dọc) hoặc `1920x1080` (ngang), FPS: `30`.
4. Bấm **Bắt đầu phát luồng** (Start Streaming).
5. Mở Camera hoặc app gọi video trên iPhone để nhận luồng hình ảnh trực tiếp.

### Cách 2: Qua cáp USB (Tốc độ cao nhất, không lo chập chờn)
1. Cắm cáp USB nối iPhone với máy tính.
2. Mở terminal trên máy tính chuyển tiếp cổng:
   ```bash
   iproxy 1935 1935
   ```
3. Trong OBS Studio:
   - Máy chủ: `rtmp://127.0.0.1:1935/live`
   - Khóa luồng: `live`
4. Bấm **Bắt đầu phát luồng**: Video truyền trực tiếp qua cáp Lightning độ trễ bằng 0!
