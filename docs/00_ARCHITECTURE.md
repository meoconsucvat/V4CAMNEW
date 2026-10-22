# BẢN ĐẶC TẢ KIẾN TRÚC HỆ THỐNG VCNEXT (V4HCAM NEXT)
Phiên bản: 0.16.73 (Build 37) | Target: iOS >= 15.0 (RootHide arm64/arm64e)

---

## 1. TỔNG QUAN HỆ THỐNG & PHÂN TẦNG QUYỀN HẠN

VCNext là một hệ thống tweak jailbreak iOS can thiệp ở cấp độ hạt nhân người dùng (userspace system-level) nhằm thay thế luồng video thật của camera bằng video tệp tin hoặc luồng RTMP trực tiếp.

Toàn bộ hệ thống được chia làm 5 tiến trình/thư viện với các phân cấp đặc quyền khác nhau:

```
+-----------------------------------------------------------------------------------+
|                                 USER INTERFACE                                    |
|  VCNext.app (Rootless Container / Applications)                                  |
|  - Quyền hạn: no-sandbox, platform-application                                    |
|  - Quản trị cấu hình, kích hoạt floating overlay, nạp video Media                 |
+-----------------------------------------------------------------------------------+
       |                                      |                               |
       | IPC (CFNotificationCenter)           | IPC                           | File IO
       v                                      v                               v
+-----------------------------+   +-----------------------------+   +---------------+
|      STREAMING PIPELINE     |   |       NETWORK & AUTH        |   | SHARED STATE  |
|  VCNStreamDaemon            |   |  VCNNetworkDaemon           |   | /var/jb/var/  |
|  - User: mobile             |   |  - User: root               |   | mobile/       |
|  - Port: 1935 (RTMP server) |   |  - CoreTelephony CommCenter |   | Library/      |
|  - Out: Streams/live.vcn    |   |  - Trao đổi anix204.xyz     |   | VCNext/       |
+-----------------------------+   +-----------------------------+   +---------------+
       |                                      |                               ^
       | IOSurface / File Map                 | CapabilityLease.plist         |
       v                                      v                               |
+---------------------------------------------------------------+             |
|                       SYSTEM HOOK LAYER                       |             |
|  VCNextCamera.dylib (Inject: mediaserverd, cameracaptured)   |-------------+
|  - MSHookMessageEx vào CMSampleBuffer / AVCaptureSession      | (Đọc Lease & Config)
|  - Kiểm tra chữ ký RSA-2048 SHA-256 từ CapabilityLease        |
|  - Tự kiểm tra tính toàn vẹn nhị phân (Binary Digest)         |
+---------------------------------------------------------------+
       |
       v
+---------------------------------------------------------------+
|                       SPRINGBOARD OVERLAY                     |
|  VCNextOverlay.dylib (Inject: SpringBoard)                    |
|  - Float button UI, điều khiển tức thì nguồn camera           |
+---------------------------------------------------------------+
```

---

## 2. BẢNG DANH MỤC THÀNH PHẦN VÀ TRÁCH NHIỆM

| Thành phần | Đường dẫn cài đặt | Quyền thực thi | Mục tiêu can thiệp / Lắng nghe |
|---|---|---|---|
| **VCNext.app** | `/Applications/VCNext.app/VCNext` | `mobile` (Rootless) | Giao diện cấu hình nguồn phát, chọn ảnh/video, bật/tắt dịch vụ. |
| **VCNNetworkDaemon** | `/usr/libexec/VCNNetworkDaemon` | `root:wheel` (LaunchDaemon) | Quản lý mạng di động (CoreTelephony), handshake với máy chủ bản quyền `https://anix204.xyz`, tạo phiên và gia hạn `CapabilityLease.plist`. |
| **VCNStreamDaemon** | `/usr/libexec/VCNStreamDaemon` | `mobile:mobile` (LaunchDaemon) | Lắng nghe TCP port 1935, xử lý giao thức RTMP từ OBS Studio / Camera bên ngoài, ghi buffer khung hình vào `live.vcn`. |
| **VCNextCamera.dylib** | `/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib` | Kế thừa từ tiến trình cha | Inject vào `mediaserverd` (và `cameracaptured`), thực hiện hook `CMSampleBuffer`, xác thực giấy phép `CapabilityLease.plist` trước khi tráo frame. |
| **VCNextOverlay.dylib** | `/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib` | Kế thừa `SpringBoard` | Inject vào `SpringBoard`, tạo UI điều khiển nổi và đồng bộ trạng thái hiển thị. |

---

## 3. KHÔNG GIAN BỘ NHỚ VÀ TỆP TIN DÙNG CHUNG (IPC & SHARED FILES)

Thư mục gốc chia sẻ dữ liệu giữa App, Daemon và Dylib:
`/var/jb/var/mobile/Library/VCNext/`

### 3.1. Các tệp tin trạng thái & cấp phép:
1. `AuthSession.plist`: Chứa thông tin đăng nhập, token truy cập (`access_token`, `renewal_token`) và **Private Key ECDSA P-256** của thiết bị.
2. `CapabilityLease.plist`: Giấy phép được ký số từ máy chủ xác nhận quyền sử dụng tính năng camera. Tệp này được `VCNextCamera.dylib` đọc và thẩm định chữ ký.
3. `CameraConfig.plist`: Cấu hình nguồn phát được người dùng lựa chọn từ `VCNext.app` (chế độ phát: video lặp, ảnh tĩnh, hoặc RTMP live).
4. `CameraStatus.plist`: Báo cáo trạng thái của camera hook (số lượng frame đã render, tiến trình đang hook, lỗi nếu có).
5. `ServerStatus.plist`: Trạng thái máy chủ cấp phép và heartbeat.
6. `NetworkPolicy.plist`: Cấu hình can thiệp chính sách mạng của CommCenter.

### 3.2. Bộ đệm luồng phát Media:
- `Streams/live.vcn`: File đệm bộ nhớ ánh xạ (Memory-mapped buffer) trung gian giữa RTMP StreamDaemon và Camera Hook.
- `Streams/incoming.flv`: Gói tin FLV thô nhận từ cổng RTMP.
- `Media/`: Thư mục lưu trữ video MP4 và ảnh JPEG/PNG do người dùng đưa vào.

---

## 4. KÊNH TRUYỀN THÔNG BÁO HỆ THỐNG (DARWIN NOTIFICATIONS)

Tất cả các thành phần sử dụng `CFNotificationCenterGetDarwinNotifyCenter()` để đồng bộ trạng thái tức thời không cần polling:

- `com.vcnext.state.changed`: Trạng thái bật/tắt toàn cục của tweak.
- `com.vcnext.floating.changed`: Yêu cầu ẩn/hiện nút nổi trên SpringBoard.
- `com.vcnext.server.status.changed`: Máy chủ phản hồi trạng thái mới.
- `com.vcnext.camera.status.changed`: MediaServerD đã nạp hook hoặc đổi trạng thái pipeline.
- `com.vcnext.capability.changed`: File `CapabilityLease.plist` đã được cập nhật từ mạng.
- `com.vcnext.auth.session.changed`: Cặp khóa hoặc phiên xác thực đã được làm mới.
- `com.vcnext.network.apply`: Yêu cầu NetworkDaemon cấu hình lại quyền truy cập mạng di động.
