# TẦNG 4: ĐẶC TẢ ĐIỀU PHỐI VIDEO, IPC BUFFER & HOOK ENGINE (LAYER 4 SPEC)
Thành phần phân tích: `VCNStreamDaemon`, `VCNextCamera.dylib`, tệp đệm `live.vcn`

---

## 1. TỔNG QUAN LUỒNG DỮ LIỆU VIDEO (END-TO-END PIPELINE)

```
[OBS Studio / RTMP Client]
          |  (Port 1935 - H.264 NALUs qua RTMP)
          v
[VCNStreamDaemon (usr/libexec/VCNStreamDaemon)]
          |  1. Nhận gói RTMP, bóc tách Video Tag
          |  2. Đóng gói theo chuẩn VCNL / VCNP / VCNT
          |  3. Ghi vào tệp đệm chia sẻ:
          v
[/var/jb/var/mobile/Library/VCNext/Streams/live.vcn]
          |  (Đọc tuần tự qua pread / stat polling)
          v
[VCNextCamera.dylib (Inject: mediaserverd)]
          |  1. Class VCNac4cead4ba5e6d7a15fe: poll() đọc NALU
          |  2. Khởi tạo VTDecompressionSession giải mã sang CVPixelBuffer
          |  3. Class VCNd322545034651df4a1c9: renderImage:intoBGRAPixelBuffer:
          |  4. Hook Trampoline (0x6694) tráo CMSampleBuffer trong mediaserverd
          v
[AVCaptureSession / Ứng dụng người dùng (Camera Feed Mới)]
```

---

## 2. ĐẶC TẢ GIAO THỨC TỆP ĐỆM `live.vcn`

Tệp `live.vcn` được thiết kế theo mô hình stream tệp nhị phân có framing hai đầu (dual-framing packet protocol) để đảm bảo không nạp frame bị lỗi hoặc frame chưa ghi xong:

### 2.1. File Header (16 bytes):
Nằm tại byte `0x00` của tệp, được ghi bởi Daemon (`0x10000517c`) và thẩm định bởi Camera Hook (`0xe32c`):

| Offset | Chiều dài | Kiểu dữ liệu | Giá trị / Ý nghĩa |
|---|---|---|---|
| `0x00` | 4 bytes | ASCII Magic | `0x56434e4c` (`VCNL` - VCNext Live) |
| `0x04` | 2 bytes | uint16_t | Phiên bản giao thức (`0x0001`) |
| `0x06` | 2 bytes | uint16_t | Chiều dài File Header (`0x0010` = 16) |
| `0x08` | 8 bytes | uint64_t | Stream Generation / Inode number |

### 2.2. Packet Header (24 bytes):
Được gắn ở đầu mỗi khung hình NALU H.264 (`0xed04`):

| Offset | Chiều dài | Kiểu dữ liệu | Giá trị / Ý nghĩa |
|---|---|---|---|
| `0x00` | 4 bytes | ASCII Magic | `0x56434e50` (`VCNP` - VCNext Packet) |
| `0x04` | 2 bytes | uint16_t | Chiều dài Packet Header (`0x0018` = 24) |
| `0x06` | 2 bytes | uint16_t | Tag Type (`0x0009` = Video Frame) |
| `0x08` | 8 bytes | uint64_t | Monotonic Frame Sequence ID |
| `0x10` | 4 bytes | uint32_t | Chiều dài Payload NALU (bytes) |
| `0x14` | 4 bytes | uint32_t | Cờ thuộc tính (KeyFrame, Timestamp offset) |

### 2.3. Packet Payload:
- Dữ liệu byte H.264 thô (Annex-B hoặc AVCC NALUs: SPS, PPS, IDR Slice, Non-IDR Slice).

### 2.4. Packet Trailer (16 bytes):
Nằm ngay sau Payload, dùng để xác thực tính toàn vẹn trước khi giải mã (`0xeef4`):

| Offset | Chiều dài | Kiểu dữ liệu | Giá trị / Ý nghĩa |
|---|---|---|---|
| `0x00` | 4 bytes | ASCII Magic | `0x56434e54` (`VCNT` - VCNext Trailer) |
| `0x04` | 4 bytes | uint32_t | Chiều dài Payload (BẮT BUỘC bằng Header Offset `0x10`) |
| `0x08` | 8 bytes | uint64_t | Frame Sequence ID (BẮT BUỘC bằng Header Offset `0x08`) |

---

## 3. KIẾN TRÚC HOOK ENGINE TRONG `VCNextCamera.dylib`

### 3.1. Danh mục các Node Celestial / CoreMedia bị can thiệp:
Tweak không can thiệp ở tầng UI mà hook trực tiếp vào đồ thị xử lý tín hiệu camera của Apple (Celestial CoreMedia Capture Graph):
- `BWPreviewSinkNode` (Xử lý frame preview ra màn hình)
- `BWStillImageSampleBufferSinkNode` (Xử lý chụp ảnh tĩnh)
- Selector chính bị hook: `renderSampleBuffer:forInput:`

### 3.2. Cấu trúc Mảng Trampoline 20 Điểm (20-Slot Trampoline Table):
- Bắt đầu từ offset `0x6b68` đến `0x710c`.
- Mỗi trampoline chiếm 0x4c (76 bytes) mã máy ARM64.
- Mỗi slot đóng vai trò là một proxy IMP độc lập truyền thông tin định danh class vào bộ điều phối trung tâm:
  - Gọi vào Universal Dispatcher tại `0x6694`.
  - Lưu trữ con trỏ IMP gốc vào mảng `0x26290`.

### 3.3. Quy trình Tráo Frame tại `0x6694`:
1. Kiểm tra cờ toàn cục `injectionEnabled` tại `0x26ea0`. Nếu tắt, gọi thẳng IMP gốc.
2. Trích xuất buffer ảnh gốc bằng `CMSampleBufferGetImageBuffer(x24)`.
3. Kiểm tra Pixel Format:
   - Hợp lệ: `BGRA` (`0x42475241`), `420v` (`0x32307834`), `420f` (`0x32307866`).
   - Bất thường: Bỏ qua tráo, tăng biến đếm `replacementFormatMismatches` và gọi camera thật.
4. Gọi `0x6844` để lấy frame ảo từ hàng đợi giải mã.
5. Sao chép Metadata và Attachment (PTS, Duration, Exposure) từ `CMSampleBuffer` gốc sang frame mới qua `CMCopyDictionaryOfAttachments` và `CMSetAttachments`.
6. Tráo con trỏ buffer và gọi IMP gốc bằng `blr x21`.

---

## 4. TƯƠNG THÍCH ĐẶC THÙ VỚI DOPAMINE 2 ROOTHIDE

### 4.1. Hệ thống tệp ảo RootHide (`/var/jb`):
Toàn bộ tệp tin cấu hình, socket và IPC bắt buộc phải giải quyết qua đường dẫn RootHide (`jbroot`):
- Đường dẫn chuẩn: `/var/jb/var/mobile/Library/VCNext/`
- Các liên kết tượng trưng `.roothidepatch.symlink` đi kèm các binary đảm bảo `PatchLoader` của RootHide có thể nạp lại và ký lại dylib khi khởi động hệ thống.

### 4.2. Xử lý PAC trên iOS 15/16 arm64e:
- `postinst` của gói cài đặt đã phải xử lý riêng cho `iPhone12,*` (A13 Bionic - iPhone 11 series) bằng cách ép cấu hình `VCNextCamera.plist` chỉ inject vào `mediaserverd`, loại bỏ các target khác để tránh xung đột PAC trap.
- Khi biên dịch hoặc patch dylib, bắt buộc phải dùng công cụ của RootHide Toolchain (`jtool2` / `ldid` với cờ signing tương thích RootHide) để không làm hỏng ptrauth.
