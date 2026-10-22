# KIẾN TRÚC & HƯỚNG DẪN VẬN HÀNH VIRTUAL CAMERA (VCAM) TRONG VCNEXT

Tài liệu hướng dẫn toàn diện về cách thức hoạt động của luồng video ảo, cơ chế phân phối khung hình và cách kết nối OBS Studio từ máy tính vào iPhone 8 Plus.

---

## 1. BẢN ĐỒ LUỒNG DỮ LIỆU STREAMING (STREAMING PIPELINE)

Trong hệ thống VCNext, chức năng Virtual Camera (Camera ảo) hoạt động theo 2 chế độ:

### CHẾ ĐỘ 1: Tệp Tin Cục Bộ (Local File Mode)
1. Người dùng mở `VCNext.app` trên iPhone, vào tab cấu hình, chọn một video MP4 hoặc ảnh tĩnh từ thư viện Photo hoặc tệp tin trong máy.
2. Tệp được lưu tại `/var/jb/var/mobile/Library/VCNext/Media/`.
3. `VCNextCamera.dylib` trong `mediaserverd` đọc tệp qua `AVAssetReader`, giải mã từng khung hình thành `CVPixelBuffer` và tráo vào `CMSampleBuffer` của camera thật theo chu kỳ lặp (loop).

---

### CHẾ ĐỘ 2: Luồng Trực Tiếp RTMP (Live RTMP Mode từ OBS Studio)
Đây là chế độ truyền hình trực tiếp luồng video từ máy tính (hoặc camera bên ngoài) thẳng vào camera iPhone theo thời gian thực (Zero Latency):

```
+-----------------------------------------------------------------------------------+
|                            MÁY TÍNH (PC / LAPTOP)                                 |
|   OBS Studio / FFmpeg / vMix                                                      |
|   - Video Encoder: H.264 (AVC) Baseline / Main Profile                           |
|   - Độ phân giải: 1080x1920 (dọc) hoặc 1920x1080 (ngang)                          |
|   - Tốc độ khung hình: 30 fps (khớp với camera iOS)                              |
+-----------------------------------------------------------------------------------+
                                  |
                                  | RTMP Stream qua TCP Port 1935 (Wi-Fi hoặc USB)
                                  v
+-----------------------------------------------------------------------------------+
|                        IPHONE 8 PLUS (DOPAMINE 2 ROOTHIDE)                        |
|                                                                                   |
|   1. VCNStreamDaemon (TCP Port 1935 Server):                                      |
|      - Lắng nghe kết nối RTMP từ OBS trên cổng 1935                               |
|      - Bóc tách Video Packet H.264 NALUs (SPS, PPS, IDR, Non-IDR)                 |
|      - Đóng gói theo chuẩn VCNL (16B) -> VCNP (24B) -> VCNT (16B)                 |
|      - Ghi liên tục vào tệp đệm chia sẻ:                                          |
|        /var/jb/var/mobile/Library/VCNext/Streams/live.vcn                         |
|                                                                                   |
|   2. VCNextCamera.dylib (Inject trong mediaserverd):                              |
|      - Hàm poll() đọc NALU từ live.vcn                                            |
|      - Khởi tạo VTDecompressionSession giải mã sang CVPixelBuffer                 |
|      - Tráo con trỏ khung hình trong hàm renderSampleBuffer:forInput:             |
|                                                                                   |
|   3. Ứng dụng Camera / Zalo / Facebook / TikTok / KYC:                            |
|      - Nhận luồng video từ OBS như thể camera vật lý đang quay!                  |
+-----------------------------------------------------------------------------------+
```

---

## 2. HƯỚNG DẪN KẾT NỐI OBS STUDIO VÀO IPHONE

### Cách 1: Kết nối trực tiếp qua mạng Wi-Fi nội bộ (Cùng mạng Wi-Fi)
1. Trên iPhone: Mở Cài đặt -> Wi-Fi -> Bấm vào chữ `(i)` cạnh mạng Wi-Fi đang kết nối để xem địa chỉ IP của iPhone (ví dụ: `192.168.1.150`).
2. Mở app **VCNext** trên iPhone:
   - Bật công tắc **Virtual Camera**.
   - Chọn chế độ nguồn phát: **RTMP Stream**.
3. Mở **OBS Studio** trên máy tính:
   - Vào **Settings** (Cài đặt) -> **Stream** (Phát luồng):
     * **Service:** Chọn `Custom...` (Tùy chỉnh).
     * **Server:** Nhập `rtmp://<IP_IPHONE>:1935/live` (Ví dụ: `rtmp://192.168.1.150:1935/live`).
     * **Stream Key:** Nhập bất kỳ chuỗi nào (Ví dụ: `stream` hoặc `live`).
   - Vào **Settings** -> **Output** (Đầu ra):
     * Video Bitrate: `2500 Kbps` - `4000 Kbps`.
     * Encoder: `x264` hoặc `NVIDIA NVENC H.264`.
   - Vào **Settings** -> **Video**:
     * Base / Output Resolution: `1080x1920` (nếu quay camera dọc điện thoại) hoặc `1920x1080` (nếu quay ngang).
     * FPS: `30`.
4. Bấm **Start Streaming** (Bắt đầu phát luồng) trên OBS Studio.
5. Trên iPhone: Mở app Camera hoặc Zalo để thấy hình ảnh từ màn hình OBS hiển thị ngay lập tức!

---

### Cách 2: Kết nối qua cáp USB (Cực kỳ ổn định, không lo lag Wi-Fi)
1. Cắm cáp USB kết nối iPhone với máy tính.
2. Dùng công cụ `iproxy` (từ gói `libimobiledevice` hoặc 3uTools) để chuyển tiếp cổng 1935:
   ```bash
   iproxy 1935 1935
   ```
3. Trong OBS Studio:
   - **Server:** Nhập `rtmp://127.0.0.1:1935/live`
   - **Stream Key:** `live`
4. Bấm **Start Streaming**: Dữ liệu video truyền trực tiếp qua cáp Lightning tốc độ cao!

---

## 3. CƠ CHẾ RELAY QUA VPS KHI PHÁT STREAM TỪ XA (OVER INTERNET)

Nếu máy tính phát OBS và iPhone ở 2 nơi khác nhau (không chung mạng Wi-Fi và không cắm cáp):
1. Có thể cài đặt một RTMP Relay Server (như **MediaMTX** hoặc **Nginx-RTMP**) trên VPS `13.238.38.121` mở cổng 1935.
2. OBS trên máy tính đẩy stream về: `rtmp://vc.huxa.xyz:1935/live/test`.
3. Trên iPhone kết nối SSH reverse tunnel hoặc kéo luồng về cổng 1935 nội bộ của `VCNStreamDaemon`.
