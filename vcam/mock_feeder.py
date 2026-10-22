#!/usr/bin/env python3
"""
VCNext Direct Video Feeder (Mock Streamer without OBS)
Đọc tệp video H.264 Annex-B, tự động đóng gói theo đúng chuẩn giao thức VCNext:
- Header tệp: VCNL (16 bytes)
- Packet Header: VCNP (24 bytes)
- Packet Trailer: VCNT (16 bytes)
Ghi liên tục vào tệp đệm live.vcn để kiểm tra camera ảo hoạt động trực tiếp.
"""

import sys
import os
import time
import struct

VCNL_MAGIC = 0x56434e4c # 'VCNL'
VCNP_MAGIC = 0x56434e50 # 'VCNP'
VCNT_MAGIC = 0x56434e54 # 'VCNT'

def make_file_header(seq: int = 1) -> bytes:
    # 16 bytes: magic (4), version (2), header_len (2), inode/generation (8)
    return struct.pack('<IHHI', VCNL_MAGIC, 1, 16, 0) + struct.pack('<Q', seq)

def make_packet_header(seq: int, payload_len: int, is_keyframe: bool = False) -> bytes:
    # 24 bytes:
    # +0x00: VCNP (4B)
    # +0x04: header_len = 24 (2B)
    # +0x06: tag_type = 9 (video) (2B)
    # +0x08: sequence_id (8B)
    # +0x10: payload_len (4B)
    # +0x14: flags (4B)
    flags = 1 if is_keyframe else 0
    return struct.pack('<IHHI', VCNP_MAGIC, 24, 9, 0) + struct.pack('<QI', seq, payload_len) + struct.pack('<I', flags)

def make_packet_trailer(seq: int, payload_len: int) -> bytes:
    # 16 bytes:
    # +0x00: VCNT (4B)
    # +0x04: payload_len (4B) - BẮT BUỘC bằng payload_len ở header
    # +0x08: sequence_id (8B) - BẮT BUỘC bằng sequence_id ở header
    return struct.pack('<IIQ', VCNT_MAGIC, payload_len, seq)

def parse_annex_b_nalus(data: bytes):
    """
    Tách các NALU H.264 dạng start-code 0x000001 hoặc 0x00000001
    """
    nalus = []
    i = 0
    start = -1
    while i < len(data) - 4:
        if data[i:i+3] == b'\x00\x00\x01':
            if start != -1:
                nalus.append(data[start:i])
            start = i + 3
            i += 3
        elif data[i:i+4] == b'\x00\x00\x00\x01':
            if start != -1:
                nalus.append(data[start:i])
            start = i + 4
            i += 4
        else:
            i += 1
    if start != -1 and start < len(data):
        nalus.append(data[start:])
    return nalus

def feed_video_to_vcn(h264_path: str, output_vcn_path: str, fps: int = 30):
    print(f"[*] Bắt đầu đọc tệp H.264: {h264_path}")
    print(f"    Ghi luồng vào tệp đệm: {output_vcn_path}")
    print(f"    Tốc độ khung hình    : {fps} FPS")

    with open(h264_path, "rb") as f:
        raw_video = f.read()

    nalus = parse_annex_b_nalus(raw_video)
    print(f"[+] Tìm thấy {len(nalus)} NALU frames trong tệp.")

    os.makedirs(os.path.dirname(os.path.abspath(output_vcn_path)), exist_ok=True)
    out_f = open(output_vcn_path, "wb")

    # 1. Ghi file header VCNL
    out_f.write(make_file_header(seq=1))
    out_f.flush()

    seq = 1
    frame_interval = 1.0 / fps

    print("[*] Đang đẩy khung hình theo thời gian thực (Bấm Ctrl+C để dừng)...")
    try:
        while True:
            for nalu in nalus:
                t0 = time.time()
                nalu_type = nalu[0] & 0x1f
                is_key = (nalu_type in (5, 7, 8)) # IDR, SPS, PPS

                # Đóng gói packet
                pkt_hdr = make_packet_header(seq, len(nalu), is_key)
                pkt_trl = make_packet_trailer(seq, len(nalu))

                out_f.write(pkt_hdr + nalu + pkt_trl)
                out_f.flush()
                seq += 1

                elapsed = time.time() - t0
                sleep_time = max(0.001, frame_interval - elapsed)
                time.sleep(sleep_time)
    except KeyboardInterrupt:
        print("\n[*] Đã dừng feeder.")
    finally:
        out_f.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Sử dụng: python mock_feeder.py <input.h264> <output_live.vcn> [fps]")
        sys.exit(0)

    fps_val = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    feed_video_to_vcn(sys.argv[1], sys.argv[2], fps=fps_val)
