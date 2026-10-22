#!/usr/bin/env python3
"""
VCNext Custom RootHide Debian Package Builder
Đóng gói gói .deb chuẩn dpkg / Sileo cho RootHide Dopamine 2:
1. Dữ liệu: data.tar.zst chứa toàn bộ 14 slice nhị phân đã vá hoàn chỉnh và 5 POSIX symlink thật trỏ tới AutoPatches.dylib.
2. Kiểm soát: control.tar.zst với permissions chuẩn xác (control 0644, maintainer scripts 0755).
3. Định dạng AR chuẩn Debian: debian-binary (2.0), control.tar.zst, data.tar.zst.
"""

import os
import sys
import io
import time
import tarfile
import zstandard

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DEB = os.path.join(ROOT_DIR, "VCNext-custom-roothide.deb")

def make_ar_header(filename: str, size: int, mode: int = 0o100644, mtime: int = 0, uid: int = 0, gid: int = 0) -> bytes:
    """
    Sinh 60-byte header cho định dạng Debian ar archive
    """
    # File identifier (16 bytes, space padded, slash terminated)
    fn = (filename + "/").ljust(16)[:16]
    # File modification timestamp (12 bytes)
    mt = str(mtime).ljust(12)[:12]
    # Owner ID (6 bytes)
    u = str(uid).ljust(6)[:6]
    # Group ID (6 bytes)
    g = str(gid).ljust(6)[:6]
    # File mode (8 bytes octal)
    md = format(mode, "o").ljust(8)[:8]
    # File size in bytes (10 bytes decimal)
    sz = str(size).ljust(10)[:10]
    # Ending characters (2 bytes `\x60\n`)
    end = b"`\n"

    hdr = fn.encode("ascii") + mt.encode("ascii") + u.encode("ascii") + g.encode("ascii") + md.encode("ascii") + sz.encode("ascii") + end
    assert len(hdr) == 60
    return hdr

def compress_zstd(data: bytes, level: int = 19) -> bytes:
    cctx = zstandard.ZstdCompressor(level=level)
    return cctx.compress(data)

def build_package():
    print("[*] Bắt đầu quy trình đóng gói VCNext-custom-roothide.deb...")

    # 1. Nạp template metadata từ deb gốc
    orig_deb_path = os.path.join(ROOT_DIR, "VCNext-0.16.73-roothide.deb")
    with open(orig_deb_path, "rb") as f:
        orig_deb = f.read()

    # Trích xuất cấu trúc thành viên ban đầu của data.tar
    pos = 8
    orig_data_tar = None
    orig_ctrl_tar = None
    while pos < len(orig_deb):
        hdr = orig_deb[pos:pos+60]
        if len(hdr) < 60: break
        name = hdr[:16].strip().decode('ascii')
        size = int(hdr[48:58].strip())
        content = orig_deb[pos+60 : pos+60+size]
        if name == 'data.tar.zst':
            orig_data_tar = zstandard.ZstdDecompressor().decompress(content, max_output_size=100*1024*1024)
        elif name == 'control.tar.zst':
            orig_ctrl_tar = zstandard.ZstdDecompressor().decompress(content, max_output_size=10*1024*1024)
        pos += 60 + size + (size % 2)

    assert orig_data_tar is not None
    assert orig_ctrl_tar is not None

    # 2. Xây dựng data.tar mới
    data_tar_buf = io.BytesIO()
    in_tar = tarfile.open(fileobj=io.BytesIO(orig_data_tar))
    out_tar = tarfile.open(fileobj=data_tar_buf, mode="w")

    for member in in_tar.getmembers():
        # Kiểm tra nếu là file thông thường nằm trong extracted/data
        disk_rel = member.name.lstrip('./')
        disk_path = os.path.join(ROOT_DIR, "extracted", "data", disk_rel)

        if member.issym():
            # Bảo toàn nguyên vẹn 100% POSIX symlink trỏ tới AutoPatches.dylib
            ti = tarfile.TarInfo(name=member.name)
            ti.type = tarfile.SYMTYPE
            ti.linkname = member.linkname
            ti.mode = member.mode
            ti.uid = member.uid
            ti.gid = member.gid
            ti.uname = member.uname
            ti.gname = member.gname
            ti.mtime = member.mtime
            out_tar.addfile(ti)
            print(f"  [+] Added SYMLINK: {member.name} -> {member.linkname}")

        elif member.isdir():
            ti = tarfile.TarInfo(name=member.name)
            ti.type = tarfile.DIRTYPE
            ti.mode = member.mode
            ti.uid = member.uid
            ti.gid = member.gid
            ti.uname = member.uname
            ti.gname = member.gname
            ti.mtime = member.mtime
            out_tar.addfile(ti)

        elif member.isfile():
            assert os.path.exists(disk_path), f"Thiếu file trên đĩa: {disk_path}"
            with open(disk_path, "rb") as f:
                content = f.read()

            ti = tarfile.TarInfo(name=member.name)
            ti.type = tarfile.REGTYPE
            ti.size = len(content)
            ti.mode = member.mode
            ti.uid = member.uid
            ti.gid = member.gid
            ti.uname = member.uname
            ti.gname = member.gname
            ti.mtime = member.mtime
            out_tar.addfile(ti, io.BytesIO(content))

    out_tar.close()
    data_tar_bytes = data_tar_buf.getvalue()
    print(f"[+] data.tar hoàn tất ({len(data_tar_bytes)} bytes)")
    data_zst = compress_zstd(data_tar_bytes)
    print(f"[+] data.tar.zst nén zstd ({len(data_zst)} bytes)")

    # 3. Xây dựng control.tar mới
    ctrl_tar_buf = io.BytesIO()
    in_ctrl = tarfile.open(fileobj=io.BytesIO(orig_ctrl_tar))
    out_ctrl = tarfile.open(fileobj=ctrl_tar_buf, mode="w")

    for member in in_ctrl.getmembers():
        disk_rel = member.name.lstrip('./')
        disk_path = os.path.join(ROOT_DIR, "extracted", "control", disk_rel)

        if member.isdir():
            ti = tarfile.TarInfo(name=member.name)
            ti.type = tarfile.DIRTYPE
            ti.mode = member.mode
            ti.uid = member.uid
            ti.gid = member.gid
            ti.mtime = member.mtime
            out_ctrl.addfile(ti)
        elif member.isfile():
            with open(disk_path, "rb") as f:
                content = f.read()
            ti = tarfile.TarInfo(name=member.name)
            ti.type = tarfile.REGTYPE
            ti.size = len(content)
            ti.mode = member.mode
            ti.uid = member.uid
            ti.gid = member.gid
            ti.mtime = member.mtime
            out_ctrl.addfile(ti, io.BytesIO(content))

    out_ctrl.close()
    ctrl_tar_bytes = ctrl_tar_buf.getvalue()
    ctrl_zst = compress_zstd(ctrl_tar_bytes)
    print(f"[+] control.tar.zst nén zstd ({len(ctrl_zst)} bytes)")

    # 4. Đóng gói Debian AR Archive chuẩn
    ar_buf = io.BytesIO()
    ar_buf.write(b"!<arch>\n")

    # Member 1: debian-binary (size 4)
    deb_bin_data = b"2.0\n"
    ar_buf.write(make_ar_header("debian-binary", len(deb_bin_data)))
    ar_buf.write(deb_bin_data)
    if len(deb_bin_data) % 2 != 0: ar_buf.write(b"\n")

    # Member 2: control.tar.zst
    ar_buf.write(make_ar_header("control.tar.zst", len(ctrl_zst)))
    ar_buf.write(ctrl_zst)
    if len(ctrl_zst) % 2 != 0: ar_buf.write(b"\n")

    # Member 3: data.tar.zst
    ar_buf.write(make_ar_header("data.tar.zst", len(data_zst)))
    ar_buf.write(data_zst)
    if len(data_zst) % 2 != 0: ar_buf.write(b"\n")

    final_deb_bytes = ar_buf.getvalue()
    with open(OUTPUT_DEB, "wb") as f:
        f.write(final_deb_bytes)

    print(f"\n[+] XUẤT BẢN THÀNH CÔNG: {OUTPUT_DEB}")
    print(f"    Tổng kích thước: {len(final_deb_bytes):,} bytes")

if __name__ == "__main__":
    build_package()
