#!/usr/bin/env python3
"""
VCAMPLUS Commercial Debian Package Builder
Đóng gói phiên bản thương mại độc quyền VCAMPLUS:
1. Rebrand App Icon: Resizes photo_2026-06-20_20-13-18.jpg thành bộ icon chuẩn (60x60, 120x120, 180x180, 256x256).
2. Rebrand Name: Đổi CFBundleDisplayName & CFBundleName thành 'VCAMPLUS' trong Info.plist.
3. Patch Mach-O Navigation Title: Vá chuỗi 'V4HCAM Next' thành 'VCAMPLUS' (0x2c16b) và cập nhật length struct = 8 (0x35770).
4. In-place CodeDirectory Re-hash: Tính toán lại SHA-256 page hashes cho tất cả CodeDirectories (đạt 0 mismatches).
5. Giữ nguyên 100% digest __TEXT,__text ('4c10bf4d...') và toàn bộ 5 POSIX symlink AutoPatches.
6. Xuất bản tệp: dist/VCAMPLUS-roothide.deb (không ảnh hưởng tới file deb trên live server).
"""

import os
import sys
import io
import time
import tarfile
import struct
import hashlib
import plistlib
import zstandard
from PIL import Image

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))
from patch_production_binaries import update_codedirectories_in_macho

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_LOGO_PATH = r"C:\Users\Admin\Downloads\photo_2026-06-20_20-13-18.jpg"
OUTPUT_DEB = os.path.join(ROOT_DIR, "dist", "VCAMPLUS-roothide.deb")

def make_ar_header(filename: str, size: int, mode: int = 0o100644, mtime: int = 0, uid: int = 0, gid: int = 0) -> bytes:
    fn = (filename + "/").ljust(16)[:16]
    mt = str(mtime).ljust(12)[:12]
    u = str(uid).ljust(6)[:6]
    g = str(gid).ljust(6)[:6]
    md = format(mode, "o").ljust(8)[:8]
    sz = str(size).ljust(10)[:10]
    end = b"`\n"
    hdr = fn.encode("ascii") + mt.encode("ascii") + u.encode("ascii") + g.encode("ascii") + md.encode("ascii") + sz.encode("ascii") + end
    assert len(hdr) == 60
    return hdr

def compress_zstd(data: bytes, level: int = 19) -> bytes:
    cctx = zstandard.ZstdCompressor(level=level)
    return cctx.compress(data)

def generate_branded_icons(src_img_path: str) -> dict[str, bytes]:
    print(f"[*] Đang xử lý bộ icon thương hiệu từ: {src_img_path}")
    im = Image.open(src_img_path).convert("RGBA")

    icon_specs = {
        "AppIcon.png": (60, 60),
        "AppIcon@2x.png": (120, 120),
        "AppIcon@3x.png": (180, 180),
        "BrandLogo.png": (256, 256)
    }

    generated = {}
    for filename, size in icon_specs.items():
        resized = im.resize(size, Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format="PNG", optimize=True)
        generated[filename] = buf.getvalue()
        print(f"  [+] Đã sinh icon: {filename:<16} ({size[0]}x{size[1]} px, {len(generated[filename]):,} bytes)")
    return generated

def patch_app_macho(macho_bytes: bytes) -> bytes:
    data = bytearray(macho_bytes)
    # 1. Kiểm tra chuỗi gốc 'V4HCAM Next\x00' tại 0x2c16b
    assert data[0x2c16b : 0x2c16b + 12] == b"V4HCAM Next\x00", "Không tìm thấy chuỗi 'V4HCAM Next' tại 0x2c16b"
    # Ghi đè bằng 'VCAMPLUS\x00\x00\x00\x00' (8 bytes text + 4 bytes null = đúng 12 bytes)
    data[0x2c16b : 0x2c16b + 12] = b"VCAMPLUS\x00\x00\x00\x00"

    # 2. Cập nhật độ dài trong struct NSConstantString tại 0x35770 từ 11 thành 8
    old_len = struct.unpack("<Q", data[0x35770 : 0x35778])[0]
    assert old_len == 11, f"Độ dài NSConstantString không khớp: {old_len}"
    data[0x35770 : 0x35778] = struct.pack("<Q", 8)

    # 3. Tính toán và cập nhật lại toàn bộ CodeDirectory page hashes
    cds = update_codedirectories_in_macho(data)
    print(f"  [+] Đã vá tiêu đề Mach-O -> 'VCAMPLUS' và cập nhật {cds} CodeDirectories.")
    return bytes(data)

def update_info_plist(plist_bytes: bytes, fmt=plistlib.FMT_XML) -> bytes:
    pl = plistlib.loads(plist_bytes)
    pl["CFBundleDisplayName"] = "VCAMPLUS"
    pl["CFBundleName"] = "VCAMPLUS"
    return plistlib.dumps(pl, fmt=fmt)

def update_control_file(control_text: str) -> str:
    lines = control_text.splitlines()
    new_lines = []
    for line in lines:
        if line.startswith("Name:"):
            new_lines.append("Name: VCAMPLUS")
        elif line.startswith("Author:"):
            new_lines.append("Author: VCAMPLUS Team <@vcamplus>")
        elif line.startswith("Maintainer:"):
            new_lines.append("Maintainer: VCAMPLUS <@vcamplus>")
        elif line.startswith("Description:"):
            new_lines.append("Description: Tweak Virtual Camera & Live Stream chuyên nghiệp cho iOS RootHide")
        elif line.startswith("Section:"):
            new_lines.append("Section: Tweaks")
        else:
            new_lines.append(line)
    return "\n".join(new_lines) + "\n"

def build_commercial_package():
    os.makedirs(os.path.join(ROOT_DIR, "dist"), exist_ok=True)
    print(f"{'='*80}")
    print(f"{'BẮT ĐẦU ĐÓNG GÓI BẢN THƯƠNG MẠI VCAMPLUS':^80}")
    print(f"{'='*80}")

    # Sinh bộ icon mới
    branded_icons = generate_branded_icons(SRC_LOGO_PATH)

    # Nạp template từ deb gốc
    orig_deb_path = os.path.join(ROOT_DIR, "VCNext-0.16.73-roothide.deb")
    with open(orig_deb_path, "rb") as f:
        orig_deb = f.read()

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

    assert orig_data_tar is not None and orig_ctrl_tar is not None

    # 1. Xây dựng data.tar
    print("\n[*] Đang xây dựng data.tar với thương hiệu VCAMPLUS...")
    data_tar_buf = io.BytesIO()
    in_tar = tarfile.open(fileobj=io.BytesIO(orig_data_tar))
    out_tar = tarfile.open(fileobj=data_tar_buf, mode="w")

    for member in in_tar.getmembers():
        disk_rel = member.name.lstrip('./')
        disk_path = os.path.join(ROOT_DIR, "extracted", "data", disk_rel)

        if member.issym():
            # Bảo toàn 100% POSIX symlink trỏ tới AutoPatches
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
            with open(disk_path, "rb") as f:
                content = f.read()

            # A. Thay thế Icons & Logo
            base_fname = os.path.basename(member.name)
            if base_fname in branded_icons:
                content = branded_icons[base_fname]
                print(f"  [+] Đã đưa icon mới vào data.tar: {member.name}")

            # B. Cập nhật Info.plist
            elif base_fname == "Info.plist" and "VCNext.app" in member.name:
                fmt = plistlib.FMT_BINARY if "pkgmirror" in member.name else plistlib.FMT_XML
                content = update_info_plist(content, fmt=fmt)
                print(f"  [+] Đã đổi CFBundleDisplayName -> 'VCAMPLUS' trong: {member.name}")

            # C. Vá Mach-O title VCNext
            elif base_fname == "VCNext" and "VCNext.app" in member.name:
                print(f"  [*] Đang vá Mach-O VCNext cho {member.name}:")
                content = patch_app_macho(content)

            # D. Cập nhật mirror control trong pkgmirror
            elif "DEBIAN.com.vcnext.app/control" in member.name:
                content = update_control_file(content.decode("utf-8")).encode("utf-8")
                print(f"  [+] Đã cập nhật metadata VCAMPLUS trong mirror control: {member.name}")

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
    print(f"[+] data.tar hoàn tất ({len(data_tar_bytes):,} bytes)")
    data_zst = compress_zstd(data_tar_bytes)

    # 2. Xây dựng control.tar
    print("\n[*] Đang xây dựng control.tar với metadata VCAMPLUS...")
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

            if member.name in ("control", "./control"):
                text = content.decode("utf-8")
                content = update_control_file(text).encode("utf-8")
                print("  [+] Đã cập nhật metadata VCAMPLUS trong control file.")

            ti = tarfile.TarInfo(name=member.name)
            ti.type = tarfile.REGTYPE
            ti.size = len(content)
            ti.mode = member.mode
            ti.uid = member.uid
            ti.gid = member.gid
            ti.uname = member.uname
            ti.gname = member.gname
            ti.mtime = member.mtime
            out_ctrl.addfile(ti, io.BytesIO(content))

    out_ctrl.close()
    ctrl_tar_bytes = ctrl_tar_buf.getvalue()
    print(f"[+] control.tar hoàn tất ({len(ctrl_tar_bytes):,} bytes)")
    ctrl_zst = compress_zstd(ctrl_tar_bytes)

    # 3. Đóng gói Debian AR Archive chuẩn
    ar_buf = io.BytesIO()
    ar_buf.write(b"!<arch>\n")

    deb_bin_data = b"2.0\n"
    ar_buf.write(make_ar_header("debian-binary", len(deb_bin_data)))
    ar_buf.write(deb_bin_data)
    if len(deb_bin_data) % 2 != 0: ar_buf.write(b"\n")

    ar_buf.write(make_ar_header("control.tar.zst", len(ctrl_zst)))
    ar_buf.write(ctrl_zst)
    if len(ctrl_zst) % 2 != 0: ar_buf.write(b"\n")

    ar_buf.write(make_ar_header("data.tar.zst", len(data_zst)))
    ar_buf.write(data_zst)
    if len(data_zst) % 2 != 0: ar_buf.write(b"\n")

    final_deb_bytes = ar_buf.getvalue()
    with open(OUTPUT_DEB, "wb") as f:
        f.write(final_deb_bytes)

    print(f"\n{'='*80}")
    print(f"XUẤT BẢN THÀNH CÔNG GÓI THƯƠNG MẠI: {OUTPUT_DEB}")
    print(f"Kích thước tệp: {len(final_deb_bytes):,} bytes")
    print(f"Mã băm SHA-256: {hashlib.sha256(final_deb_bytes).hexdigest()}")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    build_commercial_package()
