#!/usr/bin/env python3
"""
VCNext Binary Authority Patcher (v2 - Length Preserved & Full Package Aligned)
Thay thế khối mã hóa Tag 2 (Thumbprint PKCS#1) và Tag 3 (Certificate RSA-3072 1071B)
trong phân vùng __TEXT,__const của cả 10 file thực thi (14 slices).

Khắc phục 100% các phát hiện từ Codex:
1. Bảo toàn nguyên vẹn 9 trường độ dài (length metadata fields) bên trong khối 1384 bytes.
2. Tag 2 thumbprint được tính trên định dạng PKCS#1 (khớp SecKeyCopyExternalRepresentation trên iOS).
3. Hỗ trợ đầy đủ cả 5 file chính và 5 file pkgmirror (14 offsets).
4. Kiểm tra giải mã native-style bằng cách đọc độ dài trực tiếp từ nhị phân.
5. Giữ nguyên 100% phân vùng __TEXT,__text trên mọi slice.
"""

import os
import sys
import hashlib
import struct
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))
from crypto_engine import encrypt_payload_block, decrypt_payload_block, MASTER_KEY

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KEY_PATH = os.path.join(ROOT_DIR, "mocks/test_server_private_key.pem")

TARGET_FILES = {
    # 5 file chính
    "extracted/data/usr/libexec/VCNNetworkDaemon": [0xa2c8],
    "extracted/data/usr/libexec/VCNStreamDaemon": [0x11238],
    "extracted/data/Applications/VCNext.app/VCNext": [0x2b288],
    "extracted/data/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib": [0x1a778, 0x4b0f8],
    "extracted/data/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib": [0x15768, 0x3e2a8],
    # 5 file pkgmirror tương ứng
    "extracted/data/var/mobile/Library/pkgmirror/usr/libexec/VCNNetworkDaemon": [0xa2c8],
    "extracted/data/var/mobile/Library/pkgmirror/usr/libexec/VCNStreamDaemon": [0x11238],
    "extracted/data/var/mobile/Library/pkgmirror/Applications/VCNext.app/VCNext": [0x2b288],
    "extracted/data/var/mobile/Library/pkgmirror/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib": [0x1a778, 0x4b0f8],
    "extracted/data/var/mobile/Library/pkgmirror/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib": [0x15768, 0x3e2a8]
}
TARGET_OFFSETS = TARGET_FILES

LENGTH_OFFSETS = [0x10, 0x28, 0x40, 0x88, 0xb0, 0xc8, 0xe0, 0xf8, 0x540]
EXPECTED_LENGTHS = [16, 16, 16, 64, 32, 16, 16, 16, 1088]

def generate_1071_byte_certificate(priv_key: rsa.RSAPrivateKey) -> tuple[bytes, bytes]:
    """
    Sinh chứng chỉ X.509 DER đúng chuẩn 1071 bytes và thumbprint PKCS#1 chuẩn Apple
    """
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'VCNext Main Online Signing'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'A' * 37)
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'VCNext Main Online Signing'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'A' * 37)
    ]))
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    builder = builder.serial_number(12345678901234567890)
    builder = builder.public_key(priv_key.public_key())
    cert = builder.sign(priv_key, hashes.SHA256())
    der = cert.public_bytes(serialization.Encoding.DER)
    assert len(der) == 1071, f"Kích thước DER không chuẩn: {len(der)} (cần 1071)"

    # PKCS#1 format (khớp với SecKeyCopyExternalRepresentation trên iOS Security framework)
    pkcs1_bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )
    thumbprint_32 = hashlib.sha256(pkcs1_bytes).digest()
    assert len(thumbprint_32) == 32

    # Đồng bộ ra thư mục mocks
    mocks_dir = os.path.join(ROOT_DIR, "mocks")
    os.makedirs(mocks_dir, exist_ok=True)
    with open(os.path.join(mocks_dir, "custom_server_cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(mocks_dir, "custom_server_cert.der"), "wb") as f:
        f.write(der)
    with open(os.path.join(mocks_dir, "custom_server_public_key.pem"), "wb") as f:
        f.write(cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return der, thumbprint_32

def build_replacement_block(arg1, arg2, arg3=None) -> bytes:
    """
    Tạo khối nhị phân 1384 bytes, bảo toàn tuyệt đối 9 trường length metadata.
    Hỗ trợ cả 2 chữ ký hàm:
    - build_replacement_block(der_1071, thumbprint_32)
    - build_replacement_block(template_block, der_1071, thumbprint_32)
    """
    if arg3 is None:
        der_1071 = arg1
        thumbprint_32 = arg2
        # Tự tìm template block từ tệp gốc
        template_path = "extracted/data/usr/libexec/VCNNetworkDaemon"
        if not os.path.exists(template_path):
            alt_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "extracted/data/usr/libexec/VCNNetworkDaemon"))
            if os.path.exists(alt_path):
                template_path = alt_path
        with open(template_path, "rb") as f:
            template_block = f.read()[0xa2c8 : 0xa830]
    else:
        template_block = arg1
        der_1071 = arg2
        thumbprint_32 = arg3

    assert len(template_block) == 1384
    block = bytearray(template_block)

    # 1. Mã hóa Tag 2 (Thumbprint PKCS#1)
    s2, iv1_2, iv2_2, ct2, mac2 = encrypt_payload_block(2, thumbprint_32)
    block[0:16] = s2
    block[24:40] = iv2_2
    block[48:64] = iv1_2
    block[72:136] = ct2
    block[144:176] = mac2

    # 2. Mã hóa Tag 3 (Certificate DER 1071B)
    s3, iv1_3, iv2_3, ct3, mac3 = encrypt_payload_block(3, der_1071)
    block[184:200] = s3
    block[208:224] = iv2_3
    block[232:248] = iv1_3
    block[256:1344] = ct3
    block[1352:1384] = mac3

    # Kiểm tra xác nhận 9 trường length không bị ghi đè
    for off, exp in zip(LENGTH_OFFSETS, EXPECTED_LENGTHS):
        val = struct.unpack('<Q', block[off : off + 8])[0]
        assert val == exp, f"Length field tại +0x{off:x} bị sai lệch: {val} != {exp}"

    return bytes(block)

def verify_native_block_decryption(block: bytes, expected_cert: bytes, expected_thumbprint: bytes) -> bool:
    """
    Kiểm tra giải mã theo đúng cơ chế mà nhị phân native thực hiện (đọc độ dài từ block)
    """
    try:
        # Tag 2:
        t2_salt_len = struct.unpack('<Q', block[0x10:0x18])[0]
        t2_iv2_len = struct.unpack('<Q', block[0x28:0x30])[0]
        t2_iv1_len = struct.unpack('<Q', block[0x40:0x48])[0]
        t2_ct_len = struct.unpack('<Q', block[0x88:0x90])[0]
        t2_mac_len = struct.unpack('<Q', block[0xb0:0xb8])[0]

        dec_tp = decrypt_payload_block(
            2,
            block[0 : t2_salt_len],
            block[48 : 48 + t2_iv1_len],
            block[24 : 24 + t2_iv2_len],
            block[72 : 72 + t2_ct_len],
            block[144 : 144 + t2_mac_len]
        )
        assert dec_tp == expected_thumbprint, "Tag 2 thumbprint giải mã không khớp"

        # Tag 3:
        t3_salt_len = struct.unpack('<Q', block[0xc8:0xd0])[0]
        t3_iv2_len = struct.unpack('<Q', block[0xe0:0xe8])[0]
        t3_iv1_len = struct.unpack('<Q', block[0xf8:0x100])[0]
        t3_ct_len = struct.unpack('<Q', block[0x540:0x548])[0]
        t3_mac_len = 32

        dec_cert = decrypt_payload_block(
            3,
            block[184 : 184 + t3_salt_len],
            block[232 : 232 + t3_iv1_len],
            block[208 : 208 + t3_iv2_len],
            block[256 : 256 + t3_ct_len],
            block[1352 : 1352 + t3_mac_len]
        )
        assert dec_cert == expected_cert, "Tag 3 cert giải mã không khớp"
        return True
    except Exception as e:
        print(f"[-] Lỗi giải mã native block: {e}")
        return False

def patch_all_binaries(dry_run: bool = True):
    print(f"[*] Bắt đầu quy trình vá khối mã hóa Certificate & Thumbprint (v2)...")
    print(f"    Chế độ: {'DRY-RUN (Kiểm tra thử nghiệm)' if dry_run else 'APPLY (Áp dụng ghi đè)'}")

    with open(KEY_PATH, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    der_cert, thumbprint = generate_1071_byte_certificate(priv_key)
    print(f"[+] Đã sinh chứng chỉ X.509 DER: {len(der_cert)} bytes")
    print(f"[+] PKCS#1 Thumbprint (Apple SecKeyCopyExternalRepresentation): {thumbprint.hex()}")

    # Lấy template block chuẩn từ VCNNetworkDaemon
    template_path = "extracted/data/usr/libexec/VCNNetworkDaemon"
    with open(template_path, "rb") as f:
        template_block = f.read()[0xa2c8 : 0xa830]

    rep_block = build_replacement_block(der_cert, thumbprint)
    assert len(rep_block) == 1384

    # Kiểm tra giải mã native block
    assert verify_native_block_decryption(rep_block, der_cert, thumbprint)
    print("[+] Kiểm tra native-style length decryption trên block mới: 100% HỢP LỆ.")

    total_slices_verified = 0

    # Nạp chứng chỉ gốc và thumbprint gốc để kiểm tra các slice trước khi vá
    orig_cert_path = os.path.join(ROOT_DIR, "mocks/server_cert.pem")
    with open(orig_cert_path, "rb") as f:
        orig_cert_obj = x509.load_pem_x509_certificate(f.read())
        orig_der = orig_cert_obj.public_bytes(serialization.Encoding.DER)
    orig_thumbprint = bytes.fromhex("273b81f5e79116c3a4fe4ce1743482baf1418485d2aea0ed76226ff60c0e4572")

    for path, offsets in TARGET_FILES.items():
        if not os.path.exists(path):
            print(f"[-] LỖI THIẾU TỆP: {path}")
            sys.exit(1)

        with open(path, "rb") as f:
            data = bytearray(f.read())

        print(f"\n[*] Kiểm tra tệp: {path}")
        for off in offsets:
            orig_slice = bytes(data[off : off + 1384])
            # Thẩm định vị trí gốc bằng cách giải mã trực tiếp với độ dài trong block
            if not verify_native_block_decryption(orig_slice, orig_der, orig_thumbprint):
                print(f"  [-] LỖI XÁC THỰC BLOCK GỐC tại offset 0x{off:x}")
                sys.exit(1)
            print(f"  [+] Đã xác thực offset 0x{off:x} (1384 bytes, 9 lengths preserved, HMAC verified)")
            total_slices_verified += 1

            if not dry_run:
                data[off : off + 1384] = rep_block

        if not dry_run:
            with open(path, "wb") as f:
                f.write(data)
            print(f"  [+] ĐÃ VÁ THÀNH CÔNG: {path}")

    print(f"\n[+] Tổng số slices đã thẩm định: {total_slices_verified}/14 slices trên 10 file.")
    if dry_run:
        print("[*] Kiểm tra hoàn tất ở chế độ DRY-RUN. Sử dụng --apply để ghi đè.")

patch_binaries = patch_all_binaries

if __name__ == "__main__":
    is_dry = "--apply" not in sys.argv
    patch_all_binaries(dry_run=is_dry)
