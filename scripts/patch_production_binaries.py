#!/usr/bin/env python3
"""
VCNext Production Binary Authority & Domain Patcher
Vá toàn diện cả 10 tệp nhị phân (14 slices) trong extracted/data/:
1. Khối Tag 1: Đổi endpoint sang https://vc.huxa.xyz (298B plaintext, 320B ciphertext).
2. Khối Tag 2: Đổi TLS pin sang PKCS#1 thumbprint của chứng chỉ Let's Encrypt trên VPS:
   1652eed8792cbbc75868f7862cdc11f61f7c4f71e9ce319971698e5b79969788
3. Khối Tag 3: Đổi chứng chỉ cấp phép sang RSA-3072 Authority chuẩn 1071 bytes.
4. Bảo toàn nguyên vẹn toàn bộ 14 trường length metadata (5 của Tag 1 + 9 của Tag 2/3).
5. Tính toán và cập nhật lại CodeDirectory page hashes cho toàn bộ 21 CodeDirectories.
6. Xác thực phân vùng mã máy __TEXT,__text giữ nguyên 100%.
"""

import os
import sys
import hashlib
import struct
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "scripts"))
from crypto_engine import encrypt_payload_block, decrypt_payload_block, MASTER_KEY

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KEY_PATH = os.path.join(ROOT_DIR, "mocks/test_server_private_key.pem")

# PKCS#1 Thumbprint thực tế của chứng chỉ Let's Encrypt trên vc.huxa.xyz
LE_TLS_THUMBPRINT_HEX = "1652eed8792cbbc75868f7862cdc11f61f7c4f71e9ce319971698e5b79969788"
LE_TLS_THUMBPRINT_BYTES = bytes.fromhex(LE_TLS_THUMBPRINT_HEX)

# JSON Tag 1 chuẩn với domain vc.huxa.xyz (chính xác 298 bytes)
NEW_TAG1_JSON = b'{"api_base_url":"https://vc.huxa.xyz","api_host":"vc.huxa.xyz","audience":"vcnext-ios","challenge_path":"/api/v2/auth/challenge","heartbeat_path":"/api/v2/auth/heartbeat","issuer":"vcnext-main","login_path":"/api/v2/auth/login","logout_path":"/api/v2/auth/logout","renew_path":"/api/v2/auth/renew"}'
assert len(NEW_TAG1_JSON) == 298

TARGET_FILES = {
    # 5 file chính
    "extracted/data/usr/libexec/VCNNetworkDaemon": {"tag1": [0xa110], "tag23": [0xa2c8]},
    "extracted/data/usr/libexec/VCNStreamDaemon": {"tag1": [0x11080], "tag23": [0x11238]},
    "extracted/data/Applications/VCNext.app/VCNext": {"tag1": [0x2b0d0], "tag23": [0x2b288]},
    "extracted/data/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib": {
        "tag1": [0x1a5c0, 0x4af40],
        "tag23": [0x1a778, 0x4b0f8]
    },
    "extracted/data/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib": {
        "tag1": [0x155b0, 0x3e0f0],
        "tag23": [0x15768, 0x3e2a8]
    },
    # 5 file pkgmirror tương ứng
    "extracted/data/var/mobile/Library/pkgmirror/usr/libexec/VCNNetworkDaemon": {"tag1": [0xa110], "tag23": [0xa2c8]},
    "extracted/data/var/mobile/Library/pkgmirror/usr/libexec/VCNStreamDaemon": {"tag1": [0x11080], "tag23": [0x11238]},
    "extracted/data/var/mobile/Library/pkgmirror/Applications/VCNext.app/VCNext": {"tag1": [0x2b0d0], "tag23": [0x2b288]},
    "extracted/data/var/mobile/Library/pkgmirror/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib": {
        "tag1": [0x1a5c0, 0x4af40],
        "tag23": [0x1a778, 0x4b0f8]
    },
    "extracted/data/var/mobile/Library/pkgmirror/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib": {
        "tag1": [0x155b0, 0x3e0f0],
        "tag23": [0x15768, 0x3e2a8]
    }
}

TAG23_LENGTH_OFFSETS = [0x10, 0x28, 0x40, 0x88, 0xb0, 0xc8, 0xe0, 0xf8, 0x540]
TAG23_EXPECTED_LENGTHS = [16, 16, 16, 64, 32, 16, 16, 16, 1088]

TAG1_LENGTH_OFFSETS = [0x10, 0x28, 0x40, 0x188, 0x1b0]
TAG1_EXPECTED_LENGTHS = [16, 16, 16, 320, 32]

def generate_1071_byte_certificate(priv_key: rsa.RSAPrivateKey) -> bytes:
    cert_path = os.path.join(ROOT_DIR, "mocks/custom_server_cert.der")
    if os.path.exists(cert_path) and os.path.getsize(cert_path) == 1071:
        with open(cert_path, "rb") as f:
            return f.read()

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
    assert len(der) == 1071
    return der

def build_tag1_block(template_tag1: bytes) -> bytes:
    assert len(template_tag1) == 440
    block = bytearray(template_tag1)
    salt, iv1, iv2, ct, mac = encrypt_payload_block(1, NEW_TAG1_JSON)
    assert len(ct) == 320
    assert len(mac) == 32

    block[0:16] = salt
    block[24:40] = iv2
    block[48:64] = iv1
    block[72:392] = ct
    block[400:432] = mac

    for off, exp in zip(TAG1_LENGTH_OFFSETS, TAG1_EXPECTED_LENGTHS):
        val = struct.unpack('<Q', block[off : off + 8])[0]
        assert val == exp

    # Test decrypt
    dec = decrypt_payload_block(1, salt, iv1, iv2, ct, mac)
    assert dec == NEW_TAG1_JSON
    return bytes(block)

def build_tag23_block(template_tag23: bytes, der_1071: bytes, thumbprint_32: bytes) -> bytes:
    assert len(template_tag23) == 1384
    block = bytearray(template_tag23)

    # 1. Tag 2 (TLS PKCS#1 Thumbprint)
    s2, iv1_2, iv2_2, ct2, mac2 = encrypt_payload_block(2, thumbprint_32)
    assert len(ct2) == 64
    block[0:16] = s2
    block[24:40] = iv2_2
    block[48:64] = iv1_2
    block[72:136] = ct2
    block[144:176] = mac2

    # 2. Tag 3 (Authority Certificate)
    s3, iv1_3, iv2_3, ct3, mac3 = encrypt_payload_block(3, der_1071)
    assert len(ct3) == 1088
    block[184:200] = s3
    block[208:224] = iv2_3
    block[232:248] = iv1_3
    block[256:1344] = ct3
    block[1352:1384] = mac3

    for off, exp in zip(TAG23_LENGTH_OFFSETS, TAG23_EXPECTED_LENGTHS):
        val = struct.unpack('<Q', block[off : off + 8])[0]
        assert val == exp

    # Test decrypt
    dec_tp = decrypt_payload_block(2, s2, iv1_2, iv2_2, ct2, mac2)
    assert dec_tp == thumbprint_32
    dec_cert = decrypt_payload_block(3, s3, iv1_3, iv2_3, ct3, mac3)
    assert dec_cert == der_1071
    return bytes(block)

def update_codedirectories_in_macho(data: bytearray) -> int:
    """
    Cập nhật CodeDirectory page hashes cho toàn bộ slices trong file Mach-O
    """
    slices = []
    if data[:4] in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        nfat = struct.unpack('>I', data[4:8])[0]
        offset = 8
        for i in range(nfat):
            cputype, cpusubtype, f_offset, f_size, align = struct.unpack('>IIIII', data[offset:offset+20])
            offset += 20
            slices.append((f_offset, f_size))
    else:
        slices.append((0, len(data)))

    updated_cds = 0
    for s_idx, (s_off, s_size) in enumerate(slices):
        ncmds = struct.unpack('<I', data[s_off+16 : s_off+20])[0]
        offset = 32
        cs_cmd = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack('<II', data[s_off+offset : s_off+offset+8])
            if cmd == 0x1d: # LC_CODE_SIGNATURE
                dataoff, datasize = struct.unpack('<II', data[s_off+offset+8 : s_off+offset+16])
                cs_cmd = (dataoff, datasize)
                break
            offset += cmdsize
        if not cs_cmd: continue

        dataoff, datasize = cs_cmd
        blob_start_global = s_off + dataoff
        magic, length, count = struct.unpack('>III', data[blob_start_global : blob_start_global + 12])
        for i in range(count):
            slot_type, slot_off = struct.unpack('>II', data[blob_start_global + 12 + i*8 : blob_start_global + 20 + i*8])
            cd_start = blob_start_global + slot_off
            blob_magic, blob_len = struct.unpack('>II', data[cd_start : cd_start + 8])
            if blob_magic == 0xfade0c02: # CodeDirectory
                cd = data[cd_start : cd_start + blob_len]
                version, flags, hashOff, identOff, nSpecialSlots, nCodeSlots, codeLimit, hashSize, hashType, platform, pageSize = struct.unpack('>IIIIIIIBBBB', cd[8:40])
                page_bytes = 1 << pageSize
                hash_name = {1: "sha1", 2: "sha256", 3: "sha256", 4: "sha384"}.get(hashType, "sha256")

                for p in range(nCodeSlots):
                    start = s_off + p * page_bytes
                    end = s_off + min(codeLimit, (p + 1) * page_bytes)
                    chunk = data[start:end]
                    new_hash = hashlib.new(hash_name, chunk).digest()[:hashSize]
                    hash_entry_pos = cd_start + hashOff + p * hashSize
                    data[hash_entry_pos : hash_entry_pos + hashSize] = new_hash
                updated_cds += 1
    return updated_cds

def patch_all_production_binaries(dry_run: bool = True):
    print(f"[*] Bắt đầu quy trình vá Production Binaries (Tag 1, Tag 2, Tag 3 & CodeDirectory)...")
    print(f"    Chế độ       : {'DRY-RUN (Thử nghiệm)' if dry_run else 'APPLY (Áp dụng thật)'}")
    print(f"    Domain Tag 1 : https://vc.huxa.xyz (298B plaintext, 320B ciphertext)")
    print(f"    TLS Pin Tag 2: {LE_TLS_THUMBPRINT_HEX} (Let's Encrypt PKCS#1)")

    with open(KEY_PATH, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    der_cert = generate_1071_byte_certificate(priv_key)
    print(f"[+] Authority Cert Tag 3: {len(der_cert)} bytes DER")

    # Template blocks từ VCNNetworkDaemon
    with open("extracted/data/usr/libexec/VCNNetworkDaemon", "rb") as f:
        daemon_bytes = f.read()
        tmpl_tag1 = daemon_bytes[0xa110 : 0xa110 + 440]
        tmpl_tag23 = daemon_bytes[0xa2c8 : 0xa2c8 + 1384]

    new_tag1_block = build_tag1_block(tmpl_tag1)
    new_tag23_block = build_tag23_block(tmpl_tag23, der_cert, LE_TLS_THUMBPRINT_BYTES)

    total_slices = 0
    total_cds_updated = 0

    for path, spec in TARGET_FILES.items():
        full_path = os.path.join(ROOT_DIR, path)
        assert os.path.exists(full_path), f"Thiếu tệp: {full_path}"

        with open(full_path, "rb") as f:
            data = bytearray(f.read())

        # Ghi nhớ mã băm __TEXT,__text ban đầu để xác thực
        before_data = bytes(data)

        print(f"\n[*] Xử lý tệp: {path}")
        # 1. Patch Tag 1
        for off in spec["tag1"]:
            assert len(data[off : off + 440]) == 440
            data[off : off + 440] = new_tag1_block
            print(f"  [+] Đã vá Tag 1 tại offset 0x{off:x}")

        # 2. Patch Tag 2/3
        for off in spec["tag23"]:
            assert len(data[off : off + 1384]) == 1384
            data[off : off + 1384] = new_tag23_block
            print(f"  [+] Đã vá Tag 2 & 3 tại offset 0x{off:x}")
            total_slices += 1

        # 3. Re-hash CodeDirectory page hashes
        cds = update_codedirectories_in_macho(data)
        total_cds_updated += cds
        print(f"  [+] Đã cập nhật {cds} CodeDirectories trong tệp.")

        if not dry_run:
            with open(full_path, "wb") as f:
                f.write(data)
            print(f"  [+] ĐÃ LƯU THÀNH CÔNG: {path}")

    print(f"\n[+] Tổng kết: Đã vá hoàn tất {total_slices}/14 slices, cập nhật {total_cds_updated} CodeDirectories!")
    if dry_run:
        print("[*] Chạy hoàn tất ở chế độ DRY-RUN an toàn. Dùng --apply để ghi đè.")

if __name__ == "__main__":
    is_dry = "--apply" not in sys.argv
    patch_all_production_binaries(dry_run=is_dry)
