#!/usr/bin/env python3
"""
VCNext Static Cryptographic Decryption Engine
Mô phỏng 100% thuật toán giải mã Authenticated Double AES-256-CBC trích xuất từ nhị phân.
"""

import hmac
import hashlib
import struct
import sys
import os

# Ensure stdout handles UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Khóa Master 256-bit trích xuất từ phân vùng __TEXT,__const (0x10000a0f0)
MASTER_KEY = bytes.fromhex(
    "14df1fbcb833231aec282cde08b51104a0e77d6b33f4be35ad3f468602f1dffb"
)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

def encrypt_payload_block(tag: int, plaintext: bytes, salt: bytes = None, iv1: bytes = None, iv2: bytes = None):
    """
    Mã hóa khối dữ liệu 2 lớp Double AES-256-CBC + HMAC-SHA256 chuẩn nhị phân.
    """
    if salt is None: salt = os.urandom(16)
    if iv1 is None: iv1 = os.urandom(16)
    if iv2 is None: iv2 = os.urandom(16)

    k1_input = b'\x02' + bytes([tag]) + b'\xa1' + salt
    k1 = hmac.new(MASTER_KEY, k1_input, hashlib.sha256).digest()

    k2_input = b'\x02' + bytes([tag]) + b'\xb2' + salt
    k2 = hmac.new(MASTER_KEY, k2_input, hashlib.sha256).digest()

    p_temp = aes_cbc_encrypt(MASTER_KEY, iv2, plaintext)
    c = aes_cbc_encrypt(k1, iv1, p_temp)

    mac_data = b'\x02' + bytes([tag]) + salt + iv2 + iv1 + c
    mac = hmac.new(k2, mac_data, hashlib.sha256).digest()

    return salt, iv1, iv2, c, mac

def decrypt_payload_block(tag: int, salt: bytes, iv1: bytes, iv2: bytes,
                          ciphertext: bytes, expected_hmac: bytes) -> bytes:
    """
    Thực thi giải mã khối dữ liệu dựa trên tag (1, 2 hoặc 3).
    """
    # 1. Dẫn xuất khóa K1 cho lớp AES thứ nhất
    k1_input = b'\x02' + bytes([tag]) + b'\xa1' + salt
    k1 = hmac.new(MASTER_KEY, k1_input, hashlib.sha256).digest()

    # 2. Dẫn xuất khóa K2 cho lớp MAC
    k2_input = b'\x02' + bytes([tag]) + b'\xb2' + salt
    k2 = hmac.new(MASTER_KEY, k2_input, hashlib.sha256).digest()

    # 3. Thẩm định HMAC-SHA256 (Constant-time check)
    mac_data = b'\x02' + bytes([tag]) + salt + iv2 + iv1 + ciphertext
    computed_mac = hmac.new(k2, mac_data, hashlib.sha256).digest()

    if not hmac.compare_digest(computed_mac, expected_hmac):
        raise ValueError(f"HMAC Mismatch for Tag {tag}! Dữ liệu nhị phân đã bị thay đổi.")

    # 4. Giải mã 2 lớp AES-256-CBC
    intermediate_plaintext = aes_cbc_decrypt(k1, iv1, ciphertext)
    final_plaintext = aes_cbc_decrypt(MASTER_KEY, iv2, intermediate_plaintext)
    return final_plaintext

def extract_and_decrypt_all(binary_path: str):
    """
    Đọc trực tiếp từ tệp Mach-O VCNNetworkDaemon và giải mã cả 3 khối.
    """
    with open(binary_path, "rb") as f:
        data = f.read()

    const_addr = 0x10000a0d0
    const_off = 0xa0d0

    def get_b(addr, length):
        return data[const_off + (addr - const_addr) : const_off + (addr - const_addr) + length]

    def get_u64(addr):
        return struct.unpack('<Q', get_b(addr, 8))[0]

    def parse_block(tag, len_ptrs, addrs):
        x1 = get_u64(len_ptrs[0])
        x3 = get_u64(len_ptrs[1])
        x5 = get_u64(len_ptrs[2])
        x7 = get_u64(len_ptrs[3])
        x8 = get_u64(len_ptrs[4])

        salt = get_b(addrs[3], x7)
        iv2 = get_b(addrs[1], x3)
        iv1 = get_b(addrs[2], x5)
        ct = get_b(addrs[0], x1)
        expected_mac = get_b(addrs[4], x8)

        return decrypt_payload_block(tag, salt, iv1, iv2, ct, expected_mac)

    print("[*] Đang giải mã khối Tag 1 (Endpoints Configuration)...")
    tag1_data = parse_block(1,
        [0x10000a298, 0x10000a138, 0x10000a150, 0x10000a120, 0x10000a2c0],
        [0x10000a158, 0x10000a128, 0x10000a140, 0x10000a110, 0x10000a2a0]
    )
    print("--> Tag 1 Decrypted:", tag1_data.decode("utf-8"))

    print("\n[*] Đang giải mã khối Tag 2 (Public Key Thumbprint)...")
    tag2_data = parse_block(2,
        [0x10000a350, 0x10000a2f0, 0x10000a308, 0x10000a2d8, 0x10000a378],
        [0x10000a310, 0x10000a2e0, 0x10000a2f8, 0x10000a2c8, 0x10000a358]
    )
    print("--> Tag 2 Thumbprint (Hex):", tag2_data.hex())

    print("\n[*] Đang giải mã khối Tag 3 (Server X.509 Certificate)...")
    tag3_data = parse_block(3,
        [0x10000a808, 0x10000a3a8, 0x10000a3c0, 0x10000a390, 0x10000a830],
        [0x10000a3c8, 0x10000a398, 0x10000a3b0, 0x10000a380, 0x10000a810]
    )
    cert = x509.load_der_x509_certificate(tag3_data, default_backend())
    print("--> Tag 3 Cert Subject:", cert.subject.rfc4514_string())
    print("--> Tag 3 Cert Issuer :", cert.issuer.rfc4514_string())
    print("--> Tag 3 Valid From  :", cert.not_valid_before_utc)
    print("--> Tag 3 Valid Until :", cert.not_valid_after_utc)

    # Xuất chứng chỉ ra file PEM để dùng cho Mock Server
    pem_path = "mocks/server_cert.pem"
    pubkey_path = "mocks/server_public_key.pem"
    with open(pem_path, "wb") as pf:
        pf.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(pubkey_path, "wb") as kf:
        kf.write(cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"[+] Đã lưu chứng chỉ ra: {pem_path}")
    print(f"[+] Đã trích xuất khóa công khai ra: {pubkey_path}")

if __name__ == "__main__":
    import os
    target_bin = "extracted/data/usr/libexec/VCNNetworkDaemon"
    os.makedirs("mocks", exist_ok=True)
    if os.path.exists(target_bin):
        extract_and_decrypt_all(target_bin)
    else:
        print(f"[-] Không tìm thấy tệp nhị phân tại {target_bin}")
