"""Read-only app instruction bytes and public authority identity measurements."""
from pathlib import Path
import hashlib
import json
import struct
import capstone
import lief
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from crypto_engine import decrypt_payload_block

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/ui_tag1'
APP = ROOT / 'extracted/data/Applications/VCNext.app/VCNext'
MIRROR = ROOT / 'extracted/data/var/mobile/Library/pkgmirror/Applications/VCNext.app/VCNext'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    raw = APP.read_bytes()
    owner = lief.MachO.parse(str(APP))
    binary = owner.at(0)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    ranges = [(0x100006048, 0x1000060AC), (0x10000657C, 0x10000659C),
              (0x1000079D0, 0x100007A98), (0x100007D48, 0x100007DA4),
              (0x100008A08, 0x100008A7C), (0x10000933C, 0x1000093D4),
              (0x100021304, 0x10002137C), (0x100021BC0, 0x100021BD4),
              (0x100021C50, 0x100021C80), (0x100021F00, 0x100021F48)]
    rows = []
    for start, end in ranges:
        section = next(s for s in binary.sections
                       if s.virtual_address <= start and end <= s.virtual_address + s.size)
        file_start = section.offset + start - section.virtual_address
        data = raw[file_start:file_start + end - start]
        instructions = list(md.disasm(data, start))
        assert len(instructions) * 4 == len(data)
        rows.append({'start': hex(start), 'end_exclusive': hex(end),
                     'file_offset': hex(file_start), 'bytes': data.hex(),
                     'instructions': [{'va': hex(i.address), 'opcode': i.bytes.hex(),
                                       'instruction': i.mnemonic + ' ' + i.op_str}
                                      for i in instructions]})
    # Original embedded Tag2/3 only. No signing key is read.
    block = raw[0x2B288:0x2B288+1392]

    def field(start, length_offset):
        size = struct.unpack_from('<Q', block, length_offset)[0]
        return block[start:start+size]

    pin = decrypt_payload_block(2, field(0,16), field(48,64), field(24,40),
                                field(72,136), field(144,176))
    cert = decrypt_payload_block(3, field(184,200), field(232,248), field(208,224),
                                 field(256,1344), field(1352,1384))
    public = x509.load_der_x509_certificate(cert).public_key()
    pkcs1 = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    mirror_owner = lief.MachO.parse(str(MIRROR))
    text = bytes(binary.get_section('__text').content)
    mirror_text = bytes(mirror_owner.at(0).get_section('__text').content)
    assert text == mirror_text
    result = {'scope': 'Raw binary data/instruction inspection only; no target execution',
              'app_path': str(APP), 'app_sha256': sha(raw),
              'app_text_file_offset': hex(binary.get_section('__text').offset),
              'app_text_size': hex(len(text)), 'app_text_sha256': sha(text),
              'mirror_sha256': sha(MIRROR.read_bytes()),
              'main_mirror_text_identical': text == mirror_text,
              'original_tag2_pin': pin.hex(),
              'original_tag3_cert_der_length': len(cert),
              'original_tag3_public_pkcs1_sha256': sha(pkcs1),
              'original_tag2_equals_tag3_public_pkcs1_sha256': pin.hex() == sha(pkcs1),
              'ranges': rows}
    assert sha(APP.read_bytes()) == result['app_sha256']
    OUT.mkdir(exist_ok=True, parents=True)
    (OUT/'app_raw_evidence.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k != 'ranges'}, indent=2))


if __name__ == '__main__':
    main()
