"""Read-only byte checks for server-error presentation; never imports the server."""
from pathlib import Path
import hashlib
import json
import struct

import capstone
import lief

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/rebranding"
BASE = 0x100000000


def main():
    source = ROOT / "extracted/data/Applications/VCNext.app/VCNext"
    raw = source.read_bytes()
    original_hash = hashlib.sha256(raw).hexdigest()
    assert original_hash == "cb09e14b403151b31e81ed5c2eb40fea014ed1357067818cc47ac1c0517cba4f"
    image = lief.MachO.parse(list(raw)).at(0)
    sections = list(image.sections)

    def file_offset(address, count=1):
        for section in sections:
            delta = address - section.virtual_address
            if 0 <= delta and delta + count <= section.size:
                return section.offset + delta
        raise ValueError(hex(address))

    def cstring(address):
        offset = file_offset(address)
        end = raw.index(b"\0", offset)
        assert end - offset < 4096
        return raw[offset:end].decode("utf-8")

    def pointer(address):
        value = struct.unpack_from("<Q", raw, file_offset(address, 8))[0]
        # This artifact uses DYLD_CHAINED_PTR_64_OFFSET. Keep original words
        # untouched; only decode the image-relative target for this read.
        return value if BASE <= value < BASE + len(raw) else BASE + (value & ((1 << 36) - 1))

    engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    engine.detail = True
    stubs = next(s for s in sections if s.name == "__objc_stubs")
    stub_names = {}
    instructions = list(engine.disasm(bytes(stubs.content), stubs.virtual_address))
    for first, second in zip(instructions, instructions[1:]):
        if first.mnemonic != "adrp" or second.mnemonic != "ldr":
            continue
        if first.reg_name(first.operands[0].reg) != "x1":
            continue
        if second.reg_name(second.operands[0].reg) != "x1":
            continue
        memory = second.operands[1].mem
        if second.reg_name(memory.base) != "x1" or memory.index:
            continue
        address = first.operands[1].imm + memory.disp
        stub_names[first.address] = cstring(pointer(address))

    assert stub_names[0x100027FA0] == "setNumberOfLines:"
    assert stub_names[0x100025980] == "errorLabel"
    assert stub_names[0x100024B80] == "alertControllerWithTitle:message:preferredStyle:"
    text = next(s for s in sections if s.name == "__text" and s.segment_name == "__TEXT")
    all_instructions = list(engine.disasm(bytes(text.content), text.virtual_address))
    selectors = ("setNumberOfLines:", "alertControllerWithTitle:message:preferredStyle:", "displayMessageForError:")
    calls = {name: [] for name in selectors}
    for instruction in all_instructions:
        if instruction.mnemonic == "bl":
            name = stub_names.get(instruction.operands[0].imm)
            if name in calls:
                calls[name].append(hex(instruction.address))
    assert calls["setNumberOfLines:"] == ["0x10000a520", "0x10000e7fc"]
    assert calls["alertControllerWithTitle:message:preferredStyle:"] == ["0x100016540"]
    assert raw[0xA51C:0xA520].hex() == "42008052"  # mov w2,#2
    assert raw[0xA520:0xA524].hex() == "a0760094"  # bl setNumberOfLines:

    ranges = [
        (0x100005AF4, 0x100005C20, "NSError construction"),
        (0x1000064A4, 0x100006788, "HTTP response parser"),
        (0x100009B24, 0x10000B968, "Complete login buildInterface; decompiler preview is truncated"),
        (0x10000BF90, 0x10000C100, "Message selection and legacy support suffix"),
        (0x10000C388, 0x10000C4FC, "Manual sign-in UI completion"),
        (0x1000092F8, 0x1000093F8, "Restore UI completion"),
        (0x1000164F0, 0x1000165BC, "The separate media-import UIAlertController"),
    ]
    lines = [f"; Current app SHA256 {original_hash}", "; Fresh Capstone; selector names decoded from current stubs/selrefs."]
    for start, end, title in ranges:
        lines.append(f"\n; {title}: {start:#x}..{end:#x} (exclusive)")
        for instruction in engine.disasm(raw[file_offset(start):file_offset(end - 1) + 1], start):
            suffix = ""
            if instruction.mnemonic == "bl":
                name = stub_names.get(instruction.operands[0].imm)
                if name:
                    suffix = " ; objc_msgSend$" + name
            lines.append(f"{instruction.address:#x} {instruction.bytes.hex()} {instruction.mnemonic} {instruction.op_str}{suffix}")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "client_fresh_arm64.asm").write_text("\n".join(lines) + "\n", encoding="utf-8")
    example = {"ok": False, "error": "wrong_password", "message": "Sai mật khẩu.\nHỗ trợ: @your_support"}
    encoded = json.dumps(example, ensure_ascii=False).encode("utf-8")
    assert json.loads(encoded) == example
    report = {
        "method": "Read-only raw Mach-O/LIEF/Capstone and Python JSON roundtrip",
        "ios_ui_executed": False,
        "foundation_runtime_executed": False,
        "app_sha256": original_hash,
        "app_text_sha256": hashlib.sha256(bytes(text.content)).hexdigest(),
        "decoded_objc_stubs": len(stub_names),
        "selected_direct_selector_call_sites": calls,
        "login_error_number_of_lines": 2,
        "number_of_lines_argument": {"address": "0x10000a51c", "bytes": "42008052"},
        "number_of_lines_call": {"address": "0x10000a520", "bytes": "a0760094", "target": "0x100027fa0"},
        "setLineBreakMode_selector_present": b"setLineBreakMode:\0" in raw,
        "legacy_suffix": "\n@toilaluyen",
        "legacy_suffix_exact_identifiers": ["INVALID_CREDENTIALS", "DEVICE_LIMIT"],
        "unicode_newline_python_json_roundtrip": True,
        "roundtrip_does_not_prove_ios_layout": True,
        "source_unchanged": hashlib.sha256(source.read_bytes()).hexdigest() == original_hash,
    }
    assert report["source_unchanged"]
    (OUT / "client_inventory.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "login_error_number_of_lines": 2, "source_unchanged": True}, indent=2))


if __name__ == "__main__":
    main()
