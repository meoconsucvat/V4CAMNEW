"""Read-only, artifact-specific UI-string/signature inventory (no target execution)."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct

import capstone
import lief

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/rebranding"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cd = module("rebrand_cd_parser", ROOT / "scripts/verify_v3_code_directory.py")
    deb = module("rebrand_deb_parser", ROOT / "scripts/audit_final_package.py")
    packages = {}
    for name in ["VCNext-0.16.73-roothide.deb", "VCNext-custom-roothide.deb"]:
        raw, members, headers = deb.archive(ROOT / name)
        data, rows, metadata = deb.read_tar(members["data.tar.zst"])
        packages[name] = (sha(raw), data)
    report = {"method": "Current and original package bytes, LIEF sections, fresh Capstone; no binary writes, signing, network, or target execution", "files": []}
    assembly = []
    for relative in ["Applications/VCNext.app/VCNext", "var/mobile/Library/pkgmirror/Applications/VCNext.app/VCNext"]:
        path = ROOT / "extracted/data" / relative
        data = path.read_bytes()
        before = sha(data)
        assert packages["VCNext-custom-roothide.deb"][1][relative] == data
        original = packages["VCNext-0.16.73-roothide.deb"][1][relative]
        image = lief.MachO.parse(str(path)).at(0)
        command_offset = 32
        chain_formats = []
        for _ in range(struct.unpack_from("<I", data, 16)[0]):
            command, size = struct.unpack_from("<II", data, command_offset)
            if command == 0x80000034:
                payload_offset, _ = struct.unpack_from("<II", data, command_offset+8)
                starts_offset = struct.unpack_from("<I", data, payload_offset+4)[0]
                starts = payload_offset+starts_offset
                for segment in range(struct.unpack_from("<I", data, starts)[0]):
                    offset = struct.unpack_from("<I", data, starts+4+segment*4)[0]
                    if offset:
                        chain_formats.append(struct.unpack_from("<H",data,starts+offset+6)[0])
            command_offset += size
        assert chain_formats and set(chain_formats) == {6}, chain_formats
        sections = {s.name: s for s in image.sections if s.name in ["__text", "__cstring", "__cfstring"]}
        cstrings, cfstrings = sections["__cstring"], sections["__cfstring"]
        text = sections["__text"]
        cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        cs.detail = True
        instructions = list(cs.disasm(bytes(text.content), text.virtual_address))
        assert len(instructions)*4 == text.size
        constants = []
        for offset in range(cfstrings.offset, cfstrings.offset+cfstrings.size, 32):
            isa, flags, rawptr, length = struct.unpack_from("<4Q", data, offset)
            # This executable has chained rebases: actual string target is the
            # low 36 bits of the observed DYLD_CHAINED_PTR_64_OFFSET word.
            pointer = rawptr & ((1 << 36)-1)
            if cstrings.offset <= pointer < cstrings.offset+cstrings.size:
                end = data.find(b"\0", pointer)
                constants.append({"file_offset": offset, "vm": cfstrings.virtual_address+offset-cfstrings.offset,
                                  "flags": flags, "raw_pointer": rawptr, "string_file_offset": pointer,
                                  "explicit_length": length, "data": data[pointer:end]})
        strings = []
        cursor = cstrings.offset
        while cursor < cstrings.offset+cstrings.size:
            end = data.find(b"\0", cursor, cstrings.offset+cstrings.size)
            assert end >= cursor
            value = data[cursor:end]
            if b"V4HCAM" in value:
                aliases = [v for v in constants if cursor <= v["string_file_offset"] <= end]
                targets = {cstrings.virtual_address+cursor-cstrings.offset: "cstring"}
                targets.update({v["vm"]: "cfstring" for v in aliases})
                references = []
                for index, inst in enumerate(instructions):
                    if inst.mnemonic != "adrp" or len(inst.operands) != 2:
                        continue
                    register, page = inst.operands[0].reg, inst.operands[1].imm
                    for following in instructions[index+1:index+4]:
                        ops = following.operands
                        if following.mnemonic == "add" and len(ops) == 3 and ops[1].reg == register and ops[2].type == capstone.arm64.ARM64_OP_IMM:
                            target = page + ops[2].imm
                            if target in targets:
                                references.append({"adrp": hex(inst.address), "add": hex(following.address),
                                                   "target": hex(target), "kind": targets[target],
                                                   "instructions": [f"{hex(v.address)} {v.bytes.hex()} {v.mnemonic} {v.op_str}" for v in instructions[index:index+5]]})
                        # For the narrow sequence scan, stop on overwritten ADRP
                        # register. This does not claim exhaustive semantic xrefs.
                        _, written = following.regs_access()
                        if register in written:
                            break
                strings.append({"text": value.decode("utf-8"), "utf8_bytes": len(value), "file_offset": hex(cursor),
                                "vm": hex(cstrings.virtual_address+cursor-cstrings.offset), "nul_file_offset": hex(end),
                                "current_equals_original_including_nul": original[cursor:end+1] == data[cursor:end+1],
                                "cfstrings": [{k: (hex(v) if k in ["file_offset", "vm", "raw_pointer", "string_file_offset", "flags"] else v)
                                               for k,v in row.items() if k != "data"} for row in aliases],
                                "fresh_adjacent_adrp_add_references": references})
            cursor = end+1
        signatures = []
        embedded = []
        for sl in cd.macho_slices(data):
            _, entries = cd.superblob(data, *sl["signature"])
            embedded.extend({"slot":hex(slot),"magic":hex(entry["magic"]),"bytes":entry["length"],
                             "sha256":sha(data[entry["absolute_offset"]:entry["absolute_offset"]+entry["length"]])}
                            for slot,entry in entries.items())
            for slot, entry in entries.items():
                if entry["magic"] != 0xfade0c02:
                    continue
                desc = cd.read_cd(data, entry, sl)
                signatures.append({"slot": hex(slot), "directory_file_offset": hex(entry["absolute_offset"]),
                                   **desc, "code_mismatch_count": len(cd.code_mismatches(data, sl, entry, desc)),
                                   "special_slots": cd.special_slots(data, sl, entry, desc, entries, path)})
        row = {"path": relative, "bytes": len(data), "sha256": before, "original_sha256": sha(original),
               "text_sha256": sha(bytes(text.content)), "text_matches_original": original[text.offset:text.offset+text.size] == bytes(text.content),
               "sections": {k:{"segment": v.segment_name, "file_offset": hex(v.offset), "vm":hex(v.virtual_address), "size":v.size} for k,v in sections.items()},
               "strings":strings, "code_directories":signatures,
               "dyld_chained_pointer_formats":chain_formats, "embedded_signature_entries":embedded,
               "bundle_CodeResources_exists": (path.parent / "_CodeSignature/CodeResources").is_file()}
        assert all(v["current_equals_original_including_nul"] for v in strings)
        assert row["text_matches_original"] and all(not v["code_mismatch_count"] for v in signatures)
        report["files"].append(row)
        if relative.startswith("Applications"):
            for start, stop in [(0x10000dbe8,0x10000dc08),(0x10001fe44,0x1000200e0),(0x1000200e0,0x100020214),(0x10002155c,0x1000216f4)]:
                assembly.append(f"\n# Current executable {before}; VA {hex(start)}..{hex(stop)}")
                selected=bytes(text.content)[start-text.virtual_address:stop-text.virtual_address]
                assembly.extend(f"{hex(i.address)} {i.bytes.hex()} {i.mnemonic} {i.op_str}" for i in cs.disasm(selected,start))
        assert sha(path.read_bytes()) == before
    report["package_sha256"] = {k:v[0] for k,v in packages.items()}
    report["all_code_page_hashes_match"] = True
    report["input_binaries_unchanged"] = True
    (OUT / "strings_inventory.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    (OUT / "strings_fresh_arm64.asm").write_text("\n".join(assembly)+"\n",encoding="utf-8")
    print(json.dumps({"files":[{"path":r["path"],"sha256":r["sha256"],"strings":len(r["strings"]),"code_directories":len(r["code_directories"])}for r in report["files"]],"all_code_page_hashes_match":True,"input_binaries_unchanged":True},indent=2))


if __name__ == "__main__":
    main()
