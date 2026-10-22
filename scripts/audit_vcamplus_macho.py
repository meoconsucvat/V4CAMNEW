"""Independent read-only audit of shipped VCAMPLUS Mach-O members.

Imports only parser declarations from existing helpers. Never calls builders,
patchers, signing tools, product entrypoints, credentials, databases, or network.
Writes derived JSON/Markdown/assembly evidence under docs/evidence/vcamplus only.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct

import capstone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/vcamplus"
BASELINE = ROOT / "VCNext-custom-roothide.deb"
STAGED = ROOT / "dist/VCAMPLUS-roothide.deb"
EXPECTED_STAGED_SHA = "ff13f266d898a02173224645ea0d81e47bad508ca965cd5c37e976512d71c558"
EXPECTED_TEXT_SHA = "4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2"
APPS = ("Applications/VCNext.app/VCNext",
        "var/mobile/Library/pkgmirror/Applications/VCNext.app/VCNext")
STRING_OFFSET, LENGTH_OFFSET = 0x2C16B, 0x35770


def sha(data):
    return hashlib.sha256(data).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def layout(data, image):
    base = image["base"]
    pos = base + 32
    commands, sections, segments = [], [], []
    for _ in range(struct.unpack_from("<I", data, base+16)[0]):
        cmd, size = struct.unpack_from("<II", data, pos)
        row = {"command": cmd, "offset": pos, "size": size}
        if cmd == 0x19:
            seg = struct.unpack_from("<II16sQQQQiiII", data, pos)
            segments.append({"name": seg[2].rstrip(b"\0").decode(), "vm": seg[3],
                             "vm_size": seg[4], "file_offset": base+seg[5], "file_size": seg[6]})
            for index in range(seg[-2]):
                sec = struct.unpack_from("<16s16sQQ8I", data, pos+72+index*80)
                sections.append({"name": sec[0].rstrip(b"\0").decode(),
                    "segment": sec[1].rstrip(b"\0").decode(), "vm": sec[2],
                    "size": sec[3], "offset": base+sec[4]})
        if cmd == 0x80000034:
            off, count = struct.unpack_from("<II", data, pos+8)
            row.update({"payload_offset": base+off, "payload_size": count})
        commands.append(row)
        pos += size
    return {"commands": commands, "segments": segments, "sections": sections,
            "load_commands_end": pos}


def chained_words(data, image, meta):
    """Walk the observed DYLD_CHAINED_PTR_64_OFFSET (6) chains, fail closed."""
    words, payloads, formats = {}, [], set()
    for command in meta["commands"]:
        if command["command"] != 0x80000034:
            continue
        payload = command["payload_offset"]
        payloads.append((payload, command["payload_size"]))
        version, starts_offset = struct.unpack_from("<II", data, payload)
        assert version == 0
        starts = payload+starts_offset
        segment_count = struct.unpack_from("<I", data, starts)[0]
        assert segment_count == len(meta["segments"])
        for index in range(segment_count):
            relative = struct.unpack_from("<I", data, starts+4+index*4)[0]
            if not relative:
                continue
            info = starts+relative
            size, page_size, fmt, seg_offset, _, page_count = struct.unpack_from("<IHHQIH", data, info)
            formats.add(fmt)
            assert fmt == 6 and size >= 22+page_count*2
            # This artifact's image-relative offsets map directly to file offsets.
            segment = meta["segments"][index]
            assert image["base"]+seg_offset == segment["file_offset"]
            for page in range(page_count):
                first = struct.unpack_from("<H", data, info+22+page*2)[0]
                if first == 0xFFFF:
                    continue
                assert first & 0x8000 == 0, "Unexpected multi-start chain layout"
                address = image["base"]+seg_offset+page*page_size+first
                visited = set()
                while True:
                    assert address not in visited and address not in words
                    visited.add(address)
                    assert segment["file_offset"] <= address <= segment["file_offset"]+segment["file_size"]-8
                    value = struct.unpack_from("<Q", data, address)[0]
                    words[address] = value
                    following = (value >> 51) & 0xFFF
                    if following == 0:
                        break
                    address += following*4
    return words, payloads, sorted(formats)


def special_slots(data, entries, entry, desc, packaged_files, bundle):
    records = []
    for slot in range(1, desc["special_slot_count"]+1):
        offset = entry["absolute_offset"]+desc["hash_offset"]-slot*desc["hash_size"]
        stored = data[offset:offset+desc["hash_size"]]
        payload, origin = None, None
        if slot in entries:
            ext = entries[slot]
            payload = data[ext["absolute_offset"]:ext["absolute_offset"]+ext["length"]]
            origin = "embedded_superblob"
        elif bundle is not None and slot in (1, 3):
            path = bundle+("/Info.plist" if slot == 1 else "/_CodeSignature/CodeResources")
            payload, origin = packaged_files.get(path), path
        expected = hashlib.new(desc["hash_name"], payload).digest()[:desc["hash_size"]] if payload is not None else None
        status = "zero_absent" if not any(stored) else "matches" if expected == stored else "unverified_missing_payload" if payload is None else "mismatch"
        records.append({"slot": slot, "offset": hex(offset), "stored": stored.hex(),
                        "payload": origin, "status": status,
                        "computed_if_available": expected.hex() if expected is not None else None})
    return records


def main():
    pkg = module("vcamplus_package_parser_only", ROOT/"scripts/audit_final_package.py")
    cd = module("vcamplus_cd_parser_only", ROOT/"scripts/verify_v3_code_directory.py")
    before, old_members, _ = pkg.archive(BASELINE)
    after, new_members, _ = pkg.archive(STAGED)
    old, _, _ = pkg.read_tar(old_members["data.tar.zst"])
    new, _, _ = pkg.read_tar(new_members["data.tar.zst"])
    assert len(after) == 479204 and sha(after) == EXPECTED_STAGED_SHA
    magic = (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
    binary_paths = sorted(p for p, b in old.items() if b[:4] in magic)
    assert binary_paths == sorted(p for p, b in new.items() if b[:4] in magic)
    assert len(binary_paths) == 10
    report = {"method": "Read-only package byte comparison, Mach-O/load-command parsing, complete observed chained-pointer traversal, CodeDirectory page and special-slot audit; fresh Capstone xrefs. No target execution/signing/network.",
        "baseline": {"path": BASELINE.relative_to(ROOT).as_posix(), "bytes": len(before), "sha256": sha(before)},
        "staged": {"path": STAGED.relative_to(ROOT).as_posix(), "bytes": len(after), "sha256": sha(after)},
        "binaries": [], "limitations": ["Code-page consistency is not AMFI/dyld/trust admission or device runtime proof.",
        "Observed CodeDirectory flags remain 0; none claims CS_ADHOC (2). No CMS signature slot or wrapper occurs. Jailbreak installation/signing policy still requires on-device validation.",
        "Unchanged camera/overlay binaries retain pre-existing A14/A16 pipeline policy and permission risks; commercial rebranding does not fix them."]}
    assembly = []
    for path in binary_paths:
        baseline, staged = old[path], new[path]
        assert len(baseline) == len(staged)
        old_images, images = cd.macho_slices(baseline), cd.macho_slices(staged)
        assert old_images == images
        changed = {i for i, pair in enumerate(zip(baseline, staged)) if pair[0] != pair[1]}
        allowed = set()
        row = {"path": path, "bytes": len(staged), "baseline_sha256": sha(baseline),
               "staged_sha256": sha(staged), "byte_identical_to_baseline": baseline == staged,
               "changed_bytes": len(changed), "slices": []}
        if path in APPS:
            assert baseline[STRING_OFFSET:STRING_OFFSET+12] == b"V4HCAM Next\0"
            assert staged[STRING_OFFSET:STRING_OFFSET+12] == b"VCAMPLUS\0\0\0\0"
            assert struct.unpack_from("<Q", baseline, LENGTH_OFFSET)[0] == 11
            assert struct.unpack_from("<Q", staged, LENGTH_OFFSET)[0] == 8
            allowed.update(range(STRING_OFFSET, STRING_OFFSET+12))
            allowed.update(range(LENGTH_OFFSET, LENGTH_OFFSET+8))
            row["title_patch"] = {"cstring_file_offset": hex(STRING_OFFSET), "baseline_hex": baseline[STRING_OFFSET:STRING_OFFSET+12].hex(),
                "staged_hex": staged[STRING_OFFSET:STRING_OFFSET+12].hex(), "length_offset": hex(LENGTH_OFFSET),
                "baseline_length": 11, "staged_length": 8}
        else:
            assert baseline == staged
        for image in images:
            meta = layout(staged, image)
            textoff, textsize = image["text"]
            assert baseline[textoff:textoff+textsize] == staged[textoff:textoff+textsize]
            _, entries = cd.superblob(staged, *image["signature"])
            _, old_entries = cd.superblob(baseline, *image["signature"])
            assert entries == old_entries
            is_app = path in APPS
            if is_app:
                assert sha(staged[textoff:textoff+textsize]) == EXPECTED_TEXT_SHA
            current = {"base": hex(image["base"]), "cpu": hex(image["cpu"]), "subtype": hex(image["subtype"]),
                "text_bytes": textsize, "text_sha256": sha(staged[textoff:textoff+textsize]), "text_identical": True,
                "load_command_bytes_identical": baseline[image["base"]:meta["load_commands_end"]] == staged[image["base"]:meta["load_commands_end"]],
                "code_directories": [], "cms_present": 0x10000 in entries or any(e["magic"] == 0xFADE0B01 for e in entries.values()),
                "embedded_non_codedirectory_blobs_identical": all(baseline[e["absolute_offset"]:e["absolute_offset"]+e["length"]] == staged[e["absolute_offset"]:e["absolute_offset"]+e["length"]] for e in entries.values() if e["magic"] != 0xFADE0C02)}
            assert current["load_command_bytes_identical"] and current["embedded_non_codedirectory_blobs_identical"] and not current["cms_present"]
            if is_app:
                words, payloads, formats = chained_words(staged, image, meta)
                assert words
                assert all(struct.unpack_from("<Q", baseline, offset)[0] == word for offset, word in words.items())
                assert all(baseline[offset:offset+length] == staged[offset:offset+length] for offset, length in payloads)
                record = LENGTH_OFFSET-24
                isa, flags, target, length = struct.unpack_from("<4Q", staged, record)
                assert target & ((1 << 36)-1) == STRING_OFFSET
                assert baseline[record:record+24] == staged[record:record+24]
                current["chained_fixups"] = {"formats": formats, "walked_pointer_words": len(words),
                    "all_pointer_words_identical": True, "fixup_payloads_identical": True,
                    "title_cfstring_record": hex(record), "title_cfstring_vm": hex(0x100000000+record),
                    "isa_word": hex(isa), "flags": hex(flags), "string_pointer_word": hex(target), "first_24_bytes_identical": True}
                # Enumerate aliases to the old slot, including suffix/interior pointers.
                cf = next(s for s in meta["sections"] if s["segment"] == "__DATA_CONST" and s["name"] == "__cfstring")
                aliases = []
                for offset in range(cf["offset"], cf["offset"]+cf["size"], 32):
                    _, _, ptr, length = struct.unpack_from("<4Q", staged, offset)
                    target = ptr & ((1 << 36)-1)
                    if STRING_OFFSET <= target < STRING_OFFSET+12:
                        aliases.append({"record": hex(offset), "target": hex(target), "length": length})
                assert aliases == [{"record": hex(record), "target": hex(STRING_OFFSET), "length": 8}]
                current["title_cfstring_aliases"] = aliases
                if path == APPS[0]:
                    # Fresh adjacent ADRP+ADD references to the string and constant.
                    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
                    cs.detail = True
                    instructions = list(cs.disasm(staged[textoff:textoff+textsize], 0x100000000+textoff))
                    targets = {0x100000000+STRING_OFFSET, 0x100000000+record}
                    xrefs = []
                    for i, inst in enumerate(instructions[:-1]):
                        following = instructions[i+1]
                        if inst.mnemonic == "adrp" and following.mnemonic == "add":
                            a, b = inst.operands, following.operands
                            if len(a) == 2 and len(b) == 3 and b[1].reg == a[0].reg and b[2].type == capstone.arm64.ARM64_OP_IMM and a[1].imm+b[2].imm in targets:
                                xrefs.append({"adrp": hex(inst.address), "add": hex(following.address), "target": hex(a[1].imm+b[2].imm)})
                                assembly.append(f"\n# Title reference {hex(a[1].imm+b[2].imm)}; staged executable SHA256 {sha(staged)}")
                                assembly.extend(f"{hex(v.address)} {v.bytes.hex()} {v.mnemonic} {v.op_str}" for v in instructions[max(0,i-2):i+7])
                    current["fresh_adjacent_adrp_add_xrefs"] = xrefs
                    assert xrefs
            bundle = path.rsplit("/",1)[0] if is_app else None
            for slot, entry in entries.items():
                if entry["magic"] != 0xFADE0C02:
                    continue
                desc = cd.read_cd(staged, entry, image)
                start, end = entry["absolute_offset"], entry["absolute_offset"]+entry["length"]
                hashstart = start+desc["hash_offset"]
                specialstart = hashstart-desc["special_slot_count"]*desc["hash_size"]
                assert baseline[specialstart:hashstart] == staged[specialstart:hashstart]
                special = special_slots(staged, entries, entry, desc, new, bundle)
                assert all(s["status"] in ("matches", "zero_absent") for s in special)
                changed_pages = []
                for index in range(desc["code_slot_count"]):
                    off = image["base"]+index*desc["page_size"]
                    stop = image["base"]+min((index+1)*desc["page_size"], desc["code_limit"])
                    hpos = hashstart+index*desc["hash_size"]
                    if baseline[off:stop] != staged[off:stop]:
                        changed_pages.append(index)
                        allowed.update(range(hpos,hpos+desc["hash_size"]))
                    else:
                        assert baseline[hpos:hpos+desc["hash_size"]] == staged[hpos:hpos+desc["hash_size"]]
                assert changed_pages == ([44,53] if is_app else [])
                mismatches = cd.code_mismatches(staged,image,entry,desc)
                assert not mismatches and not cd.code_mismatches(baseline,image,entry,desc)
                current["code_directories"].append({"slot": hex(slot), "offset": hex(start), **desc,
                    "changed_code_pages": changed_pages, "code_page_mismatches": mismatches,
                    "baseline_cdhash": hashlib.new(desc["hash_name"],baseline[start:end]).digest()[:20].hex(),
                    "staged_cdhash": hashlib.new(desc["hash_name"],staged[start:end]).digest()[:20].hex(),
                    "special_slots_bytes_identical": True, "special_slots": special})
            row["slices"].append(current)
        assert changed <= allowed, [hex(v) for v in sorted(changed-allowed)]
        row["diff_whitelist_pass"] = True
        row["changed_offsets"] = [hex(v) for v in sorted(changed)] if path in APPS else []
        report["binaries"].append(row)
    counts = {"binaries": len(report["binaries"]), "slices": sum(len(b["slices"]) for b in report["binaries"]),
        "code_directories": sum(len(s["code_directories"]) for b in report["binaries"] for s in b["slices"]),
        "unchanged_binaries": sum(b["byte_identical_to_baseline"] for b in report["binaries"]),
        "changed_app_codedirectories": sum(len(s["code_directories"]) for b in report["binaries"] if b["path"] in APPS for s in b["slices"]),
        "code_page_mismatches": 0}
    assert counts == {"binaries":10,"slices":14,"code_directories":21,"unchanged_binaries":8,"changed_app_codedirectories":3,"code_page_mismatches":0}
    assert BASELINE.read_bytes() == before and STAGED.read_bytes() == after
    report.update({"counts": counts, "package_inputs_unchanged_after_audit": True, "all_assertions_pass": True})
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/"macho_integrity.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    (OUT/"macho_title_xrefs.asm").write_text("\n".join(assembly)+"\n",encoding="utf-8")
    lines = ["# Independent VCAMPLUS Mach-O audit", "", "PASS: exact packaged bytes; static consistency only.", "",
        f"Staged: `{sha(after)}` / {len(after)} bytes.",
        f"Baseline: `{sha(before)}` / {len(before)} bytes.", "", "| Path | Bytes | Staged SHA-256 | Identical to baseline |", "|---|---:|---|---|"]
    lines += [f"| `{b['path']}` | {b['bytes']} | `{b['staged_sha256']}` | {b['byte_identical_to_baseline']} |" for b in report["binaries"]]
    lines += ["", "- 10 binaries, 14 slices, 21 CodeDirectories, zero code-page mismatches.",
        "- Eight camera/overlay/daemon files are entirely byte-identical to baseline.",
        "- Both apps: exact 12-byte slot `VCAMPLUS\\0\\0\\0\\0` at 0x2c16b; uint64 CFString length 8 at 0x35770. Only this slot, this length word, and page hashes for pages 44/53 differ.",
        f"- Both app __TEXT,__text SHA-256: `{EXPECTED_TEXT_SHA}` (unchanged).",
        "- All observed chained pointer words and chained-fixup payloads preserved; title CFString first 24 bytes preserved. No additional CFString alias points within this slot.",
        "- All special-slot bytes and embedded requirements/entitlements preserved; each nonzero special slot validates. Info/CodeResources special slots, where present, are all-zero/absent, not invalid nonzero seals. No packaged CodeResources exists.",
        "- App pages 44/53 are 4096-byte code pages containing the string and CFString length respectively; all three applicable CD page-hash arrays are correct.",
        "- All CD flags are 0; no CMS slot/wrapper exists. This is page consistency evidence, not a standards-compliant new signature or AMFI admission proof. New CDHashes require target install/signing/trust validation.",
        "- Baseline and staged package files were re-read unchanged after auditing. No product binary or package was written.", "", "See macho_integrity.json for complete slice/CD/special-slot/byte-diff details and macho_title_xrefs.asm for fresh disassembly."]
    (OUT/"macho_findings.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps({"staged": report["staged"], "counts": counts,
                      "all_assertions_pass": True,"package_inputs_unchanged_after_audit":True},indent=2))


if __name__ == "__main__":
    main()
