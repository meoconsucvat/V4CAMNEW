"""Read-only CodeDirectory audit of originals and the v3 staged patch.

The hypothetical code-slot updates are made only in a bytearray. This helper
never writes a Mach-O file, signs a binary, loads target code, or reads keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
HASHES = {1: "sha1", 2: "sha256", 3: "sha256", 4: "sha384"}
SLOT_NAMES = {
    0: "CodeDirectory", 1: "Info.plist", 2: "Requirements",
    3: "CodeResources", 4: "Application", 5: "XML entitlements",
    7: "DER entitlements", 0x1000: "Alternate CodeDirectory",
    0x10000: "CMS signature",
}
SOURCES = [
    "https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h",
    "https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/requirement.h",
    "https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/codedirectory.cpp#L236-L249",
]


def digest(data, algorithm="sha256", size=None):
    result = hashlib.new(algorithm, data).digest()
    return result if size is None else result[:size]


def unpack(fmt, data, pos):
    size = struct.calcsize(fmt)
    assert 0 <= pos <= len(data) - size, (fmt, pos, len(data))
    return struct.unpack_from(fmt, data, pos)


def cstring(data, offset):
    assert 0 <= offset < len(data)
    end = data.find(b"\0", offset)
    assert end >= offset
    return data[offset:end].decode("utf-8", "backslashreplace")


def macho_slices(data):
    magic = data[:4]
    if magic == b"\xca\xfe\xba\xbe":
        count, = unpack(">I", data, 4)
        assert 1 <= count <= 32
        entries = []
        for index in range(count):
            cpu, subtype, offset, size, alignment = unpack(">5I", data, 8 + index * 20)
            assert offset + size <= len(data)
            entries.append((cpu, subtype, offset, size))
    else:
        assert magic == b"\xcf\xfa\xed\xfe", magic.hex()
        cpu, subtype = unpack("<II", data, 4)
        entries = [(cpu, subtype, 0, len(data))]
    slices = []
    for cpu, subtype, base, size in entries:
        image = data[base:base + size]
        header = unpack("<8I", image, 0)
        assert header[0] == 0xFEEDFACF
        ncmds, sizeofcmds = header[4:6]
        assert 0 < ncmds <= 1024 and 32 + sizeofcmds <= len(image)
        pos = 32
        signature = None
        text = None
        for _ in range(ncmds):
            cmd, cmdsize = unpack("<II", image, pos)
            assert cmdsize >= 8 and pos + cmdsize <= 32 + sizeofcmds
            if cmd == 0x1D:
                assert cmdsize == 16 and signature is None
                sigoff, sigsize = unpack("<II", image, pos + 8)
                assert sigoff + sigsize <= size
                signature = (base + sigoff, sigsize)
            if cmd == 0x19:
                segment = unpack("<II16sQQQQiiII", image, pos)
                nsects = segment[-2]
                assert 72 + nsects * 80 <= cmdsize
                for index in range(nsects):
                    sec = unpack("<16s16sQQ8I", image, pos + 72 + index * 80)
                    if sec[0].rstrip(b"\0") == b"__text" and sec[1].rstrip(b"\0") == b"__TEXT":
                        section_size, section_offset = sec[3:5]
                        assert section_offset + section_size <= size and text is None
                        text = (base + section_offset, section_size)
            pos += cmdsize
        assert pos == 32 + sizeofcmds and signature is not None and text is not None
        slices.append({"cpu": cpu, "subtype": subtype, "base": base,
                       "size": size, "signature": signature, "text": text})
    return slices


def superblob(data, start, allocation):
    magic, length, count = unpack(">III", data, start)
    assert magic == 0xFADE0CC0 and length <= allocation and count <= 64
    assert 12 + count * 8 <= length
    entries = {}
    for index in range(count):
        slot, offset = unpack(">II", data, start + 12 + index * 8)
        assert slot not in entries and offset >= 12 + count * 8
        blob_magic, blob_length = unpack(">II", data, start + offset)
        assert blob_length >= 8 and offset + blob_length <= length
        entries[slot] = {"slot": slot, "name": SLOT_NAMES.get(slot, "unknown"),
                         "offset": offset, "absolute_offset": start + offset,
                         "magic": blob_magic, "length": blob_length}
    return length, entries


def read_cd(data, entry, image):
    start, length = entry["absolute_offset"], entry["length"]
    blob = bytes(data[start:start + length])
    fields = unpack(">9I4B", blob, 0)
    magic, length, version, flags, hashoff, identoff, nspecial, ncodes, limit, hsize, htype, platform, exponent = fields
    assert magic == 0xFADE0C02 and htype in HASHES
    assert hsize == {1: 20, 2: 32, 3: 20, 4: 48}[htype]
    assert exponent <= 20 and hashoff >= nspecial * hsize
    assert hashoff + ncodes * hsize <= length
    scatter = unpack(">I", blob, 44)[0] if version >= 0x20100 else 0
    assert scatter == 0, "Scatter layout not supported by this narrow audit"
    teamoff = unpack(">I", blob, 48)[0] if version >= 0x20200 else 0
    if version >= 0x20300:
        limit64, = unpack(">Q", blob, 56)
        if limit == 0xFFFFFFFF:
            limit = limit64
    pagesize = (1 << exponent) if exponent else limit
    assert pagesize > 0 and ncodes == math.ceil(limit / pagesize)
    assert limit <= image["size"] and limit <= image["signature"][0] - image["base"]
    execseg = unpack(">QQQ", blob, 64) if version >= 0x20400 else None
    return {"version": version, "flags": flags, "hash_offset": hashoff,
            "special_slot_count": nspecial, "code_slot_count": ncodes,
            "code_limit": limit, "hash_size": hsize, "hash_type": htype,
            "hash_name": HASHES[htype], "platform": platform,
            "page_size_exponent": exponent, "page_size": pagesize,
            "scatter_offset": scatter, "identifier": cstring(blob, identoff),
            "team_identifier": cstring(blob, teamoff) if teamoff else None,
            "exec_segment": list(execseg) if execseg else None}


def code_mismatches(data, image, entry, cd):
    results = []
    for index in range(cd["code_slot_count"]):
        start = image["base"] + index * cd["page_size"]
        end = image["base"] + min((index + 1) * cd["page_size"], cd["code_limit"])
        want = digest(data[start:end], cd["hash_name"], cd["hash_size"])
        hpos = entry["absolute_offset"] + cd["hash_offset"] + index * cd["hash_size"]
        stored = data[hpos:hpos + cd["hash_size"]]
        if stored != want:
            results.append({"index": index, "slice_page_offset": hex(start - image["base"]),
                            "absolute_page_offset": hex(start), "covered_bytes": end - start,
                            "stored": bytes(stored).hex(), "computed": want.hex()})
    return results


def requirement_tree(blob):
    """Decode the observed prefix-expression subset, failing on unknown opcodes."""
    magic, length, count = unpack(">III", blob, 0)
    assert magic == 0xFADE0C01 and length == len(blob)
    results = []
    for index in range(count):
        req_type, reqoff = unpack(">II", blob, 12 + index * 8)
        reqmagic, reqlen, kind = unpack(">III", blob, reqoff)
        assert reqmagic == 0xFADE0C00 and kind == 1 and reqoff + reqlen <= len(blob)
        pos = reqoff + 12

        def uint():
            nonlocal pos
            value, = unpack(">I", blob, pos)
            pos += 4
            assert pos <= reqoff + reqlen
            return value

        def datum():
            nonlocal pos
            size = uint()
            assert pos + size <= reqoff + reqlen
            value = blob[pos:pos + size]
            pos += (size + 3) & ~3
            return value

        def match():
            value = uint()
            return {"operation": value, "value_hex": datum().hex() if value not in (0, 14) else None}

        def expression(depth=0):
            assert depth < 32
            op = uint()
            if op in (0, 1, 3, 13, 15, 21, 23):
                return {"op": op}
            if op in (6, 7):
                return {"op": op, "left": expression(depth + 1), "right": expression(depth + 1)}
            if op == 9:
                return {"op": op, "child": expression(depth + 1)}
            if op in (2, 18, 19):
                return {"op": op, "value": datum().decode("utf-8", "backslashreplace")}
            if op == 8:
                return {"op": op, "cdhash": datum().hex()}
            if op == 4:
                return {"op": op, "cert_index": uint(), "anchor_hash": datum().hex()}
            if op in (10, 16):
                return {"op": op, "field": datum().hex(), "match": match()}
            if op in (11, 14, 17, 22):
                return {"op": op, "cert_index": uint(), "field_hex": datum().hex(), "match": match()}
            if op in (12, 20):
                return {"op": op, "value": uint()}
            raise ValueError(f"Unsupported requirement opcode {op:#x}; cannot claim absence of cdhash link")

        tree = expression()
        assert pos == reqoff + reqlen
        encoded = json.dumps(tree)
        results.append({"requirement_type": req_type, "kind": kind, "expression": tree,
                        "has_cdhash_expression": '"cdhash"' in encoded,
                        "has_apple_generic_anchor": '"op": 15' in encoded})
    return results


def special_slots(data, image, entry, cd, entries, original_path):
    records = []
    for slot in range(1, cd["special_slot_count"] + 1):
        offset = entry["absolute_offset"] + cd["hash_offset"] - slot * cd["hash_size"]
        stored = bytes(data[offset:offset + cd["hash_size"]])
        embedded = entries.get(slot)
        external = None
        if original_path.parent.name.endswith(".app"):
            if slot == 1:
                external = original_path.parent / "Info.plist"
            elif slot == 3:
                external = original_path.parent / "_CodeSignature" / "CodeResources"
        payload, origin = None, None
        if embedded:
            payload = bytes(data[embedded["absolute_offset"]:embedded["absolute_offset"] + embedded["length"]])
            origin = "embedded_superblob_entry"
        elif external and external.is_file():
            payload = external.read_bytes()
            origin = "external_bundle_file"
        # CodeDirectory::slotIsPresent treats an all-zero digest as absent.
        # An available Info.plist next to such a slot is unsealed, not a stale
        # non-zero slot hash introduced by our in-memory experiment.
        if not any(stored):
            computed = digest(payload, cd["hash_name"], cd["hash_size"]) if payload is not None else None
            status = "zero_absent_external_available" if external and payload is not None else "zero_absent"
        elif payload is not None:
            computed = digest(payload, cd["hash_name"], cd["hash_size"])
            status = "matches" if stored == computed else "mismatch"
        else:
            computed = None
            status = "not_verified_missing_external_or_embedded_blob"
        records.append({"slot": slot, "name": SLOT_NAMES.get(slot, "unknown"),
                        "stored": stored.hex(), "computed": computed.hex() if computed is not None else None,
                        "status": status, "origin": origin,
                        "external_file": str(external.relative_to(ROOT)).replace("\\", "/") if external else None})
    return records


def audit_file(info, staged_root):
    relative = Path(info["path"])
    original_path, staged_path = ROOT / relative, staged_root / relative
    original, staged = original_path.read_bytes(), staged_path.read_bytes()
    before_hashes = (digest(original), digest(staged))
    assert before_hashes[0].hex() == info["original_sha256"]
    assert before_hashes[1].hex() == info["staged_sha256"]
    assert len(original) == len(staged)
    original_slices, staged_slices = macho_slices(original), macho_slices(staged)
    assert original_slices == staged_slices
    modified = bytearray(staged)
    output = {"path": relative.as_posix(), "original_sha256": before_hashes[0].hex(),
              "staged_sha256": before_hashes[1].hex(), "file_size": len(original), "slices": []}
    for image in original_slices:
        sigstart, sigsize = image["signature"]
        super_length, entries = superblob(staged, sigstart, sigsize)
        assert original[sigstart:sigstart + sigsize] == staged[sigstart:sigstart + sigsize]
        textstart, textsize = image["text"]
        text_before = original[textstart:textstart + textsize]
        assert text_before == staged[textstart:textstart + textsize]
        row = {"slice_offset": hex(image["base"]), "cpu": hex(image["cpu"]),
               "subtype": hex(image["subtype"]), "signature_file_offset": hex(sigstart),
               "signature_allocated_bytes": sigsize, "superblob_length": super_length,
               "superblob_slots": [{**v, "slot": hex(k), "magic": hex(v["magic"]),
                                      "absolute_offset": hex(v["absolute_offset"])} for k, v in entries.items()],
               "cms_signature_slot_present": 0x10000 in entries,
               "cms_blobwrapper_present": any(v["magic"] == 0xFADE0B01 for v in entries.values()),
               "on_disk_signature_blob_unchanged": True,
               "text_sha256_before": digest(text_before).hex(),
               "code_directories": []}
        if 2 in entries:
            req = entries[2]
            row["requirements"] = requirement_tree(staged[req["absolute_offset"]:req["absolute_offset"] + req["length"]])
        for slot, entry in entries.items():
            if entry["magic"] != 0xFADE0C02:
                continue
            cd = read_cd(staged, entry, image)
            original_mismatches = code_mismatches(original, image, entry, cd)
            staged_mismatches = code_mismatches(staged, image, entry, cd)
            cdstart, cdlen = entry["absolute_offset"], entry["length"]
            cdhash_before = digest(staged[cdstart:cdstart + cdlen], cd["hash_name"], 20).hex()
            for index in range(cd["code_slot_count"]):
                page_start = image["base"] + index * cd["page_size"]
                page_end = image["base"] + min((index + 1) * cd["page_size"], cd["code_limit"])
                computed = digest(staged[page_start:page_end], cd["hash_name"], cd["hash_size"])
                pos = cdstart + cd["hash_offset"] + index * cd["hash_size"]
                modified[pos:pos + cd["hash_size"]] = computed
            after_mismatches = code_mismatches(modified, image, entry, cd)
            specials_before = special_slots(staged, image, entry, cd, entries, original_path)
            specials_after = special_slots(modified, image, entry, cd, entries, original_path)
            assert specials_before == specials_after and not after_mismatches
            row["code_directories"].append({"superblob_slot": hex(slot), **cd,
                "flags_hex": hex(cd["flags"]), "cs_adhoc_flag_set": bool(cd["flags"] & 2),
                "original_page_mismatches": original_mismatches,
                "staged_page_mismatches": staged_mismatches,
                "after_in_memory_rehash_page_mismatches": after_mismatches,
                "cdhash_before": cdhash_before,
                "cdhash_after_in_memory_rehash": digest(modified[cdstart:cdstart + cdlen], cd["hash_name"], 20).hex(),
                "special_slots": specials_before, "special_slots_unchanged_after_rehash": True})
        row["text_sha256_after_in_memory_rehash"] = digest(modified[textstart:textstart + textsize]).hex()
        row["text_unchanged_after_in_memory_rehash"] = modified[textstart:textstart + textsize] == text_before
        output["slices"].append(row)
    changed = [index for index, (a, b) in enumerate(zip(staged, modified)) if a != b]
    allowed = []
    for row in output["slices"]:
        for cd in row["code_directories"]:
            matching = next(v for v in row["superblob_slots"] if v["slot"] == cd["superblob_slot"])
            start = int(matching["absolute_offset"], 16) + cd["hash_offset"]
            allowed.append((start, start + cd["code_slot_count"] * cd["hash_size"]))
    assert all(any(a <= i < b for a, b in allowed) for i in changed)
    assert before_hashes == (digest(original_path.read_bytes()), digest(staged_path.read_bytes()))
    output.update({"in_memory_rehash_changed_bytes": len(changed),
                   "in_memory_rehash_only_changes_code_slot_hash_arrays": True,
                   "in_memory_rehash_file_size_unchanged": len(modified) == len(staged),
                   "hypothetical_rehashed_file_sha256": digest(modified).hex(),
                   "original_and_staged_files_unchanged_on_disk": True})
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "docs/evidence/sign_off_v3")
    args = parser.parse_args()
    evidence = args.evidence_dir.resolve()
    input_path = evidence / "verification_results.json"
    verification = json.loads(input_path.read_text(encoding="utf-8"))
    files = [audit_file(row, evidence / "staged_patch") for row in verification["staged_patch"]["files"]]
    slices = [s for f in files for s in f["slices"]]
    directories = [cd for s in slices for cd in s["code_directories"]]
    special_slots_all = [slot for cd in directories for slot in cd["special_slots"]]
    summary = {
        "files": len(files), "slices": len(slices), "code_directories": len(directories),
        "original_total_code_page_mismatches": sum(len(cd["original_page_mismatches"]) for cd in directories),
        "staged_total_code_page_mismatches": sum(len(cd["staged_page_mismatches"]) for cd in directories),
        "after_in_memory_rehash_total_code_page_mismatches": sum(len(cd["after_in_memory_rehash_page_mismatches"]) for cd in directories),
        "all_text_sections_unchanged_after_rehash": all(s["text_unchanged_after_in_memory_rehash"] for s in slices),
        "all_file_sizes_unchanged_after_rehash": all(f["in_memory_rehash_file_size_unchanged"] for f in files),
        "all_original_and_staged_files_unchanged_on_disk": all(f["original_and_staged_files_unchanged_on_disk"] for f in files),
        "observed_code_directory_flags": sorted({cd["flags_hex"] for cd in directories}),
        "observed_code_directory_hash_types": sorted({cd["hash_type"] for cd in directories}),
        "observed_code_directory_page_sizes": sorted({cd["page_size"] for cd in directories}),
        "slices_with_cms_signature_slot": sum(s["cms_signature_slot_present"] for s in slices),
        "slices_with_cms_blobwrapper": sum(s["cms_blobwrapper_present"] for s in slices),
        "special_slot_matches": sum(s["status"] == "matches" for s in special_slots_all),
        "special_slot_mismatches": sum(s["status"] == "mismatch" for s in special_slots_all),
        "zero_info_slots_with_unsealed_external_info_plist": sum(s["slot"] == 1 and s["status"] == "zero_absent_external_available" for s in special_slots_all),
        "special_slots_not_verified": [s for s in special_slots_all if s["status"].startswith("not_verified")],
        "all_special_slots_unchanged_after_rehash": all(cd["special_slots_unchanged_after_rehash"] for cd in directories),
        "requirements_with_embedded_cdhash_expression": sum(r["has_cdhash_expression"] for s in slices for r in s.get("requirements", [])),
        "requirements_with_apple_generic_anchor_expression": sum(r["has_apple_generic_anchor"] for s in slices for r in s.get("requirements", [])),
        "all_cdhashes_changed_after_rehash": all(cd["cdhash_before"] != cd["cdhash_after_in_memory_rehash"] for cd in directories),
    }
    output = {"scope": "Static read-only audit; hypothetical page-hash updates exist only in memory; no target execution or trust validation",
              "input_verification_json_sha256": digest(input_path.read_bytes()).hex(),
              "helper_sha256": digest(Path(__file__).read_bytes()).hex(),
              "primary_sources": SOURCES, "summary": summary, "files": files,
              "limitations": [
                  "Code-slot and present special-slot hash agreement does not establish CMS authentication, requirement satisfaction, AMFI trust, or RootHide loader acceptance.",
                  "All observed CodeDirectories have flags 0; none sets CS_ADHOC, and all inspected SuperBlobs lack a CMS signature slot or BlobWrapper.",
                  "Rehashing changes the CodeDirectory digest (cdhash); any external trust or cache binding was not inspected or updated.",
                  "XML/DER entitlement blobs are hashed as opaque bytes; semantic authorization and equivalence were not evaluated.",
                  "No Mach-O or signing material was written by this helper; the staged patch remains stale on disk.",
              ]}
    (evidence / "code_directory_rehash.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
