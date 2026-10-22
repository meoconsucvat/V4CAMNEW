#!/usr/bin/env python3
"""Read-only Tag 1 layout and encryption-size audit of the supplied VCNext files.

Only this tool's JSON evidence is written. Encrypted examples remain in memory;
no input executable, authority material, source module, or endpoint is changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from crypto_engine import decrypt_payload_block, encrypt_payload_block


ROOT = Path(__file__).resolve().parents[1]
MAIN_TARGETS = {
    "usr/libexec/VCNNetworkDaemon": [0xA110],
    "usr/libexec/VCNStreamDaemon": [0x11080],
    "Applications/VCNext.app/VCNext": [0x2B0D0],
    "Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib": [0x1A5C0, 0x4AF40],
    "Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib": [0x155B0, 0x3E0F0],
}
FIELDS = {
    "salt": (0x0, 0x10, 16),
    "iv2": (0x18, 0x28, 16),
    "iv1": (0x30, 0x40, 16),
    "ciphertext": (0x48, 0x188, 320),
    "hmac": (0x190, 0x1B0, 32),
}
RECORD_SIZE = 0x1B8


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def padded_ciphertext_length(plaintext_length: int) -> int:
    # Each AES-CBC encryption performs its own PKCS#7 padding, including a full
    # block when its input length is already a multiple of sixteen.
    return 16 * (plaintext_length // 16 + 2)


def slices_and_sections(data: bytes) -> list[dict]:
    """Parse only FAT records and Mach-O LC_SEGMENT_64/section_64 structures."""
    if data[:4] == b"\xca\xfe\xba\xbe":
        count = struct.unpack_from(">I", data, 4)[0]
        slices = [struct.unpack_from(">IIIII", data, 8 + 20 * i) for i in range(count)]
        ranges = [(offset, size) for _, _, offset, size, _ in slices]
    else:
        ranges = [(0, len(data))]
    result = []
    for start, size in ranges:
        assert struct.unpack_from("<I", data, start)[0] == 0xFEEDFACF
        _, cpu, subtype, _, commands, _, _, _ = struct.unpack_from("<8I", data, start)
        assert cpu == 0x100000C, f"Unexpected architecture: {cpu:x}"
        sections = []
        command_start = start + 32
        for _ in range(commands):
            command, command_size = struct.unpack_from("<II", data, command_start)
            if command == 0x19:
                section_count = struct.unpack_from("<I", data, command_start + 64)[0]
                for j in range(section_count):
                    entry = command_start + 72 + j * 80
                    name, segment, address, length, offset = struct.unpack_from("<16s16sQQI", data, entry)
                    sections.append({
                        "name": name.rstrip(b"\0").decode(),
                        "segment": segment.rstrip(b"\0").decode(),
                        "virtual_address": address,
                        "size": length,
                        "file_offset": start + offset,
                    })
            command_start += command_size
        result.append({
            "architecture": "arm64e" if subtype & 0xFFFFFF == 2 else "arm64",
            "cpu_subtype": subtype,
            "slice_file_offset": start,
            "slice_size": size,
            "sections": sections,
        })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/evidence/ui_tag1/tag1_layout.json")
    args = parser.parse_args()
    rows, input_hashes, originals = [], {}, []
    canonical_plaintext = None
    canonical_record = None
    for mirror in (False, True):
        prefix = "extracted/data/var/mobile/Library/pkgmirror/" if mirror else "extracted/data/"
        for relative_path, offsets in MAIN_TARGETS.items():
            relative = prefix + relative_path
            data = (ROOT / relative).read_bytes()
            input_hashes[relative] = sha(data)
            slices = slices_and_sections(data)
            for offset in offsets:
                record = data[offset:offset + RECORD_SIZE]
                assert len(record) == RECORD_SIZE
                owner = next(s for s in slices if s["slice_file_offset"] <= offset < s["slice_file_offset"] + s["slice_size"])
                section = next(s for s in owner["sections"] if s["segment"] == "__TEXT" and s["name"] == "__const" and s["file_offset"] <= offset < s["file_offset"] + s["size"])
                record_va = section["virtual_address"] + offset - section["file_offset"]
                parsed, field_rows = {}, {}
                for name, (value_offset, length_offset, expected_length) in FIELDS.items():
                    length = struct.unpack_from("<Q", record, length_offset)[0]
                    assert length == expected_length, (relative, offset, name, length)
                    parsed[name] = record[value_offset:value_offset + length]
                    field_rows[name] = {
                        "file_offset": hex(offset + value_offset),
                        "virtual_address": hex(record_va + value_offset),
                        "length_file_offset": hex(offset + length_offset),
                        "length_virtual_address": hex(record_va + length_offset),
                        "stored_length_u64_le": length,
                    }
                plaintext = decrypt_payload_block(1, parsed["salt"], parsed["iv1"], parsed["iv2"], parsed["ciphertext"], parsed["hmac"])
                assert json.loads(plaintext)["api_host"] == "anix204.xyz"
                if canonical_plaintext is None:
                    canonical_plaintext, canonical_record = plaintext, record
                assert plaintext == canonical_plaintext
                assert record == canonical_record
                text = next(s for s in owner["sections"] if s["segment"] == "__TEXT" and s["name"] == "__text")
                text_hash = sha(data[text["file_offset"]:text["file_offset"] + text["size"]])
                rows.append({
                    "path": relative,
                    "mirror": mirror,
                    "architecture": owner["architecture"],
                    "slice_file_offset": hex(owner["slice_file_offset"]),
                    "tag1_file_offset": hex(offset),
                    "tag1_slice_relative_offset": hex(offset - owner["slice_file_offset"]),
                    "tag1_virtual_address": hex(record_va),
                    "record_span_bytes_including_lengths": len(record),
                    "record_sha256": sha(record),
                    "record_occurrences_in_file": data.count(record),
                    "plaintext_length": len(plaintext),
                    "ciphertext_length": len(parsed["ciphertext"]),
                    "fields": field_rows,
                    "text_sha256": text_hash,
                    "hmac_and_double_aes_decryption_pass": True,
                })
                originals.append(parsed)

    assert canonical_plaintext is not None
    # Deterministic public audit fixtures, used only in memory.
    fixture_args = {"salt": bytes(range(16)), "iv1": bytes(range(16, 32)), "iv2": bytes(range(32, 48))}

    def encrypt_case(name: str, plaintext: bytes) -> dict:
        salt, iv1, iv2, ct, mac = encrypt_payload_block(1, plaintext, **fixture_args)
        decoded = decrypt_payload_block(1, salt, iv1, iv2, ct, mac)
        assert decoded == plaintext
        assert len(ct) == padded_ciphertext_length(len(plaintext))
        return {
            "case": name,
            "plaintext_length": len(plaintext),
            "ciphertext_length": len(ct),
            "fits_physical_320_byte_ciphertext_slot": len(ct) <= 320,
            "preserves_stored_320_length_without_metadata_change": len(ct) == 320,
            "roundtrip_pass": True,
            "plaintext_sha256": sha(plaintext),
            "ciphertext_sha256": sha(ct),
        }

    cases = [encrypt_case("original_authenticated_plaintext", canonical_plaintext)]
    host_bytes = b"anix204.xyz"
    assert canonical_plaintext.count(host_bytes) == 2
    for domain in ("auth.example.com", "api.example.com", "a.example.com", "a123456789.com", "e.io"):
        changed = canonical_plaintext.replace(host_bytes, domain.encode("ascii"))
        assert json.loads(changed)["api_host"] == domain
        row = encrypt_case(f"replace_both_hosts_with_{domain}", changed)
        row["host_length_ascii_bytes"] = len(domain)
        cases.append(row)
        if len(changed) < 288:
            padded = changed + b" " * (288 - len(changed))
            assert json.loads(padded) == json.loads(changed)
            cases.append(encrypt_case(f"replace_with_{domain}_then_trailing_json_whitespace_to_288", padded))
    length_tests = []
    for length in range(336):
        row = encrypt_case(f"length_{length}", b"X" * length)
        length_tests.append({"plaintext_length": length, "ciphertext_length": row["ciphertext_length"], "roundtrip_pass": True})
    fitting = [r["plaintext_length"] for r in length_tests if r["ciphertext_length"] <= 320]
    exact = [r["plaintext_length"] for r in length_tests if r["ciphertext_length"] == 320]
    unchanged = all(sha((ROOT / p).read_bytes()) == h for p, h in input_hashes.items())
    assert unchanged
    report = {
        "method": "Static file-layout parsing, stored u64 length reads, authenticated decryption and in-memory Python encryption/roundtrip tests; no binary mutation or endpoint contact",
        "source_hashes": {
            "scripts/audit_tag1_layout.py": sha(Path(__file__).read_bytes()),
            "scripts/crypto_engine.py": sha((ROOT / "scripts/crypto_engine.py").read_bytes()),
        },
        "file_count": len(input_hashes),
        "slice_count": len(rows),
        "input_sha256": input_hashes,
        "original_plaintext_utf8": canonical_plaintext.decode("utf-8"),
        "original_plaintext_length": len(canonical_plaintext),
        "original_plaintext_sha256": sha(canonical_plaintext),
        "original_json": json.loads(canonical_plaintext),
        "all_14_tag1_records_identical": len({r["record_sha256"] for r in rows}) == 1,
        "layout": {
            "record_size": RECORD_SIZE,
            "fields_relative_offsets": {k: {"value_offset": hex(v[0]), "length_u64_offset": hex(v[1]), "expected_length": v[2]} for k, v in FIELDS.items()},
            "ciphertext_capacity_before_following_length_field": 320,
            "hmac_capacity_before_following_length_field": 32,
        },
        "ciphertext_size_formula": "16 * (floor(plaintext_length / 16) + 2), two independent PKCS#7 layers",
        "max_plaintext_for_ciphertext_at_most_320": max(fitting),
        "plaintext_range_for_exact_320_ciphertext": [min(exact), max(exact)],
        "unchanged_json_fields_max_ascii_host_length_in_both_host_values": (303 - (len(canonical_plaintext) - 2 * len(host_bytes))) // 2,
        "claimed_267_byte_plaintext_would_encrypt_to_bytes": padded_ciphertext_length(267),
        "cases": cases,
        "length_tests_0_through_335": length_tests,
        "locations": rows,
        "input_binaries_unchanged": unchanged,
        "limitations": [
            "Record locations and stored values are independently read; parser behavior still needs instruction evidence from the main app audit.",
            "Python cryptographic roundtrips do not prove acceptance by an iOS native runtime.",
            "Trailing whitespace is accepted by the Python JSON test; Apple Foundation acceptance requires native validation if used.",
            "Only replacements of both api_base_url and api_host with all other JSON bytes retained are bounded by the 13-byte hostname result.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "evidence": str(args.output.resolve()),
        "files": len(input_hashes), "slices": len(rows),
        "original_plaintext_bytes": len(canonical_plaintext),
        "ciphertext_capacity": 320,
        "max_plaintext_bytes": max(fitting),
        "exact_320_plaintext_range": [min(exact), max(exact)],
        "unchanged_fields_max_host_bytes": report["unchanged_json_fields_max_ascii_host_length_in_both_host_values"],
        "cases": cases, "input_binaries_unchanged": unchanged,
    }, indent=2))


if __name__ == "__main__":
    main()
