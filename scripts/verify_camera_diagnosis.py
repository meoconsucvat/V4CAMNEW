"""Read-only validation of camera evidence and separately staged candidates."""
from pathlib import Path
import hashlib
import importlib.util
import json

import capstone
import lief

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/camera_diagnosis"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = module("camera_package_parser", ROOT / "scripts/audit_final_package.py")
    cd = module("camera_cd_parser", ROOT / "scripts/verify_v3_code_directory.py")
    raw, members, _ = parser.archive(ROOT / "VCNext-custom-roothide.deb")
    controls, _, _ = parser.read_tar(members["control.tar.zst"])
    data, rows, _ = parser.read_tar(members["data.tar.zst"])
    relative = "Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib"
    report = {"method": "Read-only source/package bytes, independent Capstone, staged candidate validation",
              "target_runtime_executed": False, "package_sha256": sha(raw), "files": []}
    staged_root = ROOT / "dist/camera-preview-experiment"
    manifest = json.loads((staged_root / "manifest.json").read_text())
    assembly = []
    for index, name in enumerate([relative, "var/mobile/Library/pkgmirror/" + relative]):
        source = (ROOT / "extracted/data" / name).read_bytes()
        assert source == data[name]
        candidate = (staged_root / "data" / name).read_bytes()
        record = manifest["files"][index]
        assert sha(source) == record["source_sha256"] and sha(candidate) == record["candidate_sha256"]
        assert len(source) == len(candidate)
        images = cd.macho_slices(source)
        changed = {position for position, (a, b) in enumerate(zip(source, candidate)) if a != b}
        allowed = {0x547a1, 0x547b9, 0x547d1}
        directories = 0
        text = []
        for image in images:
            _, entries = cd.superblob(source, *image["signature"])
            for entry in entries.values():
                if entry["magic"] == 0xfade0c02:
                    description = cd.read_cd(source, entry, image)
                    assert not cd.code_mismatches(source, image, entry, description)
                    assert not cd.code_mismatches(candidate, image, entry, description)
                    directories += 1
                    if image["base"] == 0x34000:
                        start = entry["absolute_offset"] + description["hash_offset"] + 32 * description["hash_size"]
                        allowed.update(range(start, start + description["hash_size"]))
                else:
                    pos, length = entry["absolute_offset"], entry["length"]
                    assert candidate[pos:pos+length] == source[pos:pos+length]
            pos, length = image["text"]
            assert candidate[pos:pos+length] == source[pos:pos+length]
            text.append(sha(source[pos:pos+length]))
        assert changed <= allowed
        assert candidate[0x4000:0x4000+images[0]["size"]] == source[0x4000:0x4000+images[0]["size"]]
        report["files"].append({"path": name, "source_sha256": sha(source), "candidate_sha256": sha(candidate),
                                 "candidate_changed_bytes": len(changed), "candidate_only_expected_changes": True,
                                 "candidate_all_text_preserved": True, "arm64_slice_preserved": True,
                                 "code_directories_verified_before_and_after": directories, "code_page_mismatches": 0,
                                 "text_sha256": text, "source_matches_current_deb_member": True})
        if index == 0:
            image = lief.MachO.parse(str(ROOT / "extracted/data" / name)).at(1)
            section = image.get_section("__text")
            text_bytes = bytes(section.content)
            disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
            for begin, end in [(0x6894, 0x69f4), (0x8244, 0x8530), (0x8fd8, 0x968c), (0x996c, 0x9e48), (0x9e7c, 0x9f18)]:
                selected = text_bytes[begin-section.virtual_address:end-section.virtual_address]
                decoded = list(disassembler.disasm(selected, begin))
                assert len(decoded) * 4 == len(selected)
                assembly.append(f"\n# arm64e function 0x{begin:x}, current thin SHA256 {sha(source[0x34000:0x34000+images[1]['size']])}")
                assembly.extend(f"0x{item.address:x} {item.bytes.hex()} {item.mnemonic} {item.op_str}" for item in decoded)
    assert controls["postinst"] == (ROOT / "extracted/control/postinst").read_bytes()
    mirror = ROOT / "extracted/data/var/mobile/Library/pkgmirror/DEBIAN.com.vcnext.app/postinst"
    assert mirror.read_bytes() == controls["postinst"]
    links = [row for row in rows if row["type"] == "2" and row["path"].endswith(".roothidepatch")]
    assert len(links) == 5 and all(row["link"] == "/usr/lib/DynamicPatches/AutoPatches.dylib" for row in links)
    report["real_roothide_patch_symlinks_in_package"] = 5
    report["postinst_and_mirror_match_current_package"] = True
    report["package_sha256_unchanged"] = sha((ROOT / "VCNext-custom-roothide.deb").read_bytes()) == report["package_sha256"]
    assert report["package_sha256_unchanged"]
    report["passed"] = True
    (OUT / "renderer_arm64e_fresh.asm").write_text("\n".join(assembly) + "\n", encoding="utf-8")
    (OUT / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
