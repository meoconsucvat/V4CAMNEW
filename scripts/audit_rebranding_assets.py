"""Read-only bundle/resource/signature inventory for the rebranding audit.

Only writes derived evidence beneath docs/evidence/rebranding/assets_*.json.
Does not build, sign, load, or alter an application or package.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import plistlib
import struct

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/rebranding"


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def relative(path):
    return path.relative_to(ROOT).as_posix()


def main():
    cd = module("rebrand_cd", "verify_v3_code_directory.py")
    package = module("rebrand_package", "audit_final_package.py")
    raw, entries, ar = package.archive(ROOT / "VCNext-custom-roothide.deb")
    data, members, _ = package.read_tar(entries["data.tar.zst"])
    control, _, _ = package.read_tar(entries["control.tar.zst"])
    result = {"package_sha256": sha(raw), "package_bytes": len(raw), "ar": ar,
              "bundles": [], "symlinks": [x for x in members if x["type"] == "2"],
              "control": control["control"].decode("utf-8"), "controls": [], "bundle_tar_metadata": [x for x in members if "Applications/VCNext.app" in x["path"]]}
    for bundle in (ROOT / "extracted/data/Applications/VCNext.app",
                   ROOT / "extracted/data/var/mobile/Library/pkgmirror/Applications/VCNext.app"):
        files = []
        for path in sorted(bundle.rglob("*")):
            if not path.is_file():
                continue
            value = path.read_bytes()
            archive_path = path.relative_to(ROOT / "extracted/data").as_posix()
            item = {"path": relative(path), "bytes": len(value), "sha256": sha(value),
                    "matches_package_file": data.get(archive_path) == value}
            if path.suffix.lower() == ".png":
                assert value[:8] == b"\x89PNG\r\n\x1a\n"
                w, h, bits, color, compression, filtering, interlace = struct.unpack_from(">IIBBBBB", value, 16)
                chunks, offset = [], 8
                while offset < len(value):
                    length, = struct.unpack_from(">I", value, offset)
                    chunks.append(value[offset + 4:offset + 8].decode("ascii"))
                    offset += 12 + length
                assert offset == len(value)
                with Image.open(path) as image:
                    image.load()
                    alpha = image.getchannel("A") if "A" in image.getbands() else None
                    item["png"] = {"width": w, "height": h, "bits": bits, "color_type": color,
                                   "compression": compression, "filtering": filtering,
                                   "interlace": interlace, "chunks": chunks, "pillow_mode": image.mode,
                                   "alpha_extrema": list(alpha.getextrema()) if alpha else None,
                                   "not_fully_opaque_pixels": sum(alpha.histogram()[:255]) if alpha else 0}
            files.append(item)
        info_bytes = (bundle / "Info.plist").read_bytes()
        image_bytes = (bundle / "VCNext").read_bytes()
        info = {"path": relative(bundle), "files": files, "info": plistlib.loads(info_bytes),
                "info_encoding": "binary" if info_bytes.startswith(b"bplist00") else "xml",
                "info_sha256": sha(info_bytes), "info_sha1": hashlib.sha1(info_bytes).hexdigest(),
                "has_assets_car": (bundle / "Assets.car").exists(),
                "has_code_resources": (bundle / "_CodeSignature/CodeResources").exists(),
                "localization_directories": [relative(x) for x in bundle.rglob("*.lproj")],
                "code_signatures": []}
        for image in cd.macho_slices(image_bytes):
            _, subblobs = cd.superblob(image_bytes, *image["signature"])
            sig = {"slice_base": image["base"], "cpu": image["cpu"], "subtype": image["subtype"],
                   "blobs": subblobs, "directories": []}
            for slot, entry in subblobs.items():
                if entry["magic"] == 0xfade0c02:
                    descriptor = cd.read_cd(image_bytes, entry, image)
                    sig["directories"].append({"slot": slot, **descriptor,
                        "code_page_mismatches": cd.code_mismatches(image_bytes, image, entry, descriptor),
                        "special_slots": cd.special_slots(image_bytes, image, entry, descriptor, subblobs, bundle / "VCNext")})
                elif slot == 5:
                    sig["xml_entitlements"] = plistlib.loads(image_bytes[entry["absolute_offset"] + 8:entry["absolute_offset"] + entry["length"]])
                elif slot == 2:
                    sig["requirements"] = cd.requirement_tree(image_bytes[entry["absolute_offset"]:entry["absolute_offset"] + entry["length"]])
            info["code_signatures"].append(sig)
        result["bundles"].append(info)
    for name, value in control.items():
        mirror = "var/mobile/Library/pkgmirror/DEBIAN.com.vcnext.app/" + name
        path = ROOT / "extracted/control" / name
        result["controls"].append({"name": name, "sha256": sha(value),
            "extracted_equals_packaged": path.read_bytes() == value,
            "mirror_equals_packaged": data.get(mirror) == value})
    result["bundle_dicts_equal"] = result["bundles"][0]["info"] == result["bundles"][1]["info"]
    result["all_packaged_bundle_files_match"] = all(x["matches_package_file"] for b in result["bundles"] for x in b["files"] if not x["path"].endswith(".symlink"))
    result["all_code_pages_match"] = all(not d["code_page_mismatches"] for b in result["bundles"] for s in b["code_signatures"] for d in s["directories"])
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "assets_inventory.json"
    target.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": relative(target), "package_sha256": result["package_sha256"],
        "bundle_dicts_equal": result["bundle_dicts_equal"], "all_packaged_bundle_files_match": result["all_packaged_bundle_files_match"],
        "all_code_pages_match": result["all_code_pages_match"], "symlinks": len(result["symlinks"])}, indent=2))


if __name__ == "__main__":
    main()
