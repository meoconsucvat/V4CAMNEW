"""Independent read-only VCAMPLUS archive/resource audit. No builder execution.

Writes only derived JSON and Markdown under docs/evidence/vcamplus/.
"""
from __future__ import annotations

from collections import Counter
from compression import zstd
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import struct
import subprocess
import tarfile
import zlib

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/evidence/vcamplus"
PACKAGE = ROOT / "dist/VCAMPLUS-roothide.deb"
BASELINE = ROOT / "VCNext-custom-roothide.deb"
ICON_NAMES = {"AppIcon.png": 60, "AppIcon@2x.png": 120,
              "AppIcon@3x.png": 180, "BrandLogo.png": 256}
APP_ROOTS = ("Applications/VCNext.app", "var/mobile/Library/pkgmirror/Applications/VCNext.app")
MIRROR_CONTROL = "var/mobile/Library/pkgmirror/DEBIAN.com.vcnext.app/"


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def parse_ar(path: Path):
    blob = path.read_bytes()
    assert blob[:8] == b"!<arch>\n"
    pos, rows, entries = 8, [], {}
    while pos < len(blob):
        header = blob[pos:pos+60]
        assert len(header) == 60 and header[58:] == b"`\n"
        name = header[:16].decode("ascii").strip().removesuffix("/")
        assert name not in entries
        length = int(header[48:58].decode("ascii").strip(), 10)
        assert length >= 0 and pos+60+length <= len(blob)
        payload = blob[pos+60:pos+60+length]
        rows.append({"name": name, "header_offset": pos, "bytes": length,
                     "mode_raw_ascii": header[40:48].decode("ascii"),
                     "mode_raw_hex": header[40:48].hex(),
                     "canonical_mode_100644": header[40:48] == b"100644  ",
                     "uid": int(header[28:34]), "gid": int(header[34:40]),
                     "mtime": int(header[16:28]), "sha256": sha(payload)})
        entries[name] = payload
        pos += 60+length
        if length % 2:
            assert blob[pos:pos+1] == b"\n"
            pos += 1
    assert pos == len(blob)
    assert list(entries) == ["debian-binary", "control.tar.zst", "data.tar.zst"]
    assert entries["debian-binary"] == b"2.0\n"
    return {"path": str(path.relative_to(ROOT)), "bytes": len(blob),
            "sha256": sha(blob), "ar_members": rows}, entries


def octal(field: bytes) -> int:
    value = field.strip(b"\0 ")
    assert value and all(c in b"01234567" for c in value), field
    return int(value, 8)


def read_tar(compressed: bytes):
    assert compressed[:4] == bytes.fromhex("28b52ffd")
    raw = zstd.decompress(compressed)
    assert len(raw) % 512 == 0
    pos, headers = 0, []
    while pos+512 <= len(raw):
        block = raw[pos:pos+512]
        if block == b"\0"*512:
            assert raw[pos:pos+1024] == b"\0"*1024 and not any(raw[pos:])
            break
        stored = octal(block[148:156])
        unsigned_sum = sum(block[:148])+8*32+sum(block[156:])
        signed_sum = sum(v if v < 128 else v-256 for v in block[:148])+8*32+sum(
            v if v < 128 else v-256 for v in block[156:])
        assert stored == unsigned_sum, (pos, stored, unsigned_sum)
        size = octal(block[124:136])
        assert pos+512+size <= len(raw)
        headers.append({"offset": pos,
                        "raw_name": block[:100].rstrip(b"\0").decode("utf-8"),
                        "raw_typeflag": block[156:157].decode("ascii"),
                        "stored_checksum_octal": block[148:156].decode("ascii"),
                        "stored_checksum_decimal": stored,
                        "computed_unsigned_checksum_decimal": unsigned_sum,
                        "computed_signed_checksum_decimal": signed_sum,
                        "unsigned_checksum_match": True,
                        "size": size,
                        "ustar_magic_hex": block[257:265].hex()})
        pos += 512+((size+511)//512)*512
    else:
        raise AssertionError("No tar end markers")
    tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    members, files, seen = [], {}, set()
    for member in tf.getmembers():
        name = member.name.removeprefix("./").rstrip("/")
        assert name not in seen
        seen.add(name)
        p = PurePosixPath(name)
        assert not p.is_absolute() and ".." not in p.parts and "\\" not in name
        assert member.isfile() or member.isdir() or member.issym(), member
        content = tf.extractfile(member).read() if member.isfile() else None
        if content is not None:
            assert len(content) == member.size
            files[name] = content
        members.append({"path": name, "typeflag": member.type.decode("ascii"),
                        "size": member.size, "mode": format(member.mode, "04o"),
                        "uid": member.uid, "gid": member.gid,
                        "uname": member.uname, "gname": member.gname,
                        "link": member.linkname or None, "pax_headers": member.pax_headers,
                        "sha256": sha(content) if content is not None else None})
    symlink_names = {row["path"] for row in members if row["typeflag"] == "2"}
    symlink_descendants = [name for name in seen if any(name.startswith(s+"/") for s in symlink_names)]
    assert not symlink_descendants
    return files, {"uncompressed_bytes": len(raw), "sha256": sha(raw),
                   "raw_header_count": len(headers), "logical_member_count": len(members),
                   "all_raw_unsigned_checksums_match": True, "headers": headers,
                   "duplicate_names": False, "unsafe_member_paths": False,
                   "symlink_descendants": symlink_descendants,
                   "end_markers_valid": True, "members": members,
                   "uid_gid_counts": dict(Counter(f"{r['uid']}:{r['gid']}" for r in members))}


def fields(blob: bytes):
    result = {}
    for line in blob.decode("utf-8").splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            k, v = line.split(":", 1)
            result[k] = v.strip()
    return result


def png_chunks(blob: bytes):
    assert blob[:8] == b"\x89PNG\r\n\x1a\n"
    pos, result = 8, []
    while pos < len(blob):
        assert pos+12 <= len(blob)
        size = struct.unpack_from(">I", blob, pos)[0]
        kind = blob[pos+4:pos+8]
        payload = blob[pos+8:pos+8+size]
        assert pos+12+size <= len(blob)
        stored = struct.unpack_from(">I", blob, pos+8+size)[0]
        computed = zlib.crc32(kind+payload)
        assert stored == computed
        result.append({"kind": kind.decode("ascii"), "bytes": size,
                       "stored_crc32": f"{stored:08x}", "computed_crc32": f"{computed:08x}"})
        pos += size+12
        if kind == b"IEND":
            assert size == 0 and pos == len(blob)
            break
    assert result[0]["kind"] == "IHDR" and result[-1]["kind"] == "IEND"
    return result


def compare_files(current, prior):
    return {"added": sorted(current.keys()-prior.keys()),
            "removed": sorted(prior.keys()-current.keys()),
            "changed": [{"path": name, "old_sha256": sha(prior[name]),
                         "new_sha256": sha(current[name]),
                         "old_bytes": len(prior[name]), "new_bytes": len(current[name])}
                        for name in sorted(current.keys() & prior.keys())
                        if current[name] != prior[name]]}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    package, entries = parse_ar(PACKAGE)
    baseline, previous = parse_ar(BASELINE)
    control, control_report = read_tar(entries["control.tar.zst"])
    data, data_report = read_tar(entries["data.tar.zst"])
    old_control, old_control_report = read_tar(previous["control.tar.zst"])
    old_data, old_data_report = read_tar(previous["data.tar.zst"])
    package["matches_requested_identity"] = (package["bytes"] == 479204 and package["sha256"] ==
        "ff13f266d898a02173224645ea0d81e47bad508ca965cd5c37e976512d71c558")
    source_logo_path = Path(r"C:\Users\Admin\Downloads\photo_2026-06-20_20-13-18.jpg")
    source_logo = None
    logo_report = {"present": source_logo_path.exists()}
    if source_logo_path.exists():
        logo_bytes = source_logo_path.read_bytes()
        image = Image.open(io.BytesIO(logo_bytes))
        image.load()
        source_logo = image.convert("RGBA")
        logo_report.update({"sha256": sha(logo_bytes), "format": image.format,
                            "mode": image.mode, "dimensions": list(image.size)})
    icons, plists = [], []
    for root in APP_ROOTS:
        for name, dimension in ICON_NAMES.items():
            path = root+"/"+name
            blob = data[path]
            image = Image.open(io.BytesIO(blob))
            image.load()
            ihdr = struct.unpack(">IIBBBBB", blob[16:29])
            alpha = image.getchannel("A").getextrema() if image.mode == "RGBA" else None
            expected = source_logo.resize((dimension, dimension), Image.Resampling.LANCZOS) if source_logo else None
            icons.append({"path": path, "bytes": len(blob), "sha256": sha(blob),
                          "format": image.format, "mode": image.mode,
                          "dimensions": list(image.size), "expected_dimension": dimension,
                          "dimensions_match": image.size == (dimension, dimension),
                          "PNG_IHDR_bit_depth": ihdr[2], "PNG_IHDR_color_type": ihdr[3],
                          "PNG_IHDR_compression_filter_interlace": list(ihdr[4:]),
                          "alpha_extrema": list(alpha) if alpha else None,
                          "all_alpha_opaque": alpha == (255, 255),
                          "chunks": png_chunks(blob),
                          "all_png_chunk_crcs_valid": True,
                          "matches_source_lanczos_rgba_pixels": image.tobytes() == expected.tobytes() if expected else None})
        path = root+"/Info.plist"
        blob = data[path]
        parsed = plistlib.loads(blob)
        old_parsed = plistlib.loads(old_data[path])
        changed = {k: {"old": old_parsed.get(k), "new": parsed.get(k)} for k in sorted(parsed.keys() | old_parsed.keys())
                   if parsed.get(k) != old_parsed.get(k)}
        plists.append({"path": path, "format": "binary" if blob.startswith(b"bplist00") else "xml",
                       "sha256": sha(blob), "fields": parsed, "changed_fields": changed,
                       "identifier_preserved": parsed.get("CFBundleIdentifier") == old_parsed.get("CFBundleIdentifier") == "com.vcnext.app",
                       "name_fields_vcamplus": parsed.get("CFBundleDisplayName") == parsed.get("CFBundleName") == "VCAMPLUS"})
    scripts = []
    shell = Path(r"C:\Program Files\Git\bin\bash.exe")
    for name in ("preinst", "postinst", "prerm", "postrm"):
        if name not in control:
            continue
        blob = control[name]
        source = ROOT / "extracted/control" / name
        syntax = subprocess.run([str(shell), "--noprofile", "--norc", "--posix", "-n", str(source)],
                                capture_output=True, text=True)
        scripts.append({"name": name, "sha256": sha(blob), "mode": next(r["mode"] for r in control_report["members"] if r["path"] == name),
                        "equal_baseline": blob == old_control[name],
                        "equal_source": blob == source.read_bytes(),
                        "equal_packaged_mirror": blob == data.get(MIRROR_CONTROL+name),
                        "mirror_difference_preexisting_in_baseline":
                            (blob != data.get(MIRROR_CONTROL+name)) and old_control[name] != old_data.get(MIRROR_CONTROL+name),
                        "equal_source_mirror": blob == (ROOT / "extracted/data" / (MIRROR_CONTROL+name)).read_bytes(),
                        "lf_only": b"\r" not in blob, "syntax_check": "bash --posix -n on identical source; not installer execution",
                        "syntax_exit": syntax.returncode, "syntax_stderr": syntax.stderr})
    metadata = {"main": fields(control["control"]), "mirror": fields(data[MIRROR_CONTROL+"control"])}
    metadata["same_main_mirror"] = metadata["main"] == metadata["mirror"]
    metadata["baseline_main"] = fields(old_control["control"])
    metadata["baseline_mirror"] = fields(old_data[MIRROR_CONTROL+"control"])
    metadata["maintainer_email_shaped"] = bool(re.search(r"<[^<>\s@]+@[^<>\s@]+>", metadata["main"].get("Maintainer", "")))
    symlinks = [r for r in data_report["members"] if r["typeflag"] == "2"]
    source_comparison = []
    for name, blob in sorted(data.items()):
        source_path = ROOT / "extracted/data" / name
        source_comparison.append({"path": name, "exists": source_path.is_file(),
                                  "same_as_extracted": source_path.is_file() and blob == source_path.read_bytes()})
    md5_checks = []
    for name, blob in control.items():
        if name == "md5sums":
            for line in blob.decode().splitlines():
                expected, path = line.split(None, 1)
                path = path.strip()
                actual = hashlib.md5(data[path]).hexdigest() if path in data else None
                md5_checks.append({"path": path, "expected": expected, "actual": actual, "match": actual == expected})
    result = {"scope": "read-only local archive/resources/maintainer-script parity; no builder, install, server, or binary execution",
              "package": package, "baseline": baseline,
              "control_tar": control_report, "data_tar": data_report,
              "symlinks": symlinks, "symlink_count": len(symlinks),
              "all_five_autopatches_type2": len(symlinks) == 5 and all(r["link"] == "/usr/lib/DynamicPatches/AutoPatches.dylib" and r["typeflag"] == "2" for r in symlinks),
              "source_logo": logo_report, "icons": icons, "info_plists": plists,
              "assets_car_present": any(name.endswith("Assets.car") for name in data),
              "metadata": metadata, "scripts": scripts, "control_md5sums_checks": md5_checks,
              "baseline_control_comparison": compare_files(control, old_control),
              "baseline_data_comparison": compare_files(data, old_data),
              "source_data_comparison": source_comparison,
              "member_metadata_equals_baseline": {
                  "control": [{"path": r["path"], "changed": {k: {"old": next(x[k] for x in old_control_report["members"] if x["path"] == r["path"]), "new": r[k]}
                    for k in ("mode", "uid", "gid", "typeflag", "link")
                    if r[k] != next(x[k] for x in old_control_report["members"] if x["path"] == r["path"])}}
                    for r in control_report["members"]],
                  "data": [{"path": r["path"], "changed": {k: {"old": next(x[k] for x in old_data_report["members"] if x["path"] == r["path"]), "new": r[k]}
                    for k in ("mode", "uid", "gid", "typeflag", "link")
                    if r[k] != next(x[k] for x in old_data_report["members"] if x["path"] == r["path"])}}
                    for r in data_report["members"]]}}
    (OUT / "archive_resources.json").write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    summary = {"identity": package, "tar_checksums": {"control": control_report["raw_header_count"], "data": data_report["raw_header_count"]},
               "logical_members": {"control": control_report["logical_member_count"], "data": data_report["logical_member_count"]},
               "symlinks": result["symlink_count"], "metadata": metadata,
               "icons_all_verified": all(i["dimensions_match"] and i["mode"] == "RGBA" and i["matches_source_lanczos_rgba_pixels"] for i in icons),
               "changed_data_paths": [r["path"] for r in result["baseline_data_comparison"]["changed"]],
               "script_baseline_source_and_syntax_all_pass": all(s["equal_baseline"] and s["equal_source"] and s["syntax_exit"] == 0 for s in scripts),
               "preinst_postinst_mirror_parity_pass": all(s["equal_packaged_mirror"] and s["equal_source_mirror"] for s in scripts if s["name"] in ("preinst", "postinst")),
               "prerm_mirror_difference_preexisting": next(s["mirror_difference_preexisting_in_baseline"] for s in scripts if s["name"] == "prerm")}
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
