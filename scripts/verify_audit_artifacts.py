"""Compare original Debian archive Mach-O members with extracted audit inputs."""
from pathlib import Path
import hashlib, io, json, tarfile
from compression import zstd

ROOT = Path(__file__).resolve().parents[1]
def sha(b): return hashlib.sha256(b).hexdigest()
def main():
    deb = ROOT / 'VCNext-0.16.73-roothide.deb'
    raw = deb.read_bytes()
    assert raw[:8] == b'!<arch>\n'
    entries, offset = {}, 8
    while offset < len(raw):
        header = raw[offset:offset+60]
        size = int(header[48:58])
        entries[header[:16].decode().strip().rstrip('/')] = raw[offset+60:offset+60+size]
        offset += 60 + size + size % 2
    archive = tarfile.open(fileobj=io.BytesIO(zstd.decompress(entries['data.tar.zst'])),mode='r:')
    members, markers = [], []
    for member in archive.getmembers():
        relative = member.name.removeprefix('./')
        if member.issym() and 'roothidepatch' in relative:
            markers.append({'archive_path':relative,'link_target':member.linkname})
        if not member.isfile(): continue
        original = archive.extractfile(member).read()
        if original[:4] not in (b'\xca\xfe\xba\xbe', b'\xcf\xfa\xed\xfe'): continue
        path = ROOT / 'extracted/data' / relative
        current = path.read_bytes()
        members.append({'path':relative,'sha256_original_deb':sha(original),'sha256_extracted':sha(current),'byte_identical':original==current})
    result = {'package_sha256':sha(raw),'macho_members':members,'roothide_symlinks_in_original_archive':markers,'all_macho_members_unchanged':all(m['byte_identical'] for m in members)}
    (ROOT/'docs/evidence/overlay/artifact_preservation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
    assert result['all_macho_members_unchanged']
if __name__=='__main__': main()
