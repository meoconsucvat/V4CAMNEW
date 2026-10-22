"""Audit package identities, slices and code-page hashes without modifying inputs."""
from pathlib import Path
from compression import zstd
import hashlib
import importlib.util
import io
import json
import struct
import tarfile
import capstone
import lief

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'docs/evidence/arm64e'
TARGETS = [
    'usr/libexec/VCNNetworkDaemon', 'usr/libexec/VCNStreamDaemon',
    'Applications/VCNext.app/VCNext',
    'Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib',
    'Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib',
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def data_tar(path):
    data = path.read_bytes()
    assert data[:8] == b'!<arch>\n'
    entries = {}
    pos = 8
    while pos < len(data):
        header = data[pos:pos+60]
        size = int(header[48:58])
        entries[header[:16].decode().strip().rstrip('/')] = data[pos+60:pos+60+size]
        pos += 60 + size + size % 2
    name = next(n for n in entries if n.startswith('data.tar'))
    payload = zstd.decompress(entries[name]) if name.endswith('.zst') else entries[name]
    return sha(data), tarfile.open(fileobj=io.BytesIO(payload), mode='r:*')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('arm64e_cd_audit', ROOT/'scripts/verify_v3_code_directory.py')
    cd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cd)
    original_sha, original_tar = data_tar(ROOT/'VCNext-0.16.73-roothide.deb')
    custom_sha, custom_tar = data_tar(ROOT/'VCNext-custom-roothide.deb')
    original = {m.name.removeprefix('./'):original_tar.extractfile(m).read()
                for m in original_tar.getmembers() if m.isfile()}
    custom = {m.name.removeprefix('./'):custom_tar.extractfile(m).read()
              for m in custom_tar.getmembers() if m.isfile()}
    rows = []
    for mirror in (False, True):
        for relative in TARGETS:
            name = ('var/mobile/Library/pkgmirror/' if mirror else '') + relative
            raw, old = custom[name], original[name]
            target = OUT/'custom_payload'/name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                assert target.read_bytes() == raw
            else:
                target.write_bytes(raw)
            extracted = ROOT/'extracted/data'/name
            row = {'path':name, 'original_sha256':sha(old), 'custom_sha256':sha(raw),
                   'current_extracted_sha256':sha(extracted.read_bytes()),
                   'current_extracted_equals_custom':extracted.read_bytes() == raw,
                   'slices':[]}
            owner = lief.MachO.parse(str(target))
            old_slices = cd.macho_slices(old)
            for index, image in enumerate(cd.macho_slices(raw)):
                binary = owner.at(index)
                start, size = image['base'], image['size']
                arch = 'arm64e' if image['subtype'] & 0xffffff == 2 else 'arm64'
                thin = OUT/'thin'/('mirror' if mirror else 'main')/(Path(relative).name+'_'+arch+'.macho')
                thin.parent.mkdir(parents=True, exist_ok=True)
                thin_bytes = raw[start:start+size]
                old_start = old_slices[index]['base']
                command_size = struct.unpack_from('<I', thin_bytes, 20)[0]
                header_unchanged = thin_bytes[:32+command_size] == old[old_start:old_start+32+command_size]
                fixups_unchanged = True
                cmdpos = 32
                for _ in range(struct.unpack_from('<I', thin_bytes, 16)[0]):
                    cmd, cmdsize = struct.unpack_from('<II', thin_bytes, cmdpos)
                    if cmd in (0x80000034, 0x80000022, 0x22):
                        # Chained fixups, or each rebase/bind/weak/lazy/export range.
                        pairs = 1 if cmd == 0x80000034 else 5
                        for pair in range(pairs):
                            dataoff, datasize = struct.unpack_from('<II', thin_bytes, cmdpos+8+pair*8)
                            fixups_unchanged &= thin_bytes[dataoff:dataoff+datasize] == old[old_start+dataoff:old_start+dataoff+datasize]
                    cmdpos += cmdsize
                auth_sections = []
                for section in binary.sections:
                    if 'auth' in section.name:
                        offset, section_size = section.offset, section.size
                        auth_sections.append({'name':section.name, 'size':section_size,
                            'unchanged':thin_bytes[offset:offset+section_size] == old[old_start+offset:old_start+offset+section_size]})
                if thin.exists():
                    assert thin.read_bytes() == thin_bytes
                else:
                    thin.write_bytes(thin_bytes)
                text_start, text_size = image['text']
                old_text_start, old_text_size = old_slices[index]['text']
                text = raw[text_start:text_start+text_size]
                equal = text_size == old_text_size and text == old[old_text_start:old_text_start+old_text_size]
                sigstart, sigsize = image['signature']
                _, entries = cd.superblob(raw, sigstart, sigsize)
                directories = []
                for slot, entry in entries.items():
                    if entry['magic'] == 0xfade0c02:
                        record = cd.read_cd(raw, entry, image)
                        directories.append({'slot':hex(slot), 'flags':hex(record['flags']),
                                            'hash_type':record['hash_type'],
                                            'page_size':record['page_size'],
                                            'code_limit':record['code_limit'],
                                            'mismatches':cd.code_mismatches(raw, image, entry, record)})
                md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
                instructions = []
                for offset in range(0, len(text), 4):
                    decoded = list(md.disasm(text[offset:offset+4], binary.get_section('__text').virtual_address+offset))
                    assert len(decoded) == 1
                    instructions.append(decoded[0])
                pac = [{'address':hex(i.address),'opcode':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
                       for i in instructions if i.mnemonic.startswith(('pac','aut','braa','brab','blraa','blrab','retaa','retab','xpac'))]
                symbols = {s.name:hex(s.value) for s in binary.symbols if s.value}
                label = Path(relative).name+'_'+arch
                if not mirror:
                    (OUT/(label+'_text.asm')).write_text('\n'.join(
                        f'{i.address:#x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in instructions)+'\n', encoding='utf-8')
                    (OUT/(label+'_symbols.json')).write_text(json.dumps(symbols,indent=2)+'\n', encoding='utf-8')
                row['slices'].append({'arch':arch,'cpu_type':hex(image['cpu']),
                                      'cpu_subtype':hex(image['subtype']), 'slice_file_offset':hex(start),
                                      'slice_size':size, 'text_sha256':sha(text),
                                      'text_unchanged_from_original':equal, 'thin_path':str(thin.relative_to(ROOT)),
                                      'header_and_load_commands_unchanged':header_unchanged,
                                      'dyld_fixups_and_bindings_unchanged':fixups_unchanged,
                                      'authenticated_pointer_sections':auth_sections,
                                      'code_directories':directories, 'pac_instructions':pac,
                                      'instruction_count':len(instructions)})
            rows.append(row)
    summary = {'original_deb_sha256':original_sha,'custom_deb_sha256':custom_sha,
               'files':len(rows),'slices':sum(len(f['slices']) for f in rows),
               'code_directories':sum(len(s['code_directories']) for f in rows for s in f['slices']),
               'code_page_mismatches':sum(len(c['mismatches']) for f in rows for s in f['slices'] for c in s['code_directories']),
               'all_text_unchanged':all(s['text_unchanged_from_original'] for f in rows for s in f['slices']),
               'all_headers_and_fixups_unchanged':all(s['header_and_load_commands_unchanged'] and s['dyld_fixups_and_bindings_unchanged'] for f in rows for s in f['slices']),
               'all_authenticated_pointer_sections_unchanged':all(a['unchanged'] for f in rows for s in f['slices'] for a in s['authenticated_pointer_sections']),
               'all_current_extracted_match_custom':all(f['current_extracted_equals_custom'] for f in rows),
               'artifacts':rows}
    (OUT/'artifact_manifest.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in summary.items() if k != 'artifacts'},indent=2))


if __name__ == '__main__':
    main()
