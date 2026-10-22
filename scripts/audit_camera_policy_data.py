"""Read-only policy/section audit for the exact VCNext Camera package lineage."""
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
OUT = ROOT / 'docs/evidence/camera_diagnosis'
REL = 'Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib'
PROFILES = [('iPhone9,*', 0x20720), ('iPhone10,*', 0x20738), ('iPhone11,*', 0x20750),
            ('iPhone12,*', 0x20780), ('iPhone13,*', 0x20798), ('iPhone14,*', 0x207b0),
            ('iPhone15,*', 0x207c8)]
FIELDS = {8: 'enabled', 9: 'preview_named', 10: 'photo_named', 11: 'output',
          12: 'output_subclasses', 13: 'preview_subclasses_enable',
          14: 'preview_subclasses_ios16_only', 15: 'connected_consumer_output',
          16: 'in_place', 17: 'in_place_dedup', 18: 'in_place_purpose_half'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original_camera_members():
    raw = (ROOT / 'VCNext-0.16.73-roothide.deb').read_bytes()
    assert raw[:8] == b'!<arch>\n'
    pos, payload = 8, None
    while pos < len(raw):
        head = raw[pos:pos+60]
        name = head[:16].decode().strip().rstrip('/')
        size = int(head[48:58])
        if name.startswith('data.tar'):
            payload = raw[pos+60:pos+60+size]
            if name.endswith('.zst'):
                payload = zstd.decompress(payload)
            break
        pos += 60 + size + size % 2
    assert payload is not None
    wanted = {REL, 'var/mobile/Library/pkgmirror/' + REL}
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:*') as archive:
        return {m.name.removeprefix('./'): archive.extractfile(m).read()
                for m in archive.getmembers() if m.name.removeprefix('./') in wanted}


def main():
    originals = original_camera_members()
    spec = importlib.util.spec_from_file_location('camera_readonly_cd', ROOT / 'scripts/verify_v3_code_directory.py')
    cd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cd)
    result = {'method': 'Current bytes + LIEF load commands + independent Capstone; no target execution',
              'model_aliases_are_marketing_mappings_not_runtime_observation': True, 'files': []}
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    for name in (REL, 'var/mobile/Library/pkgmirror/' + REL):
        path = ROOT / 'extracted/data' / name
        raw = path.read_bytes()
        owner = lief.MachO.parse(str(path))
        old = originals[name]
        images = cd.macho_slices(raw)
        slices = []
        for index in range(owner.size):
            binary = owner.at(index)
            base = binary.fat_offset
            arch = 'arm64e' if binary.header.cpu_subtype & 0xffffff == 2 else 'arm64'
            section = next(s for s in binary.sections if s.segment_name == '__DATA_CONST' and s.name == '__const')
            segment = next(s for s in binary.segments if s.name == '__DATA_CONST')
            text = binary.get_section('__text')
            profiles = []
            for model, va in PROFILES:
                offset = section.offset + va - section.virtual_address
                block = raw[base+offset:base+offset+24]
                # These exact low 32-bit targets are independently corroborated
                # by the prior decoded IDA pointer table; do not rewrite chained
                # rebase words by treating the raw pointer as a plain address.
                raw_pointer = struct.unpack_from('<Q', block)[0]
                string_va = raw_pointer & 0xffffffff
                cstring = binary.get_section('__cstring')
                assert cstring.virtual_address <= string_va < cstring.virtual_address + cstring.size
                label_offset = cstring.offset + string_va - cstring.virtual_address
                label_end = raw.index(b'\0', base + label_offset)
                label = raw[base+label_offset:label_end].decode('ascii')
                profiles.append({'model': model, 'label': label, 'profile_va': hex(va),
                                 'slice_offset': hex(offset), 'fat_file_offset': hex(base+offset),
                                 'raw_pointer_word': hex(raw_pointer), 'raw_profile': block.hex(),
                                 'same_profile_bytes_as_original_package': block == old[base+offset:base+offset+24],
                                 'flags': {FIELDS[i]: block[i] for i in FIELDS},
                                 'preview_byte_fat_offset': hex(base+offset+9),
                                 'preview_subclass_byte_fat_offset': hex(base+offset+13)})
            text_bytes = raw[base+text.offset:base+text.offset+text.size]
            image = images[index]
            _, entries = cd.superblob(raw, *image['signature'])
            directories = []
            for slot, entry in entries.items():
                if entry['magic'] != 0xfade0c02:
                    continue
                descriptor = cd.read_cd(raw, entry, image)
                directories.append({'slot': hex(slot), 'hash': descriptor['hash_name'],
                                    'page_size': descriptor['page_size'], 'code_limit': descriptor['code_limit'],
                                    'policy_code_slot': 0x20798 // descriptor['page_size'],
                                    'policy_page_covered': 0x207d1 < descriptor['code_limit'],
                                    'existing_code_page_mismatches': len(cd.code_mismatches(raw, image, entry, descriptor))})
            slices.append({'architecture': arch, 'fat_base': hex(base),
                           'text_sha256': sha(text_bytes), 'code_directories': directories,
                           'section': {'segment': '__DATA_CONST', 'section': '__const',
                                       'virtual_address': hex(section.virtual_address),
                                       'slice_offset': hex(section.offset), 'size': hex(section.size),
                                       'segment_initial_protection': int(segment.init_protection),
                                       'segment_maximum_protection': int(segment.max_protection),
                                       'segment_flags': int(segment.flags)}, 'profiles': profiles})
            if arch == 'arm64e' and name == REL:
                ranges = [(0x47f8, 0x4830), (0x59a0, 0x5ae0), (0x7e70, 0x7eb0),
                          (0x7f00, 0x8040), (0x80e4, 0x81d0), (0x8260, 0x8380),
                          (0x83e4, 0x843c), (0x84c8, 0x84f0)]
                lines = []
                for start, end in ranges:
                    lines.extend(f'{i.address:#x} {i.bytes.hex()} {i.mnemonic} {i.op_str}'
                                 for i in md.disasm(raw[base+start:base+end], start))
                OUT.mkdir(parents=True, exist_ok=True)
                (OUT / 'policy_and_fallback_fresh_arm64e.asm').write_text('\n'.join(lines)+'\n', encoding='utf-8')
        assert path.read_bytes() == raw
        result['files'].append({'path': str(path.relative_to(ROOT)), 'sha256': sha(raw),
                                'prior_pac_identity_matches': sha(raw) == ('901319d0cf57ff00749fbb4e3ac4095923c5cce2d428475486fd5f386a8a6e6e' if name == REL else 'c244b61a0247bdbd88eac5a7127a9c5f4df30907b8270b66ebfca1d908e2b32a'),
                                'source_unchanged': True, 'slices': slices})
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'policy_offset_inventory.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'files': len(result['files']), 'slices': sum(len(x['slices']) for x in result['files']),
                      'all_profiles_equal_original': all(p['same_profile_bytes_as_original_package'] for x in result['files'] for s in x['slices'] for p in s['profiles']),
                      'all_inputs_unchanged': all(x['source_unchanged'] for x in result['files'])}))


if __name__ == '__main__':
    main()
