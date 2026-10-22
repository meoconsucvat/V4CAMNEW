"""Prepare a NEW diagnostic Camera copy, never modify extracted/data or a DEB.

Default is a read-only dry run. --output-dir must name a new directory. This
changes only arm64e A14/A15/A16 profile preview bytes (+9), then recomputes the
affected CodeDirectory code-slot hashes. It does not establish AMFI acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REL = 'Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib'
SOURCES = {
    REL: '901319d0cf57ff00749fbb4e3ac4095923c5cce2d428475486fd5f386a8a6e6e',
    'var/mobile/Library/pkgmirror/' + REL:
        'c244b61a0247bdbd88eac5a7127a9c5f4df30907b8270b66ebfca1d908e2b32a',
}
PROFILES = {'iPhone13,*': 0x20798, 'iPhone14,*': 0x207b0, 'iPhone15,*': 0x207c8}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, help='New directory for experimental copies; omit for dry run')
    args = parser.parse_args()
    destination = args.output_dir.resolve() if args.output_dir is not None else None
    if destination is not None:
        protected = (ROOT / 'extracted').resolve()
        if destination == protected or protected in destination.parents:
            parser.error('Output cannot be within extracted/')
        if destination.exists():
            parser.error('Output directory already exists; choose a new path')
    spec = importlib.util.spec_from_file_location('preview_readonly_cd', ROOT / 'scripts/verify_v3_code_directory.py')
    cd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cd)
    inventory = json.loads((ROOT / 'docs/evidence/camera_diagnosis/policy_offset_inventory.json').read_text(encoding='utf-8'))
    indexed = {Path(row['path']).as_posix().removeprefix('extracted/data/'): row for row in inventory['files']}
    staged = []
    report = {
        'purpose': 'Experimental named-preview coverage only; not a proven runtime fix',
        'mode': 'staged' if destination is not None else 'dry_run',
        'output_directory': str(destination) if destination is not None else None,
        'writes_to_extracted_data': False, 'deb_built_or_deployed': False,
        'ios_executed': False, 'amfi_or_runtime_trust_verified': False,
        'preview_subclasses_enabled': False,
        'notes': ['Only +9 changes: +13 remains zero, so subclass discovery stays disabled.',
                  'A11/arm64 bytes, +15 terminal policy, +16 in-place policy and all PAC code stay unchanged.',
                  'Code-page rehash preserves special slots/CMS bytes but does not re-sign CMS or register a new cdhash.'],
        'files': [],
    }
    for relative, expected in SOURCES.items():
        source = ROOT / 'extracted/data' / relative
        before = source.read_bytes()
        assert sha(before) == expected, f'Source identity changed: {relative}'
        row = indexed[relative]
        assert row['sha256'] == expected
        images = cd.macho_slices(before)
        assert len(images) == 2 and images[0]['base'] == 0x4000 and images[1]['base'] == 0x34000
        assert images[0]['subtype'] & 0xffffff == 0 and images[1]['subtype'] & 0xffffff == 2
        image = images[1]
        policies = {p['model']: p for s in row['slices'] if s['architecture'] == 'arm64e' for p in s['profiles']}
        after = bytearray(before)
        allowed, edits = set(), []
        for model, profile in PROFILES.items():
            policy = policies[model]
            assert int(policy['profile_va'], 16) == profile
            offset = image['base'] + profile
            assert int(policy['fat_file_offset'], 16) == offset
            assert before[offset:offset+24] == bytes.fromhex(policy['raw_profile'])
            assert before[offset+9] == 0 and before[offset+13] == 0 and before[offset+16] == 1
            after[offset+9] = 1
            allowed.add(offset+9)
            edits.append({'model': model, 'thin_offset': hex(profile+9), 'fat_offset': hex(offset+9),
                          'before': 0, 'after': 1, 'preview_subclass_flag_after': after[offset+13],
                          'terminal_flag_after': after[offset+15], 'in_place_flag_after': after[offset+16]})
        _, entries = cd.superblob(before, *image['signature'])
        directory_results = []
        for slot, entry in entries.items():
            if entry['magic'] != 0xfade0c02:
                assert after[entry['absolute_offset']:entry['absolute_offset']+entry['length']] == before[entry['absolute_offset']:entry['absolute_offset']+entry['length']]
                continue
            descriptor = cd.read_cd(before, entry, image)
            assert not cd.code_mismatches(before, image, entry, descriptor)
            mismatches = cd.code_mismatches(after, image, entry, descriptor)
            assert [m['index'] for m in mismatches] == [32]
            for mismatch in mismatches:
                position = entry['absolute_offset'] + descriptor['hash_offset'] + mismatch['index'] * descriptor['hash_size']
                new_hash = bytes.fromhex(mismatch['computed'])
                assert len(new_hash) == descriptor['hash_size']
                after[position:position+len(new_hash)] = new_hash
                allowed.update(range(position, position+len(new_hash)))
            special_start = entry['absolute_offset'] + descriptor['hash_offset'] - descriptor['special_slot_count'] * descriptor['hash_size']
            special_end = entry['absolute_offset'] + descriptor['hash_offset']
            assert after[special_start:special_end] == before[special_start:special_end]
            assert not cd.code_mismatches(after, image, entry, descriptor)
            start, end = entry['absolute_offset'], entry['absolute_offset']+entry['length']
            directory_results.append({'slot': hex(slot), 'hash': descriptor['hash_name'],
                                      'flags': hex(descriptor['flags']), 'changed_code_slots': [32],
                                      'special_slots_unchanged': True, 'post_mismatches': 0,
                                      'old_cdhash': hashlib.new(descriptor['hash_name'], before[start:end]).digest()[:20].hex(),
                                      'new_cdhash': hashlib.new(descriptor['hash_name'], after[start:end]).digest()[:20].hex()})
        changed = {i for i, (a, b) in enumerate(zip(before, after)) if a != b}
        assert changed <= allowed and len(before) == len(after)
        assert all(image['base']+va+9 in changed for va in PROFILES.values())
        arm64 = images[0]
        assert after[arm64['base']:arm64['base']+arm64['size']] == before[arm64['base']:arm64['base']+arm64['size']]
        text_results = []
        for current in images:
            start, size = current['text']
            assert after[start:start+size] == before[start:start+size]
            _, original_entries = cd.superblob(before, *current['signature'])
            _, new_entries = cd.superblob(after, *current['signature'])
            for original_slot, original_entry in original_entries.items():
                new_entry = new_entries[original_slot]
                if original_entry['magic'] != 0xfade0c02:
                    pos, length = original_entry['absolute_offset'], original_entry['length']
                    assert after[pos:pos+length] == before[pos:pos+length]
                else:
                    desc = cd.read_cd(after, new_entry, current)
                    assert not cd.code_mismatches(after, current, new_entry, desc)
            text_results.append({'architecture': 'arm64e' if current['subtype'] & 0xffffff == 2 else 'arm64',
                                 'sha256': sha(before[start:start+size]), 'unchanged': True})
        assert source.read_bytes() == before
        staged.append((relative, bytes(after)))
        report['files'].append({'source': str(source.relative_to(ROOT)),
                                'candidate_path': str(Path('data') / relative),
                                'source_sha256': expected, 'candidate_sha256': sha(after),
                                'file_size': len(before), 'file_length_unchanged': True,
                                'source_unchanged': True, 'arm64_slice_byte_identical': True,
                                'all_executable_text_and_pac_bytes_unchanged': True,
                                'other_profile_flags_and_pointer_chain_words_unchanged': True,
                                'special_slots_entitlements_requirements_cms_unchanged': True,
                                'only_flags_and_code_slot_hashes_changed': True,
                                'changed_byte_count': len(changed), 'profile_edits': edits,
                                'text_slices': text_results, 'arm64e_code_directories': directory_results})
    if destination is not None:
        destination.mkdir(parents=True, exist_ok=False)
        for relative, raw in staged:
            path = destination / 'data' / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            assert path.read_bytes() == raw
        (destination / 'manifest.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
