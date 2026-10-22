"""Read-only overlay audit. Writes derived evidence only under docs/evidence/overlay."""
from pathlib import Path
import bisect, hashlib, importlib.metadata, json, struct
import capstone, lief

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/overlay'
TARGET = ROOT / 'extracted/data/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib'
MIRROR = ROOT / 'extracted/data/var/mobile/Library/pkgmirror/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib'

def sha(data): return hashlib.sha256(data).hexdigest()
def analyze(path, label):
    raw = path.read_bytes()
    slices = lief.MachO.parse(str(path))
    result = {'path': str(path.relative_to(ROOT)), 'sha256': sha(raw), 'size': len(raw), 'slices': []}
    for index, binary in enumerate(slices):
        base = binary.fat_offset
        # FAT header records are big endian and declare the exact slice size.
        cpu, subtype, fat_off, fat_size, align = struct.unpack_from('>IIIII', raw, 8 + index * 20)
        assert fat_off == base
        text = binary.get_section('__text')
        symbols = {s.value: s.name for s in binary.symbols if s.value}
        indirect_symbols = list(binary.dynamic_symbol_command.indirect_symbols)
        for section in binary.sections:
            if section.name in ('__stubs', '__auth_stubs'):
                stride = section.reserved2
                assert stride > 0
                for ordinal in range(section.size // stride):
                    symbols[section.virtual_address + ordinal * stride] = indirect_symbols[section.reserved1 + ordinal].name
        starts = list(binary.function_starts.functions)
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        # Decode each aligned word so unknown instructions never silently end the scan.
        instructions, undecoded = [], []
        for offset in range(0, text.size, 4):
            chunk = bytes(text.content[offset:offset+4])
            decoded = list(md.disasm(chunk, text.virtual_address + offset))
            if decoded: instructions.append(decoded[0])
            else: undecoded.append(hex(text.virtual_address + offset))
        branches = []
        lines = []
        for ins in instructions:
            owner_index = bisect.bisect_right(starts, ins.address)-1
            owner = starts[owner_index] if owner_index >= 0 else None
            annotation = ''
            if ins.mnemonic in ('bl', 'b') and ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_IMM:
                dest = ins.operands[0].imm
                branches.append({'source':hex(ins.address),'bytes':ins.bytes.hex(),'mnemonic':ins.mnemonic,'target':hex(dest),'target_symbol':symbols.get(dest),'function_start':hex(owner) if owner is not None else None})
                annotation = ' ; ' + symbols.get(dest, '')
            lines.append(f'{ins.address:08x}  {ins.bytes.hex():8}  {ins.mnemonic:10} {ins.op_str}{annotation}')
        architecture = 'arm64' if subtype == 0 else 'arm64e'
        (OUT / f'{label}_{architecture}_text.asm').write_text('\n'.join(lines)+'\n', encoding='utf-8')
        imports = sorted(s.name for s in binary.imported_symbols)
        init = binary.get_section('__init_offsets')
        interesting = {name: [x for x in branches if x['target_symbol']==name] for name in ('_VCN5d92c005b0c38441000a','_VCN583d21a4038aaf46dd3e','_CC_SHA256','_SecKeyVerifySignature')}
        verifier = next(s.value for s in binary.symbols if s.name=='_VCN5d92c005b0c38441000a')
        # Raw absolute pointer scan is supplemental; chained/relative references need separate handling.
        ptr = struct.pack('<Q',verifier)
        pointer_hits = [hex(i) for i in range(fat_size-7) if raw[base+i:base+i+8]==ptr]
        result['slices'].append({'architecture':architecture,'cpu':hex(cpu),'subtype':hex(subtype),'fat_offset':hex(base),'fat_size':hex(fat_size),'slice_sha256':sha(raw[base:base+fat_size]),'text_sha256':sha(bytes(text.content)),'text_va':hex(text.virtual_address),'text_size':hex(text.size),'decoded_instructions':len(instructions),'undecoded_word_addresses':undecoded,'verifier_va':hex(verifier),'raw_absolute_verifier_pointer_offsets':pointer_hits,'init_offsets':[hex(x[0]) for x in struct.iter_unpack('<I',bytes(init.content))] if init else [],'imports':imports,'exported_symbols':{s.name:hex(s.value) for s in binary.exported_symbols},'rpaths':[c.path for c in binary.commands if isinstance(c,lief.MachO.RPathCommand)],'libraries':[c.name for c in binary.libraries],'uuid':str(binary.uuid.uuid) if binary.has_uuid else None,'sections':[{'name':s.name,'va':hex(s.virtual_address),'offset':hex(s.offset),'size':hex(s.size)} for s in binary.sections],'function_starts':[hex(x) for x in starts],'interesting_direct_branches':interesting})
        (OUT / f'{label}_{architecture}_direct_branches.json').write_text(json.dumps(branches,indent=2)+'\n',encoding='utf-8')
    return result

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    result={'method':'LIEF parse plus Capstone decode of each aligned __text word; no target execution', 'versions':{p:importlib.metadata.version(p) for p in ('lief','capstone')},'artifacts':[analyze(TARGET,'main'),analyze(MIRROR,'pkgmirror')]}
    result['main_pkgmirror_text_comparison'] = [{'architecture':a['architecture'],'byte_identical':bytes(lief.MachO.parse(str(TARGET)).at(i).get_section('__text').content)==bytes(lief.MachO.parse(str(MIRROR)).at(i).get_section('__text').content),'main_text_sha256':a['text_sha256'],'mirror_text_sha256':b['text_sha256']} for i,(a,b) in enumerate(zip(result['artifacts'][0]['slices'],result['artifacts'][1]['slices']))]
    (OUT/'static_inventory.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'versions':result['versions'],'artifacts':[{'path':a['path'],'sha256':a['sha256'],'slices':[{'arch':s['architecture'],'verifier':s['verifier_va'],'direct_verifier_branches':s['interesting_direct_branches']['_VCN5d92c005b0c38441000a'],'undecoded':s['undecoded_word_addresses'],'init':s['init_offsets']} for s in a['slices']]} for a in result['artifacts']]},indent=2))

if __name__=='__main__': main()
