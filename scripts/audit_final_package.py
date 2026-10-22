"""Read-only structural/package audit; writes only derived JSON evidence."""
from pathlib import Path, PurePosixPath
from compression import zstd
import hashlib
import importlib.util
import io
import json
import plistlib
import struct
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/final_sign_off'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def archive(path):
    raw = path.read_bytes()
    assert raw[:8] == b'!<arch>\n'
    entries, records = {}, []
    pos = 8
    while pos < len(raw):
        hdr = raw[pos:pos+60]
        assert len(hdr) == 60 and hdr[58:] == b'`\n'
        name = hdr[:16].decode('ascii').strip().removesuffix('/')
        size = int(hdr[48:58].decode('ascii').strip())
        assert name not in entries and size >= 0 and pos+60+size <= len(raw)
        entries[name] = raw[pos+60:pos+60+size]
        records.append({'name':name, 'size':size, 'uid':int(hdr[28:34]),
                        'gid':int(hdr[34:40]), 'mode':hdr[40:48].decode().strip(),
                        'mode_octal_digits_only':bool(hdr[40:48].strip()) and
                            all(c in b'01234567' for c in hdr[40:48].strip())})
        if size % 2:
            assert raw[pos+60+size:pos+61+size] == b'\n'
        pos += 60 + size + size % 2
    assert pos == len(raw)
    assert list(entries) == ['debian-binary','control.tar.zst','data.tar.zst']
    assert entries['debian-binary'] == b'2.0\n'
    return raw, entries, records


def read_tar(compressed):
    assert compressed[:4] == b'\x28\xb5\x2f\xfd'
    raw = zstd.decompress(compressed)
    assert len(raw) % 512 == 0
    pos, checked = 0, 0
    while pos+512 <= len(raw):
        block = raw[pos:pos+512]
        if block == b'\0'*512:
            assert raw[pos:pos+1024] == b'\0'*1024
            assert not any(raw[pos:])
            break
        ti = tarfile.TarInfo.frombuf(block, 'utf-8', 'surrogateescape')
        assert ti.size >= 0
        checked += 1
        pos += 512 + ((ti.size+511)//512)*512
    else:
        raise AssertionError('Missing tar end markers')
    tf = tarfile.open(fileobj=io.BytesIO(raw), mode='r:')
    members, files, seen, rows = tf.getmembers(), {}, set(), []
    for member in members:
        name = member.name.removeprefix('./').rstrip('/')
        assert name not in seen, name
        seen.add(name)
        p = PurePosixPath(name)
        assert not p.is_absolute() and '..' not in p.parts, name
        assert member.isfile() or member.isdir() or member.issym() or member.islnk(), name
        if member.isfile():
            files[name] = tf.extractfile(member).read()
            assert len(files[name]) == member.size
        rows.append({'path':name, 'type':member.type.decode('ascii'), 'size':member.size,
                     'mode':oct(member.mode), 'uid':member.uid, 'gid':member.gid,
                     'uname':member.uname, 'gname':member.gname, 'link':member.linkname or None,
                     'pax_headers':member.pax_headers})
    return files, rows, {'uncompressed_bytes':len(raw), 'raw_headers_checksum_valid':checked,
                        'duplicate_names':False, 'unsafe_member_paths':False, 'end_markers_valid':True}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    raw, entries, ar_records = archive(ROOT/'VCNext-custom-roothide.deb')
    control, control_rows, control_tar = read_tar(entries['control.tar.zst'])
    data, data_rows, data_tar = read_tar(entries['data.tar.zst'])
    _, old_entries, _ = archive(ROOT/'VCNext-0.16.73-roothide.deb')
    original, _, _ = read_tar(old_entries['data.tar.zst'])
    prior = json.loads((ROOT/'docs/evidence/arm64e/artifact_manifest.json').read_text())
    spec = importlib.util.spec_from_file_location('final_cd', ROOT/'scripts/verify_v3_code_directory.py')
    cd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cd)
    binaries = []
    for old_record in prior['artifacts']:
        name = old_record['path']
        blob = data[name]
        old = original[name]
        row = {'path':name,'sha256':sha(blob),'same_as_prior_audited_binary':sha(blob)==old_record['custom_sha256'],
               'same_as_current_extracted':blob==(ROOT/'extracted/data'/name).read_bytes(),'slices':[]}
        old_slices = cd.macho_slices(old)
        for index, image in enumerate(cd.macho_slices(blob)):
            text_offset, text_size = image['text']
            original_offset, original_size = old_slices[index]['text']
            _, subblobs = cd.superblob(blob,*image['signature'])
            code_dirs = []
            for slot, item in subblobs.items():
                if item['magic'] == 0xfade0c02:
                    parsed = cd.read_cd(blob,item,image)
                    code_dirs.append({'slot':hex(slot),'hash_type':parsed['hash_type'],
                        'page_size':parsed['page_size'],'mismatches':cd.code_mismatches(blob,image,item,parsed)})
            row['slices'].append({'cpu':hex(image['cpu']),'subtype':hex(image['subtype']),
                'text_sha256':sha(blob[text_offset:text_offset+text_size]),
                'text_identical_to_original':text_size==original_size and
                    blob[text_offset:text_offset+text_size]==old[original_offset:original_offset+original_size],
                'code_directories':code_dirs})
        binaries.append(row)
    scripts, shell_results = [], []
    bash = 'C:/Program Files/Git/bin/bash.exe'
    for name in ('preinst','postinst','prerm','postrm'):
        if name not in control:
            continue
        mirror = 'var/mobile/Library/pkgmirror/DEBIAN.com.vcnext.app/'+name
        mainpath = ROOT/'extracted/control'/name
        blob = control[name]
        syntax = subprocess.run([bash,'--noprofile','--norc','-n',str(mainpath)], capture_output=True,text=True)
        scripts.append({'name':name,'sha256':sha(blob),'mode':next(r['mode'] for r in control_rows if r['path']==name),
            'control_equals_extracted':blob==mainpath.read_bytes(),
            'control_equals_packaged_mirror':blob==data.get(mirror),
            'control_equals_extracted_mirror':blob==(ROOT/'extracted/data'/mirror).read_bytes(),
            'lf_only':b'\r' not in blob,'bash_posix_syntax_exit':syntax.returncode,'syntax_stderr':syntax.stderr})
        if name in ('preinst','postinst'):
            mirror_syntax = subprocess.run([bash,'--noprofile','--norc','--posix','-n',
                str(ROOT/'extracted/data'/mirror)],capture_output=True,text=True)
            scripts[-1]['mirror_bash_posix_syntax_exit'] = mirror_syntax.returncode
            scripts[-1]['mirror_syntax_stderr'] = mirror_syntax.stderr
    # Only the isolated product-model helper is executed, with sysctl and uname
    # replaced by mocks. No product installer body is ever executed.
    postinst = control['postinst'].decode()
    helper = postinst[postinst.index('get_hardware_model() {'):postinst.index('\n}\n',postinst.index('get_hardware_model() {'))+3]
    helper = helper.replace('/usr/sbin/sysctl','mock_sysctl')
    for native,fallback,status,expected in [
        ('iPhone12,1','arm64',0,'iPhone12,1'),('iPhone14,2','arm64',0,'iPhone14,2'),
        ('','iPhone12,8',1,'iPhone12,8'),('arm64','iPhone11,8',0,'iPhone11,8'),
        ('iPad13,4','arm64',0,'iPad13,4'),('','arm64',1,'arm64')]:
        code = (f"set -eu\nmock_sysctl() {{ printf '%s\\n' '{native}'; return {status}; }}\n"
                f"uname() {{ printf '%s\\n' '{fallback}'; }}\n{helper}\nget_hardware_model\n")
        response = subprocess.run([bash,'--noprofile','--norc','--posix','-c',code],capture_output=True,text=True)
        shell_results.append({'native':native,'fallback':fallback,'sysctl_status':status,
                              'expected':expected,'stdout':response.stdout.strip(),'exit':response.returncode,
                              'pass':response.stdout.strip()==expected and response.returncode==0})
    symlinks = [r for r in data_rows if r['type']=='2']
    plists = {name:plistlib.loads(blob) for name,blob in data.items() if name.endswith('.plist')}
    main_executables = [r for r in data_rows if r['path'] in [b['path'] for b in binaries]]
    result = {
        'package_name':'VCNext-custom-roothide.deb','package_bytes':len(raw),'sha256':sha(raw),
        'server_download_copy_same':raw==(ROOT/'server/VCNext-custom-roothide.deb').read_bytes(),
        'ar_headers':ar_records, 'control_tar':control_tar,'data_tar':data_tar,
        'all_ar_mode_fields_canonical_octal':all(r['mode_octal_digits_only'] for r in ar_records),
        'control_members':control_rows,'data_members':data_rows,
        'symlinks':symlinks,'symlink_count':len(symlinks),
        'all_symlinks_target_autopatches':all(r['link']=='/usr/lib/DynamicPatches/AutoPatches.dylib' for r in symlinks),
        'binary_modes':main_executables,'binaries':binaries,'binary_count':len(binaries),
        'slices':sum(len(b['slices']) for b in binaries),
        'code_directories':sum(len(s['code_directories']) for b in binaries for s in b['slices']),
        'code_page_mismatches':sum(len(c['mismatches']) for b in binaries for s in b['slices'] for c in s['code_directories']),
        'all_text_identical_to_original':all(s['text_identical_to_original'] for b in binaries for s in b['slices']),
        'all_binaries_equal_previous_audit':all(b['same_as_prior_audited_binary'] for b in binaries),
        'scripts':scripts,'model_helper_tests':shell_results,'plist_count_parsed':len(plists),
        'camera_default_filter':plists['Library/MobileSubstrate/DynamicLibraries/VCNextCamera.plist'],
        'stream_launchd':plists['Library/LaunchDaemons/com.vcnext.streamd.plist'],
        'network_launchd':plists['Library/LaunchDaemons/com.vcnext.networkd.plist'],
    }
    (OUT/'package.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k in (
        'package_bytes','sha256','server_download_copy_same','symlink_count','all_symlinks_target_autopatches',
        'binary_count','slices','code_directories','code_page_mismatches','all_text_identical_to_original',
        'all_binaries_equal_previous_audit','scripts','model_helper_tests')},indent=2))


if __name__ == '__main__':
    main()
