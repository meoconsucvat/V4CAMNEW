"""Audit-only verification. Apply the supplied patcher to isolated copies, never inputs.

Writes public certificates, staged binaries, and test evidence under docs/evidence/sign_off.
Reads the existing signing key without copying or printing private material.
"""
from pathlib import Path
import argparse, base64, contextlib, hashlib, importlib.util, io, json, os, plistlib
import shutil, struct, subprocess, sys, time
from types import SimpleNamespace
from unittest.mock import patch
import lief
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evidence/sign_off'
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def sign_ok(e,pub):
    try:
        pub.verify(base64.b64decode(e['signature'],validate=True),json.dumps(e['lease'],sort_keys=True,separators=(',',':')).encode(),padding.PKCS1v15(),hashes.SHA256());return True
    except Exception:return False
def run_command(command,filename):
    r=subprocess.run([sys.executable,*command],cwd=ROOT,capture_output=True,encoding='utf-8')
    (OUT/filename).write_text(json.dumps({'command':[sys.executable,*command],'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr},indent=2)+'\n',encoding='utf-8')
    assert r.returncode==0,r.stderr
def main():
    global OUT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,default=OUT)
    args=parser.parse_args()
    OUT=args.output_dir.resolve()
    OUT.mkdir(exist_ok=True,parents=True)
    patcher=load('audited_patcher',ROOT/'scripts/patch_authority_in_binaries.py')
    service=load('audited_service',ROOT/'scripts/local_renewal_service.py')
    model=load('audited_model',ROOT/'scripts/cross_audit_verify.py')
    keypath=ROOT/'mocks/test_server_private_key.pem'
    key=serialization.load_pem_private_key(keypath.read_bytes(),None)
    source_hashes={p:sha((ROOT/p).read_bytes()) for p in ['scripts/patch_authority_in_binaries.py','scripts/local_renewal_service.py','scripts/crypto_engine.py','scripts/lease_generator.py','extracted/control/control','extracted/control/postinst','extracted/data/Library/LaunchDaemons/com.vcnext.networkd.plist']}
    input_hashes={p:sha((ROOT/p).read_bytes()) for p in patcher.TARGET_OFFSETS}
    run_command(['scripts/patch_authority_in_binaries.py'],'patcher_run.json')
    before_uptime=time.monotonic();before_epoch=time.time()
    run_command(['scripts/local_renewal_service.py','mocks','mocks/test_server_private_key.pem','--once'],'service_run.json')
    after_uptime=time.monotonic();after_epoch=time.time()
    service_raw=(ROOT/'mocks/CapabilityLease.plist').read_bytes()
    (OUT/'CapabilityLease.service.audited.plist').write_bytes(service_raw)
    envelope=plistlib.loads(service_raw)

    stage=OUT/'staged_patch'
    # Only known target paths are copied. Existing inputs are never overwritten.
    for name in patcher.TARGET_OFFSETS:
        target=stage/name;target.parent.mkdir(exist_ok=True,parents=True)
        if target.exists():raise FileExistsError('Staging output already exists: '+str(target))
        shutil.copy2(ROOT/name,target)
    original_builder=patcher.build_replacement_block
    generated={}
    def capture_block(der,tp):
        b=original_builder(der,tp);generated.update(der=der,thumbprint=tp,block=b);return b
    patcher.build_replacement_block=capture_block
    patcher.KEY_PATH=str(keypath)
    # The patcher now writes public certificates through ROOT_DIR even in dry-run.
    # Keep staged apply's certificate writes and original-certificate read isolated.
    (stage/'mocks').mkdir(exist_ok=True,parents=True)
    shutil.copy2(ROOT/'mocks/server_cert.pem',stage/'mocks/server_cert.pem')
    patcher.ROOT_DIR=str(stage)
    capture=io.StringIO();previous=os.getcwd()
    try:
        os.chdir(stage)
        with contextlib.redirect_stdout(capture):patcher.patch_binaries(dry_run=False)
    finally:os.chdir(previous)
    (OUT/'staged_apply.txt').write_text(capture.getvalue(),encoding='utf-8')
    der=generated['der'];newcert=x509.load_der_x509_certificate(der)
    (OUT/'staged_authority.der').write_bytes(der)
    relative_lengths=[16,40,64,136,176,200,224,248,1344]
    rows=[]
    all_text_equal=True;all_confined=True
    for name,offsets in patcher.TARGET_OFFSETS.items():
        original=(ROOT/name).read_bytes();updated=(stage/name).read_bytes()
        before=lief.MachO.parse(str(ROOT/name));after=lief.MachO.parse(str(stage/name))
        allowed=lambda i:any(off<=i<off+1384 for off in offsets)
        differences=[i for i,(x,y) in enumerate(zip(original,updated)) if x!=y]
        confined=len(original)==len(updated) and all(allowed(i) for i in differences)
        all_confined &= confined
        slices=[]
        for b,a in zip(before,after):
            bt=bytes(b.get_section('__text').content);at=bytes(a.get_section('__text').content)
            equal=bt==at;all_text_equal &= equal
            slices.append({'cpu':str(b.header.cpu_type),'subtype':hex(b.header.cpu_subtype),'fat_offset':hex(b.fat_offset),'text_sha256_before':sha(bt),'text_sha256_after':sha(at),'text_byte_identical':equal})
        blocks=[]
        for off in offsets:
            old=original[off:off+1392];new=updated[off:off+1392]
            sections=[]
            for b in before:
                for s in b.sections:
                    if s.name=='__const' and off>=b.fat_offset+s.offset and off+1384<=b.fat_offset+s.offset+s.size:
                        sections.append({'segment':s.segment_name,'section':s.name,'subtype':hex(b.header.cpu_subtype)})
            lengths=[{'relative_offset':hex(i),'file_offset':hex(off+i),'before':struct.unpack_from('<Q',old,i)[0],'after':struct.unpack_from('<Q',new,i)[0]} for i in relative_lengths]
            # Model actual runtime length arguments loaded by the binary, rather than hardcoded test lengths.
            native_lengths={'salt':struct.unpack_from('<Q',new,200)[0],'iv2':struct.unpack_from('<Q',new,224)[0],'iv1':struct.unpack_from('<Q',new,248)[0],'ciphertext':struct.unpack_from('<Q',new,1344)[0],'mac':struct.unpack_from('<Q',new,1384)[0]}
            orig_tag2=patcher.decrypt_payload_block(2,old[:16],old[48:64],old[24:40],old[72:136],old[144:176])
            def stored_length(start,length_offset):
                return new[start:start+struct.unpack_from('<Q',new,length_offset)[0]]
            patched_tag2=patcher.decrypt_payload_block(2,stored_length(0,16),stored_length(48,64),stored_length(24,40),stored_length(72,136),stored_length(144,176))
            patched_der=patcher.decrypt_payload_block(3,stored_length(184,200),stored_length(232,248),stored_length(208,224),stored_length(256,1344),stored_length(1352,1384))
            blocks.append({'offset':hex(off),'containing_sections':sections,'nine_length_fields':lengths,'runtime_tag3_lengths':native_lengths,'runtime_length_preconditions_pass':native_lengths['salt']==16 and native_lengths['iv2']==16 and native_lengths['iv1']==16 and native_lengths['ciphertext']>0 and native_lengths['mac']==32,'original_tag2':orig_tag2.hex(),'new_tag2':patched_tag2.hex(),'new_tag3_sha256':sha(patched_der),'tag3_bytes_match_generated_certificate':patched_der==der})
        mirror_prefix='extracted/data/var/mobile/Library/pkgmirror/'
        mirror=ROOT/name if name.startswith(mirror_prefix) else ROOT/mirror_prefix/Path(name).relative_to('extracted/data')
        rows.append({'path':name,'original_sha256':sha(original),'staged_sha256':sha(updated),'file_size_before':len(original),'file_size_after':len(updated),'changed_byte_count':len(differences),'diff_confined_to_declared_ranges':confined,'slices':slices,'blocks':blocks,'pkgmirror_exists':mirror.exists(),'pkgmirror_was_targeted_by_patcher':mirror.relative_to(ROOT).as_posix() in patcher.TARGET_OFFSETS if mirror.exists() else False})

    cases=[]
    def renewal_case(name,auth,notify_result=True):
        directory=OUT/'service_cases'/name;directory.mkdir(exist_ok=True,parents=True)
        if auth is not None:(directory/'AuthSession.plist').write_bytes(auth)
        capture=io.StringIO()
        with patch.object(service,'post_darwin_notification',return_value=notify_result) as notify,contextlib.redirect_stdout(capture):service.renew_lease_cycle(str(directory),key)
        e=plistlib.loads((directory/'CapabilityLease.plist').read_bytes())
        return {'case':name,'identity':{'device_id':e['device_id'],'device_key_thumbprint':e['device_key_thumbprint']},'published':True,'notification_arguments':notify.call_args.args,'notification_result_injected':notify_result,'success_reported':('TTL=90s' in capture.getvalue()),'matches_valid_input_identity':e['device_id']=='audit-device' and e['device_key_thumbprint']=='audit-thumbprint'}
    cases.append(renewal_case('valid_auth',plistlib.dumps({'device_id':'audit-device','device_key_thumbprint':'audit-thumbprint'})))
    cases.append(renewal_case('missing_auth',None))
    cases.append(renewal_case('malformed_auth',b'not a plist'))
    cases.append(renewal_case('notify_false',plistlib.dumps({'device_id':'audit-device','device_key_thumbprint':'audit-thumbprint'}),False))
    perm_dir=OUT/'service_cases/permission_failure';perm_dir.mkdir(exist_ok=True,parents=True)
    # Simulated POSIX permission failure; no real ownership change is attempted on this Windows host.
    with patch.object(service.os,'name','posix'),patch.object(service.os,'chmod',side_effect=PermissionError('audit chmod denied')),patch.object(service.os,'chown',create=True) as chown:
        service.atomic_publish_lease(envelope,str(perm_dir/'CapabilityLease.plist'))
        chown_after_chmod_failure=chown.called
    perm_result={'simulated_chmod_failed':True,'publication_still_succeeded':(perm_dir/'CapabilityLease.plist').exists(),'chown_attempted_after_chmod_failed':chown_after_chmod_failure}
    sleeps=[];attempts=[];elapsed=[0]
    def fake_sleep(seconds):
        sleeps.append(seconds);elapsed[0]+=seconds
        if len(sleeps)>3:raise KeyboardInterrupt()
    def fake_cycle(*args,**kwargs):
        attempts.append(elapsed[0])
        if len(attempts)==2:raise OSError('injected write failure')
    with patch.object(service.time,'sleep',side_effect=fake_sleep),patch.object(service.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(service,'renew_lease_cycle',side_effect=fake_cycle),contextlib.redirect_stdout(io.StringIO()):service.run_renewal_service('mocks',str(keypath))
    clockids=[]
    def fake_clock(clockid,ptr):
        clockids.append(clockid);ptr._obj.tv_sec=100;ptr._obj.tv_nsec=0;return 0
    with patch.object(service.sys,'platform','darwin'),patch.object(service.ctypes,'CDLL',return_value=SimpleNamespace(clock_gettime=fake_clock)):
        fake_uptime=service.get_system_uptime()
    unchanged={p:sha((ROOT/p).read_bytes())==digest for p,digest in input_hashes.items()}
    assert all(unchanged.values())
    sample_snapshot=OUT/'CapabilityLease.service.audited.plist'
    lease=envelope['lease']
    pkcs1=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.PKCS1)
    result={'scope':'Staged static patch experiment, Windows one-shot execution and fault injection; no iOS runtime validation',
        'reviewed_source_sha256':source_hashes,'input_binaries_unchanged':unchanged,
        'fit':{'certificate_der_bytes':len(der),'ciphertext_tag3_bytes':len(generated['block'][256:1344]),'combined_block_bytes':len(generated['block']),'generated_cert_sha256':sha(der),'disk_custom_cert_der_bytes':len(x509.load_pem_x509_certificate((ROOT/'mocks/custom_server_cert.pem').read_bytes()).public_bytes(serialization.Encoding.DER)),'new_pin_is_server_spki_sha256':generated['thumbprint']==hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest(),'new_pin_matches_server_pkcs1_sha256':generated['thumbprint']==hashlib.sha256(pkcs1).digest()},
        'staged_patch':{'all_text_sections_unchanged':all_text_equal,'all_diffs_confined':all_confined,'target_block_count':sum(len(v) for v in patcher.TARGET_OFFSETS.values()),'files':rows},
        'service_once':{'output_sha256':sha(service_raw),'snapshot':str(sample_snapshot.relative_to(ROOT)),'auth_session_present_for_requested_command':(ROOT/'mocks/AuthSession.plist').exists(),'ttl':lease['expires_at']-lease['issued_at'],'capabilities':lease['capabilities'],'receipt_between_host_monotonic_measurements':before_uptime<=envelope['received_uptime']<=after_uptime,'issued_epoch_within_run':int(before_epoch)<=lease['issued_at']<=int(after_epoch),'signature_valid_current_key':sign_ok(envelope,key.public_key()),'signature_valid_generated_staged_authority':sign_ok(envelope,newcert.public_key()),'reconstructed_reader_accepts_with_matching_host_clock_and_test_key':model.native_model(envelope,key.public_key(),after_uptime,after_epoch),'darwin_notification_exercised':False,'ios_posix_permissions_exercised':False},
        'service_identity_notification_cases':cases,'simulated_permission_failure':perm_result,'retry_schedule_seconds':{'sleep_calls':sleeps,'renewal_attempts_since_start':attempts,'fault_injection_uses_no_real_sleep':True},'mock_darwin_clock_call':{'clock_ids':clockids,'returned':fake_uptime},
    }
    (OUT/'verification_results.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'fit':result['fit'],'patch':{'text_unchanged':all_text_equal,'all_confined':all_confined,'blocks':result['staged_patch']['target_block_count'],'all_runtime_length_preconditions_pass':all(b['runtime_length_preconditions_pass'] for f in rows for b in f['blocks'])},'service_once':result['service_once'],'faults':{'permission':perm_result,'retry':result['retry_schedule_seconds'],'clock':result['mock_darwin_clock_call'],'identity_notify':cases}},indent=2))
if __name__=='__main__':main()
