"""Observational cross-audit; runs requested sample generator, never modifies iOS inputs.

Python acceptance model is an analyst reconstruction, NOT an iOS execution test.
No private key bytes are copied or printed. Evidence is written under docs/evidence.
"""
from pathlib import Path
import argparse, base64, contextlib, copy, hashlib, importlib.util, io, json, math
import plistlib, subprocess, sys, time
import lief
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/cross_audit'
def sha(b): return hashlib.sha256(b).hexdigest()
def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')
def signature_valid(envelope, public_key):
    try:
        public_key.verify(base64.b64decode(envelope['signature'],validate=True),json_bytes(envelope['lease']),padding.PKCS1v15(),hashes.SHA256())
        return True
    except Exception: return False
def native_model(envelope, key, uptime, now):
    """Safe model for ordinary finite values, reporting rejection instead of ObjC exceptions."""
    lease = envelope.get('lease')
    if not isinstance(lease,dict): return False
    num = lambda v: type(v) in (int,float) and math.isfinite(v)
    if not all(num(x) for x in [envelope.get('received_uptime'),lease.get('issued_at'),lease.get('expires_at')]): return False
    if lease.get('version') != 2 or lease.get('purpose')!='capability.lease': return False
    if lease.get('issuer')!='vcnext-main' or lease.get('audience')!='vcnext-ios' or lease.get('build')!='37': return False
    if lease.get('device_id') != envelope.get('device_id') or lease.get('device_key_thumbprint') != envelope.get('device_key_thumbprint'): return False
    if not isinstance(lease.get('capabilities'),list): return False
    ttl = lease['expires_at']-lease['issued_at']
    delta = uptime-envelope['received_uptime']
    return 0<ttl<=95 and 0<=delta<ttl and now<lease['expires_at'] and signature_valid(envelope,key)

def main():
    global OUT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,default=OUT)
    args=parser.parse_args()
    OUT=args.output_dir.resolve()
    OUT.mkdir(parents=True,exist_ok=True)
    generator = load_module('audited_generator',ROOT/'scripts/lease_generator.py')
    crypto = load_module('audited_crypto',ROOT/'scripts/crypto_engine.py')
    key = serialization.load_pem_private_key((ROOT/'mocks/test_server_private_key.pem').read_bytes(),None)
    start = time.time()
    run = subprocess.run([sys.executable,'scripts/lease_generator.py'],cwd=ROOT,capture_output=True,text=True,encoding='utf-8')
    assert run.returncode==0,run.stderr
    sample_raw = (ROOT/'mocks/CapabilityLease_sample.plist').read_bytes()
    envelope = plistlib.loads(sample_raw)
    lease = envelope['lease']
    (OUT/'generator_run.json').write_text(json.dumps({'command':[sys.executable,'scripts/lease_generator.py'],'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr,'started_epoch':start,'finished_epoch':time.time()},indent=2),encoding='utf-8')
    (OUT/'CapabilityLease_sample.audited.plist').write_bytes(sample_raw)
    (OUT/'sample_signed_bytes.python.json').write_bytes(json_bytes(lease))
    camera = ROOT/'extracted/data/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib'
    slices = lief.MachO.parse(str(camera))
    arm = slices.at(0)
    symbols = {s.name:s.value for s in arm.symbols if s.value}
    def blob(name,size): return bytes(arm.get_content_from_virtual_address(symbols[name],size))
    # Parameters are corroborated by IDA's sub_11864; never write patched blocks.
    salt=blob('_VCNbc3b38ee6e34059c33ba',16)
    iv2=blob('_VCN0ceeb3e517db039b3dfd',16)
    iv1=blob('_VCNe48ba16672456cc9502b',16)
    ct=blob('_VCN54246e55027d8124ec44',1088)
    mac=blob('_VCNf60eae9391342d238ef1',32)
    der=crypto.decrypt_payload_block(3,salt,iv1,iv2,ct,mac)
    embedded=x509.load_der_x509_certificate(der)
    overlay_path=ROOT/'extracted/data/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib'
    overlay=lief.MachO.parse(str(overlay_path)).at(0)
    overlay_symbols={s.name:s.value for s in overlay.symbols if s.value}
    def overlay_blob(name,size):return bytes(overlay.get_content_from_virtual_address(overlay_symbols[name],size))
    overlay_der=crypto.decrypt_payload_block(3,overlay_blob('_VCNbc3b38ee6e34059c33ba',16),overlay_blob('_VCNe48ba16672456cc9502b',16),overlay_blob('_VCN0ceeb3e517db039b3dfd',16),overlay_blob('_VCN54246e55027d8124ec44',1088),overlay_blob('_VCNf60eae9391342d238ef1',32))
    custom=x509.load_pem_x509_certificate((ROOT/'mocks/custom_server_cert.pem').read_bytes())
    original_export=x509.load_pem_x509_certificate((ROOT/'mocks/server_cert.pem').read_bytes())
    records=[]
    for index,b in enumerate(slices):
        arch='arm64' if b.header.cpu_subtype==0 else 'arm64e'
        text=bytes(b.get_section('__text').content)
        records.append({'architecture':arch,'subtype':hex(b.header.cpu_subtype),'fat_offset':hex(b.fat_offset),'text_va':hex(b.get_section('__text').virtual_address),'text_size':len(text),'sha256_lief':sha(text),'generator_parser':generator.calculate_text_section_digest(str(camera),arch),'documented_constant':generator.ARM64_TEXT_DIGEST if arch=='arm64' else generator.ARM64E_TEXT_DIGEST})
    cases=[]
    now=lease['issued_at']+1
    for name,mutate,up,wall,resign in [
        ('matching synthetic device uptime',lambda e:None,envelope['received_uptime']+1,now,False),
        ('device uptime already 1 hour',lambda e:None,3600.0,now,False),
        ('device uptime before received marker',lambda e:None,envelope['received_uptime']-1,now,False),
        ('wall-clock expiration',lambda e:None,121.0,lease['expires_at']+1,False),
        ('envelope device mismatch',lambda e:e.__setitem__('device_id','DIFFERENT'),121.0,now,False),
        ('envelope thumbprint mismatch',lambda e:e.__setitem__('device_key_thumbprint','DIFFERENT'),121.0,now,False),
        ('issuer mismatch signed with test key',lambda e:e['lease'].__setitem__('issuer','other-issuer'),121.0,now,True),
        ('audience mismatch signed with test key',lambda e:e['lease'].__setitem__('audience','other-audience'),121.0,now,True),
        ('received uptime wrong class',lambda e:e.__setitem__('received_uptime','120.0'),121.0,now,False),
    ]:
        e=copy.deepcopy(envelope);mutate(e)
        if resign:e['signature']=base64.b64encode(key.sign(json_bytes(e['lease']),padding.PKCS1v15(),hashes.SHA256())).decode()
        capture=io.StringIO()
        with contextlib.redirect_stdout(capture): helper=generator.verify_capability_lease_envelope(e,key.public_key())
        cases.append({'case':name,'python_helper_accepts':helper,'reconstructed_runtime_model_accepts':native_model(e,key.public_key(),up,wall),'simulated_device_uptime':up,'simulated_epoch':wall})
    ttl_200_exception=None
    try:
        extra=generator.generate_capability_lease_envelope('d','t',key,ttl_seconds=200,current_timestamp=now,current_uptime=121)
        accepts_ttl200=extra['lease']['expires_at']-extra['lease']['issued_at']==200
    except ValueError as error:
        accepts_ttl200=False
        ttl_200_exception=str(error)
    boundary_cases=[]
    for requested_ttl in [-1,0,0.5,1,90,95,95.1,200]:
        try:
            e=generator.generate_capability_lease_envelope('d','t',key,ttl_seconds=requested_ttl,current_timestamp=now,current_uptime=121)
            with contextlib.redirect_stdout(io.StringIO()):valid=generator.verify_capability_lease_envelope(e,key.public_key())
            boundary_cases.append({'requested_ttl':requested_ttl,'generated':True,'actual_ttl':e['lease']['expires_at']-e['lease']['issued_at'],'helper_accepts':valid})
        except Exception as error:
            boundary_cases.append({'requested_ttl':requested_ttl,'generated':False,'exception_type':type(error).__name__})
    capability_cases=[]
    for name,caps in [('all_five',list(generator.REQUIRED_CAPABILITIES) if hasattr(generator,'REQUIRED_CAPABILITIES') else ['camera.fake-frame','camera.obs','media.import','camera.controls','camera.color-sync']),('two_core_only',['camera.fake-frame','camera.controls']),('empty',[]),('nonstr_element',['camera.fake-frame','camera.obs','media.import','camera.controls','camera.color-sync',42])]:
        e=generator.generate_capability_lease_envelope('d','t',key,current_timestamp=now,current_uptime=121,capabilities=caps)
        with contextlib.redirect_stdout(io.StringIO()):valid=generator.verify_capability_lease_envelope(e,key.public_key())
        capability_cases.append({'case':name,'helper_accepts':valid,'all_elements_string':all(type(c)is str for c in e['lease']['capabilities']),'capabilities':e['lease']['capabilities']})
    lengths=[]
    for size in [0,1,15,16,17,31,32,128,1024]:
        plain=bytes((i%256 for i in range(size)))
        s,i1,i2,c,m=crypto.encrypt_payload_block(3,plain,salt=bytes(range(16)),iv1=bytes(range(16,32)),iv2=bytes(range(32,48)))
        assert crypto.decrypt_payload_block(3,s,i1,i2,c,m)==plain
        lengths.append({'plaintext_length':size,'ciphertext_length':len(c),'roundtrip':True})
    reconstructed=crypto.encrypt_payload_block(3,der,salt=salt,iv1=iv1,iv2=iv2)
    assert reconstructed==(salt,iv1,iv2,ct,mac)
    try:crypto.decrypt_payload_block(3,salt,iv1,iv2,ct,bytes([mac[0]^1])+mac[1:]);tamper=False
    except ValueError:tamper=True
    result={
        'scope':'Python host tests and reconstructed static predicate model only; no Foundation/iOS target execution',
        'audited_sources':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in [ROOT/'scripts/lease_generator.py',ROOT/'scripts/crypto_engine.py',ROOT/'mocks/auth_server.py',ROOT/'docs/03_SECURITY_SPEC_LAYER3_LEASE_VERIFY.md',ROOT/'docs/PROGRESS_TRACKER.md']},
        'sample':{'sha256':sha(sample_raw),'signed_python_json_sha256':sha(json_bytes(lease)),'signed_python_json_length':len(json_bytes(lease)),'field_classes':{k:type(v).__name__ for k,v in lease.items()},'envelope_classes':{k:type(v).__name__ for k,v in envelope.items()},'ttl':lease['expires_at']-lease['issued_at'],'capabilities':lease['capabilities'],'all_capability_elements_are_strings':all(type(x)is str for x in lease['capabilities']),'received_uptime':envelope['received_uptime'],'issued_at':lease['issued_at'],'expires_at':lease['expires_at'],'rsa_signature_bytes':len(base64.b64decode(envelope['signature'])),'test_key_bits':key.key_size,'python_signature_verifies_test_key':signature_valid(envelope,key.public_key()),'signature_verifies_embedded_camera_key_over_python_bytes':signature_valid(envelope,embedded.public_key()),'custom_certificate_matches_test_key':custom.public_key().public_numbers()==key.public_key().public_numbers(),'embedded_camera_cert_matches_original_export':der==original_export.public_bytes(serialization.Encoding.DER),'embedded_camera_cert_key_bits':embedded.public_key().key_size,'embedded_camera_cert_sha256':sha(der)},
        'camera_text_digests':records,'negative_validation_cases':cases,
        'generator_accepts_requested_ttl200':accepts_ttl200,
        'ttl200_rejection':ttl_200_exception,
        'ttl_boundary_cases':boundary_cases,
        'capability_override_cases':capability_cases,
        'camera_required_capability_names_from_configuration':['camera.fake-frame','camera.obs','media.import','camera.color-sync'],
        'missing_camera_capability_names':sorted(set(['camera.fake-frame','camera.obs','media.import','camera.color-sync'])-set(lease['capabilities'])),
        'crypto_inverse':{'existing_embedded_camera_tag3_reencrypted_byte_identical':True,'tampered_hmac_rejected':tamper,'padding_boundary_cases':lengths},
        'foundation_serialization_probe':{'target_execution_available':False,'sample_profile':'ASCII-only keys and values, integer numeric fields, no slash characters; simple compact JSON equivalence plausible but not target-verified','generic_unicode_python':json_bytes({'name':'café'}).decode(),'generic_slash_python':json_bytes({'path':'a/b'}).decode()},
    }
    result['sample']['embedded_overlay_certificate_matches_camera']=overlay_der==der
    result['crypto_inverse']['original_tag3_plaintext_bytes']=len(der)
    custom_der=custom.public_bytes(serialization.Encoding.DER)
    result['crypto_inverse']['custom_tag3_plaintext_bytes']=len(custom_der)
    result['crypto_inverse']['custom_tag3_ciphertext_bytes']=len(crypto.encrypt_payload_block(3,custom_der)[3])
    result['crypto_inverse']['original_tag3_ciphertext_bytes']=len(ct)
    (OUT/'verification_results.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
