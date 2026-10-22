"""Bounded loopback-only HTTP/TLS probes; never contacts a production service."""
from pathlib import Path
import contextlib, hashlib, http.client, importlib.util, io, json, ssl, threading
from http.server import HTTPServer

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/evidence/cross_audit'
def main():
    path=ROOT/'mocks/auth_server.py'
    spec=importlib.util.spec_from_file_location('audited_mock',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    class QuietHandler(mod.VCNextAuthHandler):
        def log_message(self,*args):pass
    records=[]
    for tls in [False,True]:
        server=HTTPServer(('127.0.0.1',0),QuietHandler)
        if tls:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(ROOT/'mocks/custom_server_cert.pem'),str(ROOT/'mocks/test_server_private_key.pem'))
            server.socket=context.wrap_socket(server.socket,server_side=True)
        worker=threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        try:
            results=[]
            for route in ['challenge','login','heartbeat','renew']:
                client_context=ssl.create_default_context(cafile=str(ROOT/'mocks/custom_server_cert.pem')) if tls else None
                if tls:client_context.check_hostname=False
                conn=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=client_context,timeout=5) if tls else http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                with contextlib.redirect_stdout(io.StringIO()):
                    conn.request('POST','/api/v2/auth/'+route,body='{}',headers={'Content-Type':'application/json'})
                    response=conn.getresponse()
                    body=json.loads(response.read())
                conn.close()
                item={'route':route,'http_status':response.status,'response_keys':sorted(body),'empty_body_accepted_as_active':body.get('status')=='active'}
                if route!='challenge':
                    lease=body['lease']
                    item.update({'capabilities':lease['capabilities'],'ttl':lease['expires_at']-lease['issued_at'],'session_binding_matches_returned_access_token_sha256':lease['session_binding']==hashlib.sha256(body['access_token'].encode()).hexdigest(),'renewal_binding_matches_returned_renewal_token_sha256':lease['renewal_binding']==hashlib.sha256(body['renewal_token'].encode()).hexdigest(),'next_nonce_hash_matches_returned_next_nonce_sha256':lease['next_nonce_hash']==hashlib.sha256(body['next_nonce'].encode()).hexdigest()})
                results.append(item)
            records.append({'transport':'TLS' if tls else 'HTTP','bind_address':'127.0.0.1','ephemeral_port':server.server_port,'tls_custom_cert_chain_trusted':tls,'tls_hostname_checked':False,'native_pinning_tested':False,'routes':results})
        finally:
            server.shutdown();server.server_close();worker.join(timeout=5)
            assert not worker.is_alive()
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'mock_transport_results.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(records,indent=2))
if __name__=='__main__':main()
