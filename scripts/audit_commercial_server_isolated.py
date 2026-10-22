"""Adversarial HTTP/SQLite tests with throwaway keys and a temporary database.

The production source is copied unchanged to a TemporaryDirectory. It is then
executed with __file__ bound to that copy and __name__ != '__main__'. No original
key or customer database is opened. HTTP binds only 127.0.0.1 on a random port.
Scheduling seams below pause reads; they do not replace authorization logic.
"""
from pathlib import Path
import base64
import concurrent.futures
import hashlib
import http.client
import json
import sqlite3
import tempfile
import threading
import time
import types
from http.server import ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/final_sign_off'
SOURCE = ROOT / 'server/server.py'


class DBProxy:
    """Keep real SQLite semantics; optionally schedule a completed row read."""
    def __init__(self):
        self.after_challenge_read = None
        self.after_session_read = None

    def connect(self, *args, **kwargs):
        return ConnectionProxy(sqlite3.connect(*args, **kwargs), self)


class ConnectionProxy:
    def __init__(self, connection, scheduler):
        self.connection = connection
        self.scheduler = scheduler

    def cursor(self):
        return CursorProxy(self.connection.cursor(), self.scheduler)

    def __getattr__(self, name):
        return getattr(self.connection, name)


class CursorProxy:
    def __init__(self, cursor, scheduler):
        self.cursor = cursor
        self.scheduler = scheduler
        self.query = ''

    def execute(self, sql, *args):
        self.query = ' '.join(sql.split())
        self.cursor.execute(sql, *args)
        return self

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is not None:
            if 'FROM challenges' in self.query and self.query.startswith('SELECT'):
                callback = self.scheduler.after_challenge_read
                if callback is not None:
                    callback()
            if 'FROM sessions' in self.query and self.query.startswith('SELECT'):
                callback = self.scheduler.after_session_read
                if callback is not None:
                    callback()
        return row

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class Fixture:
    def __init__(self, temporary, source):
        self.directory = Path(temporary)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        (self.directory / 'server_private_key.pem').write_bytes(self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        target = self.directory / 'server.py'
        target.write_bytes(source)
        self.namespace = {'__name__': 'vcn_isolated_audit_fixture', '__file__': str(target),
                          'print': lambda *args, **kwargs: None}
        exec(compile(source, str(target), 'exec'), self.namespace)
        self.database = self.directory / 'licenses.db'
        assert Path(self.namespace['BASE_DIR']).resolve() == self.directory.resolve()
        assert Path(self.namespace['DB_PATH']).resolve() == self.database.resolve()
        assert Path(self.namespace['KEY_PATH']).resolve() == (self.directory / 'server_private_key.pem').resolve()
        self.now = 2_000_000_000
        self.namespace['time'] = types.SimpleNamespace(time=lambda: self.now)
        self.proxy = DBProxy()
        self.namespace['sqlite3'] = self.proxy
        handler = self.namespace['VCNextRequestHandler']
        handler.log_message = lambda *args, **kwargs: None
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        self.httpd.daemon_threads = True
        self.errors = []
        self.httpd.handle_error = lambda request, addr: self.errors.append('unhandled_handler_exception')
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        device_key = ec.generate_private_key(ec.SECP256R1())
        self.device_public = device_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.thumbprint = hashlib.sha256(self.device_public).hexdigest()

    def close(self):
        self.proxy.after_challenge_read = None
        self.proxy.after_session_read = None
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive(), 'audit HTTP serving thread remains alive'
        assert self.httpd.socket.fileno() == -1, 'audit HTTP socket remains open'

    def sql(self, query, args=()):
        connection = sqlite3.connect(self.database, timeout=10.0)
        try:
            cur = connection.execute(query, args)
            rows = cur.fetchall()
            connection.commit()
            return rows
        finally:
            connection.close()

    def license(self, label, days=30):
        key = 'AUDIT-' + label.upper()
        self.sql('''INSERT INTO licenses (license_key, customer_name, plan_type,
                    duration_days, bound_device_id, device_name, status,
                    activated_at, expires_at, created_at)
                    VALUES (?, 'isolated fixture', 'test', ?, NULL, NULL, 'active', 0, 0, ?)''',
                 (key, days, self.now))
        return key

    def request(self, route, body, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        raw = json.dumps(body).encode('utf-8')
        try:
            connection.request('POST', '/api/v2/auth/' + route, raw,
                               {'Content-Type': 'application/json', **(headers or {})})
            response = connection.getresponse()
            content = response.read()
            return response.status, json.loads(content)
        except (http.client.HTTPException, ConnectionError) as error:
            return 0, {'error': type(error).__name__}
        finally:
            connection.close()

    def body(self, device, **extra):
        return {'client_build': '37', 'binary_digest': self.namespace['APP_TEXT_DIGEST'],
                'device_id': device, **extra}

    def challenge(self, key, device, **extra):
        return self.request('challenge', self.body(device, username=key,
            device_public_key=base64.b64encode(self.device_public).decode('ascii'), **extra))

    def login(self, key, device, challenge):
        return self.request('login', self.body(device, username=key,
            device_name='Audit fixture phone', challenge_id=challenge['challenge']['challenge_id']))

    def enroll(self, key, device):
        challenge = self.challenge(key, device)
        assert challenge[0] == 200, challenge[0]
        login = self.login(key, device, challenge[1])
        assert login[0] == 200, login[0]
        return login

    def signature(self, payload, signature):
        try:
            signature = base64.b64decode(signature, validate=True)
            canonical = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
            self.private_key.public_key().verify(signature, canonical, padding.PKCS1v15(), hashes.SHA256())
            return {'valid': True, 'signature_bytes': len(signature), 'canonical_bytes': len(canonical)}
        except Exception as error:
            return {'valid': False, 'error': type(error).__name__}

    def lease(self, response):
        status, body = response
        if status != 200 or 'lease' not in body:
            return {'status': status, 'error': body.get('error')}
        lease = body['lease']
        bindings = all(lease[name] == hashlib.sha256(body[token].encode('utf-8')).hexdigest()
                       for name, token in [('session_binding', 'access_token'),
                                           ('renewal_binding', 'renewal_token'),
                                           ('next_nonce_hash', 'next_nonce')])
        schema = (type(lease['version']) is int and lease['version'] == 2
                  and lease['purpose'] == 'capability.lease'
                  and lease['issuer'] == 'vcnext-main' and lease['audience'] == 'vcnext-ios'
                  and lease['build'] == '37'
                  and isinstance(lease['device_id'], str)
                  and isinstance(lease['device_key_thumbprint'], str)
                  and isinstance(lease['capabilities'], list)
                  and all(isinstance(x, str) for x in lease['capabilities'])
                  and set(lease['capabilities']) == set(self.namespace['REQUIRED_CAPABILITIES'])
                  and lease['expires_at'] - lease['issued_at'] == 90
                  and isinstance(body['user'], dict)
                  and isinstance(body['user']['username'], str)
                  and type(body['user']['active_devices']) is int
                  and type(body['user']['max_devices']) is int)
        return {'status': status, 'schema_valid': schema, 'token_bindings_valid': bindings,
                'ttl_seconds': lease['expires_at'] - lease['issued_at'],
                'capabilities_count': len(lease['capabilities']),
                'signature': self.signature(lease, body['lease_signature'])}


def main():
    source = SOURCE.read_bytes()
    results = {'source_sha256': hashlib.sha256(source).hexdigest(),
               'isolation': {'product_source_changed': False, 'production_module_imported': False,
                             'source_copy_byte_identical': True,
                             'production_keys_or_database_opened': False,
                             'rsa_fixture_bits': 3072, 'http_bind': '127.0.0.1:ephemeral',
                             'foundation_executed': False,
                             'scheduling_seams': ['after challenge row fetch', 'after session row fetch']},
               'cleanup_limitations': {
                   'initial_failed_fixture_may_remain': True,
                   'initial_fixture_basename': 'vcn-commercial-audit-wcjhovbw',
                   'contents': 'generated throwaway RSA key, copied source and temporary test SQLite only',
                   'removal_automatic_review': 'rejected: blocked by policy',
                   'alternate_deletion_attempted': False,
                   'subsequent_successful_fixtures': 'normal TemporaryDirectory cleanup'},
               'tests': {}}
    tests = results['tests']
    with tempfile.TemporaryDirectory(prefix='vcn-commercial-audit-') as temporary:
        fixture = Fixture(temporary, source)
        try:
            key = fixture.license('BASELINE')
            challenge = fixture.challenge(key, 'AUDIT-DEVICE-A')
            tests['challenge_rsa_signature'] = fixture.signature(
                challenge[1]['challenge'], challenge[1]['signature'])
            baseline = fixture.login(key, 'AUDIT-DEVICE-A', challenge[1])
            tests['login_without_password_nonce_or_device_signature'] = fixture.lease(baseline)
            assert tests['login_without_password_nonce_or_device_signature']['signature']['valid']
            tests['sequential_challenge_replay'] = fixture.lease(fixture.login(key, 'AUDIT-DEVICE-A', challenge[1]))
            tests['other_device_after_bind'] = fixture.lease(fixture.challenge(key, 'AUDIT-DEVICE-B'))
            tests['heartbeat_without_authorization_nonce_or_proof'] = fixture.lease(
                fixture.request('heartbeat', fixture.body('AUDIT-DEVICE-A')))
            tests['renew_with_wrong_token_and_replayed_proof'] = fixture.lease(fixture.request('renew',
                fixture.body('AUDIT-DEVICE-A', nonce='REPLAYED', device_signature='not-a-signature',
                             issued_at=1, request_id='REUSED'),
                {'Authorization': 'Bearer not-the-issued-token'}))
            tests['header_device_id_overrides_body'] = fixture.lease(fixture.request('heartbeat',
                fixture.body('AUDIT-DEVICE-B'), {'X-Device-ID': 'AUDIT-DEVICE-A'}))

            # The source special-cases canonical 'admin' without enforcing the
            # seeded row's device binding, status or fixed expiration.
            admin_challenge = fixture.challenge('admin', 'AUDIT-ROGUE-ADMIN-DEVICE')
            tests['admin_rogue_device_challenge_status'] = admin_challenge[0]
            if admin_challenge[0] == 200:
                admin_login = fixture.login('admin', 'AUDIT-ROGUE-ADMIN-DEVICE', admin_challenge[1])
            else:
                admin_login = admin_challenge
            tests['admin_rogue_device_login'] = fixture.lease(admin_login)
            fixture.sql("UPDATE licenses SET status='revoked', expires_at=1 WHERE license_key='admin'")
            tests['revoked_admin_heartbeat'] = fixture.lease(
                fixture.request('heartbeat', fixture.body('AUDIT-ROGUE-ADMIN-DEVICE')))

            # Force the real, possible interleaving where both requests finish
            # challenge SELECT before either starts its first DML transaction.
            key = fixture.license('DISTINCT-DEVICE-RACE')
            challenges = [fixture.challenge(key, device)[1] for device in ('AUDIT-RACE-A', 'AUDIT-RACE-B')]
            barrier = threading.Barrier(2)
            fixture.proxy.after_challenge_read = lambda: barrier.wait(timeout=10)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(fixture.login, key, device, challenge)
                           for device, challenge in zip(('AUDIT-RACE-A', 'AUDIT-RACE-B'), challenges)]
                responses = [future.result(timeout=15) for future in futures]
            fixture.proxy.after_challenge_read = None
            tests['distinct_device_activation_forced_select_overlap'] = {
                'statuses': sorted(response[0] for response in responses),
                'errors': sorted(response[1].get('error', '') for response in responses),
                'sessions': fixture.sql('SELECT COUNT(*) FROM sessions WHERE license_key=?', (key,))[0][0],
                'one_bound_device': bool(fixture.sql('SELECT bound_device_id FROM licenses WHERE license_key=?', (key,))[0][0]),
                'schedule': 'both challenge SELECT rows cached before either DELETE'}

            key = fixture.license('SAME-CHALLENGE-RACE')
            challenge = fixture.challenge(key, 'AUDIT-REPLAY-DEVICE')[1]
            barrier = threading.Barrier(2)
            fixture.proxy.after_challenge_read = lambda: barrier.wait(timeout=10)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(fixture.login, key, 'AUDIT-REPLAY-DEVICE', challenge) for _ in range(2)]
                responses = [future.result(timeout=15) for future in futures]
            fixture.proxy.after_challenge_read = None
            tests['same_challenge_concurrent_replay'] = {
                'statuses': sorted(response[0] for response in responses),
                'valid_rsa_leases': sum(fixture.lease(response).get('signature', {}).get('valid', False)
                                        for response in responses),
                'different_access_tokens': responses[0][1].get('access_token') != responses[1][1].get('access_token'),
                'remaining_challenges': fixture.sql('SELECT COUNT(*) FROM challenges WHERE challenge_id=?',
                    (challenge['challenge']['challenge_id'],))[0][0],
                'schedule': 'both requests cached the same challenge row before DELETE; second DELETE affects zero rows'}

            # Renewal can pass a normal server-time boundary by a whole lease.
            key = fixture.license('NEAR-EXPIRY')
            fixture.enroll(key, 'AUDIT-EXPIRY-DEVICE')
            fixture.sql('UPDATE licenses SET expires_at=? WHERE license_key=?', (fixture.now + 1, key))
            near = fixture.request('heartbeat', fixture.body('AUDIT-EXPIRY-DEVICE', issued_at=1))
            tests['last_second_lease_overruns_license'] = {
                'status': near[0], 'seconds_beyond_license_expiry': near[1]['lease']['expires_at'] - (fixture.now + 1),
                'lease': fixture.lease(near)}
            fixture.now += 2
            tests['client_timestamp_rollback_does_not_bypass_server_license_expiry'] = fixture.lease(
                fixture.request('heartbeat', fixture.body('AUDIT-EXPIRY-DEVICE', issued_at=1)))
            fixture.now -= 2

            # DB lifetime expiration uses < rather than <= at the exact second.
            key = fixture.license('EXACT-EXPIRY')
            fixture.enroll(key, 'AUDIT-EXACT-DEVICE')
            fixture.sql('UPDATE licenses SET expires_at=? WHERE license_key=?', (fixture.now, key))
            tests['heartbeat_at_exact_license_expiry'] = fixture.lease(
                fixture.request('heartbeat', fixture.body('AUDIT-EXACT-DEVICE')))

            key = fixture.license('UNBIND-IN-FLIGHT')
            fixture.enroll(key, 'AUDIT-UNBIND-DEVICE')
            selected = threading.Event()
            release = threading.Event()
            def pause_after_session():
                selected.set()
                if not release.wait(timeout=10):
                    raise TimeoutError('scheduling seam was not released')
            fixture.proxy.after_session_read = pause_after_session
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(fixture.request, 'heartbeat', fixture.body('AUDIT-UNBIND-DEVICE'))
                assert selected.wait(timeout=10)
                fixture.sql('UPDATE licenses SET bound_device_id=NULL, device_name=NULL WHERE license_key=?', (key,))
                fixture.sql('DELETE FROM sessions WHERE device_id=?', ('AUDIT-UNBIND-DEVICE',))
                release.set()
                response = future.result(timeout=15)
            fixture.proxy.after_session_read = None
            tests['heartbeat_after_unbind_select_update_race'] = {
                'response': fixture.lease(response),
                'sessions_after_response': fixture.sql('SELECT COUNT(*) FROM sessions WHERE license_key=?', (key,))[0][0],
                'schedule': 'pause after session SELECT; emulate current unbind clearing binding and deleting session; resume UPDATE'}

            key = fixture.license('MIGRATION-EXPIRY')
            fixture.enroll(key, 'AUDIT-MIGRATION-OLD')
            old_expiry = fixture.now + 2 * 86400
            fixture.sql('UPDATE licenses SET expires_at=? WHERE license_key=?', (old_expiry, key))
            fixture.sql('UPDATE licenses SET bound_device_id=NULL, device_name=NULL WHERE license_key=?', (key,))
            fixture.sql('DELETE FROM sessions WHERE device_id=?', ('AUDIT-MIGRATION-OLD',))
            migrated = fixture.enroll(key, 'AUDIT-MIGRATION-NEW')
            tests['unbind_reactivation_resets_full_plan_duration'] = {
                'status': migrated[0], 'remaining_before_seconds': 2 * 86400,
                'remaining_after_seconds': migrated[1]['user']['expires_at'] - fixture.now,
                'extension_seconds': migrated[1]['user']['expires_at'] - old_expiry}

            key = fixture.license('CHALLENGE-TTL')
            challenge = fixture.challenge(key, 'AUDIT-CHALLENGE-TTL')[1]
            fixture.now += 100
            tests['login_after_signed_challenge_expiry_but_before_db_expiry'] = fixture.lease(
                fixture.login(key, 'AUDIT-CHALLENGE-TTL', challenge))
            fixture.now -= 100
            tests['logout_without_authentication'] = fixture.lease(fixture.request('logout',
                fixture.body('AUDIT-DEVICE-A')))
            tests['non_object_json'] = fixture.request('heartbeat', [])[0]
            tests['numeric_client_build_rejected'] = fixture.request('heartbeat',
                dict(fixture.body('AUDIT-DEVICE-A'), client_build=37))[0]
            tests['unknown_app_digest_rejected'] = fixture.request('heartbeat',
                dict(fixture.body('AUDIT-DEVICE-A'), binary_digest='0' * 64))[0]
            tests['unhandled_handler_exceptions'] = len(fixture.errors)
        finally:
            fixture.close()
            results['isolation']['http_listener_closed'] = True
    assert SOURCE.read_bytes() == source, 'product source changed during audit'
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'server_tests.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
