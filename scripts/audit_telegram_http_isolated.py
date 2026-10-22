"""Audit HTTP/store behavior using copied source, disposable keys/DB and loopback only."""
from pathlib import Path
import base64
import concurrent.futures
import hashlib
import http.client
import json
import sys
import tempfile
import threading
import types
from http.server import ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/telegram_audit'
NOW = 2_000_000_000
PASSWORD = 'Synthetic-HTTP-Audit-Password!'


class Fixture:
    def __init__(self, directory, server_source, store_source):
        self.directory = Path(directory)
        (self.directory/'server.py').write_bytes(server_source)
        (self.directory/'store.py').write_bytes(store_source)
        self.authority = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        (self.directory/'server_private_key.pem').write_bytes(self.authority.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.old_store = sys.modules.get('store')
        self.store = types.ModuleType('store')
        self.store.__file__ = str(self.directory/'store.py')
        sys.modules['store'] = self.store
        exec(compile(store_source, self.store.__file__, 'exec'), self.store.__dict__)
        assert Path(self.store.DB_PATH).resolve() == (self.directory/'licenses.db').resolve()
        self.namespace = {'__name__': 'isolated_vcnext_http', '__package__': '',
                          '__file__': str(self.directory/'server.py'), 'print': lambda *a, **kw: None}
        exec(compile(server_source, self.namespace['__file__'], 'exec'), self.namespace)
        assert self.namespace['store'] is self.store
        assert Path(self.namespace['KEY_PATH']).resolve() == (self.directory/'server_private_key.pem').resolve()
        self.store.time = types.SimpleNamespace(time=lambda: NOW)
        self.namespace['time'] = types.SimpleNamespace(time=lambda: NOW)
        handler = self.namespace['VCNextRequestHandler']
        handler.log_message = lambda *a, **kw: None
        self.errors = []
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        self.httpd.daemon_threads = True
        self.httpd.handle_error = lambda *a: self.errors.append('unhandled_handler_exception')
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.keys = {}
        self.release_events = []

    def close(self):
        for event in self.release_events:
            event.set()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive() and self.httpd.socket.fileno() == -1
        if self.old_store is None:
            sys.modules.pop('store', None)
        else:
            sys.modules['store'] = self.old_store

    def sql(self, query, args=()):
        with self.store.connect() as con:
            cursor = con.execute(query, args)
            return [dict(row) for row in cursor.fetchall()]

    def key(self, device):
        if device not in self.keys:
            self.keys[device] = ec.generate_private_key(ec.SECP256R1())
        return self.keys[device]

    def request(self, route, body, authorization=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=20)
        headers = {'Content-Type': 'application/json'}
        if authorization is not None:
            headers['Authorization'] = authorization
        try:
            connection.request('POST', '/api/v2/auth/' + route, json.dumps(body).encode(), headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        except (http.client.HTTPException, ConnectionError) as error:
            return 0, {'error': type(error).__name__}
        finally:
            connection.close()

    def body(self, device, **extra):
        return {'device_id': device, 'client_build': '37',
                'binary_digest': self.namespace['APP_TEXT_DIGEST'], **extra}

    def challenge(self, username, device):
        raw = self.key(device).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return self.request('challenge', self.body(device, username=username,
            device_public_key=base64.b64encode(raw).decode()))

    def login(self, username, device, challenge, password=PASSWORD, nonce=True, proof=True):
        payload = challenge['challenge']
        body = self.body(device, username=username, password=password,
                         device_name='Synthetic audit phone', challenge_id=payload['challenge_id'])
        if nonce:
            body['challenge_nonce'] = payload['nonce']
        if proof:
            serialized = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
            body['device_signature'] = base64.b64encode(self.key(device).sign(
                serialized, ec.ECDSA(hashes.SHA256()))).decode()
        return self.request('login', body)

    def create(self, username, limit=1):
        return self.store.create_user(username, PASSWORD, days=30, max_devices=limit, actor='isolated-audit')

    def enroll(self, username, device):
        response = self.challenge(username, device)
        assert response[0] == 200
        response = self.login(username, device, response[1])
        assert response[0] == 200
        return response

    def summary(self, response):
        status, body = response
        if status != 200 or 'lease' not in body:
            return {'status': status, 'error': body.get('error')}
        lease = body['lease']
        signature = base64.b64decode(body['lease_signature'], validate=True)
        self.authority.public_key().verify(signature,
            json.dumps(lease, sort_keys=True, separators=(',', ':')).encode(),
            padding.PKCS1v15(), hashes.SHA256())
        bindings = all(lease[field] == hashlib.sha256(body[token].encode()).hexdigest()
                       for field, token in [('session_binding', 'access_token'),
                                            ('renewal_binding', 'renewal_token'),
                                            ('next_nonce_hash', 'next_nonce')])
        return {'status': status, 'rsa_valid': True, 'signature_bytes': len(signature),
                'ttl': lease['expires_at']-lease['issued_at'], 'five_capabilities':
                set(lease['capabilities']) == set(self.namespace['REQUIRED_CAPABILITIES']),
                'token_bindings_valid': bindings,
                'user_types_valid': isinstance(body['user'], dict) and
                isinstance(body['user']['username'], str) and
                type(body['user']['active_devices']) is int and
                type(body['user']['max_devices']) is int,
                'active_devices': body['user']['active_devices'],
                'max_devices': body['user']['max_devices']}


def main():
    server_source = (ROOT/'server/server.py').read_bytes()
    store_source = (ROOT/'server/store.py').read_bytes()
    record = {'server_sha256': hashlib.sha256(server_source).hexdigest(),
              'store_sha256': hashlib.sha256(store_source).hexdigest(),
              'isolation': {'copied_source_byte_identical': True, 'production_keys_db_read': False,
                            'external_network_requests': False, 'http': 'loopback ephemeral port',
                            'rsa_bits': 3072, 'device_proofs': 'independent synthetic P-256 keys',
                            'foundation_executed': False}, 'tests': {}}
    tests = record['tests']
    with tempfile.TemporaryDirectory(prefix='vcnext-userpass-http-') as directory:
        fixture = Fixture(directory, server_source, store_source)
        try:
            fixture.create('normal')
            baseline = fixture.enroll('normal', 'audit-normal-device')
            tests['normal_username_password_login'] = fixture.summary(baseline)
            assert tests['normal_username_password_login']['rsa_valid']
            tests['sequential_device_quota'] = fixture.summary(fixture.challenge('normal', 'audit-normal-second'))
            assert tests['sequential_device_quota']['error'] == 'DEVICE_LIMIT_REACHED'

            fixture.create('normal-two', limit=2)
            two_a = fixture.enroll('normal-two', 'audit-two-a')
            two_b = fixture.enroll('normal-two', 'audit-two-b')
            third = fixture.challenge('normal-two', 'audit-two-c')
            tests['normal_two_device_contract'] = {
                'first': fixture.summary(two_a), 'second': fixture.summary(two_b),
                'third_challenge': fixture.summary(third),
                'persisted_devices': len(fixture.store.list_devices('normal-two'))}
            assert two_b[1]['user']['active_devices'] == 2
            assert third[1]['error'] == 'DEVICE_LIMIT_REACHED'
            fixture.sql('UPDATE users SET expires_at=? WHERE username=?', (NOW+7, 'normal-two'))
            clipped = fixture.request('heartbeat', fixture.body('audit-two-a'), 'Bearer ' + two_a[1]['access_token'])
            tests['account_expiry_clips_lease'] = {'reply': fixture.summary(clipped),
                'overrun_seconds': clipped[1]['lease']['expires_at']-(NOW+7)}
            assert clipped[1]['lease']['expires_at'] == NOW+7

            tests['challenge_enumeration'] = {}
            for username, state in [('missing-audit-user', 'unknown'), ('disabled-audit', 'disabled'),
                                    ('expired-audit', 'expired')]:
                if state != 'unknown':
                    fixture.create(username)
                    fixture.sql('UPDATE users SET ' + ('enabled=0' if state == 'disabled' else 'expires_at=1') +
                                ' WHERE username=?', (username,))
                tests['challenge_enumeration'][state] = fixture.summary(fixture.challenge(username, 'audit-enum-device'))
            assert len({value['error'] for value in tests['challenge_enumeration'].values()}) == 3

            fixture.create('password-failure')
            challenge = fixture.challenge('password-failure', 'audit-password-device')[1]
            incorrect = fixture.login('password-failure', 'audit-password-device', challenge, password='incorrect-fixture')
            retry = fixture.login('password-failure', 'audit-password-device', challenge)
            tests['wrong_password_then_same_challenge_retry'] = {
                'wrong_password': fixture.summary(incorrect), 'correct_password_retry': fixture.summary(retry)}
            assert incorrect[1]['error'] == 'INVALID_PASSWORD' and retry[1]['error'] == 'CHALLENGE_INVALID'

            fixture.store.set_user_password('admin', 'Changed-Strong-Synthetic-Password!', actor='isolated-audit')
            fixture.sql('UPDATE users SET expires_at=? WHERE username=?', (NOW+315360000, 'admin'))
            admin = []
            for number, password in enumerate(('', '1')):
                device = 'audit-admin-independent-' + str(number)
                challenge = fixture.challenge('admin', device)
                response = fixture.login('admin', device, challenge[1], password=password, nonce=False, proof=False)
                admin.append({'password_case': 'empty' if not password else 'legacy-default',
                              'challenge_status': challenge[0], 'reply': fixture.summary(response)})
                assert response[0] == 200
            tests['admin_bypass_after_password_reset'] = admin

            missing = fixture.request('heartbeat', fixture.body('audit-normal-device'))
            tests['heartbeat_missing_auth_nonce_proof'] = fixture.summary(missing)
            assert missing[0] == 200
            bad = fixture.request('renew', fixture.body('audit-normal-device'), 'Bearer incorrect-fixture')
            tests['renew_wrong_nonempty_token'] = fixture.summary(bad)
            assert bad[0] == 401
            existing = fixture.sql('SELECT access_token FROM sessions WHERE device_id=?', ('audit-normal-device',))[0]
            forged = fixture.request('heartbeat', fixture.body('audit-normal-device', nonce='wrong',
                issued_at=1, request_id='replay', device_signature='invalid'), 'Bearer ' + existing['access_token'])
            tests['heartbeat_bad_proof_nonce_with_valid_token'] = fixture.summary(forged)
            assert forged[0] == 200
            tests['logout_without_auth'] = fixture.summary(fixture.request('logout', fixture.body('audit-normal-device')))

            fixture.create('quota-race')
            devices = ['audit-quota-a', 'audit-quota-b']
            challenges = [fixture.challenge('quota-race', device)[1] for device in devices]
            original_list = fixture.store.list_devices
            barrier = threading.Barrier(2)
            def quota_snapshot(username):
                snapshot = original_list(username)
                if username == 'quota-race':
                    assert not snapshot
                    barrier.wait(timeout=15)
                return snapshot
            fixture.store.list_devices = quota_snapshot
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [executor.submit(fixture.login, 'quota-race', device, challenge)
                               for device, challenge in zip(devices, challenges)]
                    responses = [f.result(timeout=20) for f in futures]
            finally:
                fixture.store.list_devices = original_list
            count = len(original_list('quota-race'))
            tests['concurrent_device_quota_max_one'] = {'responses': [fixture.summary(r) for r in responses],
                'persisted_devices': count, 'configured_max_devices': 1,
                'schedule': 'both actual list_devices snapshots cached before either insertion',
                'distinct_valid_p256_device_keys': fixture.key(devices[0]).public_key().public_numbers() !=
                                                  fixture.key(devices[1]).public_key().public_numbers()}
            assert [r[0] for r in responses] == [200, 200] and count == 2

            for user, action in [('clear-race', 'reset_devices'), ('password-race', 'set_user_password')]:
                fixture.create(user)
                device = 'audit-' + user
                challenge = fixture.challenge(user, device)[1]
                selected, release = threading.Event(), threading.Event()
                fixture.release_events.append(release)
                original_list = fixture.store.list_devices
                used = [False]
                def pause_after_quota(username):
                    snapshot = original_list(username)
                    if username == user and not used[0]:
                        used[0] = True
                        selected.set()
                        if not release.wait(timeout=15):
                            raise TimeoutError('admin operation scheduling timeout')
                    return snapshot
                fixture.store.list_devices = pause_after_quota
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(fixture.login, user, device, challenge)
                        assert selected.wait(timeout=15)
                        if action == 'reset_devices':
                            fixture.store.reset_devices(user, actor='isolated-audit')
                        else:
                            fixture.store.set_user_password(user, 'Updated-Synthetic-Password!', actor='isolated-audit')
                        release.set()
                        response = future.result(timeout=20)
                finally:
                    release.set()
                    fixture.store.list_devices = original_list
                tests[action + '_inflight_login'] = {'reply': fixture.summary(response),
                    'sessions_after_action_and_reply': fixture.sql('SELECT COUNT(*) AS n FROM sessions WHERE username=?',
                        (user,))[0]['n'], 'schedule': 'pause login after password verification/quota read, perform admin action, resume issuance'}
                assert response[0] == 200

            fixture.create('cas-user')
            baseline = fixture.enroll('cas-user', 'audit-cas-device')
            original_get = fixture.store.get_user
            barrier = threading.Barrier(2)
            def pause_both_sessions(username):
                result = original_get(username)
                if username == 'cas-user':
                    barrier.wait(timeout=15)
                return result
            fixture.store.get_user = pause_both_sessions
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [executor.submit(fixture.request, 'heartbeat', fixture.body('audit-cas-device'),
                        'Bearer ' + baseline[1]['access_token']) for _ in range(2)]
                    responses = [f.result(timeout=20) for f in futures]
            finally:
                fixture.store.get_user = original_get
            tests['session_version_same_generation_race'] = {'replies': [fixture.summary(r) for r in responses],
                'schedule': 'both checked old token/session_version before conditional update'}
            assert sorted(r[0] for r in responses) == [200, 401]

            fixture.create('aba-old')
            fixture.create('aba-new')
            baseline = fixture.enroll('aba-old', 'audit-aba-device')
            selected, release = threading.Event(), threading.Event()
            fixture.release_events.append(release)
            original_get = fixture.store.get_user
            used = [False]
            def pause_old_session(username):
                result = original_get(username)
                if username == 'aba-old' and not used[0]:
                    used[0] = True
                    selected.set()
                    if not release.wait(timeout=15):
                        raise TimeoutError('ABA scheduling timeout')
                return result
            fixture.store.get_user = pause_old_session
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(fixture.request, 'heartbeat', fixture.body('audit-aba-device'),
                        'Bearer ' + baseline[1]['access_token'])
                    assert selected.wait(timeout=15)
                    fixture.store.reset_devices('aba-old', actor='isolated-audit')
                    replacement = fixture.enroll('aba-new', 'audit-aba-device')
                    release.set()
                    response = future.result(timeout=20)
            finally:
                release.set()
                fixture.store.get_user = original_get
            row = fixture.sql('SELECT username,access_token,session_version FROM sessions WHERE device_id=?',
                ('audit-aba-device',))[0]
            tests['session_delete_recreate_version_reuse'] = {'old_reply': fixture.summary(response),
                'stored_username_is_new_user': row['username'] == 'aba-new',
                'reply_username_is_old_user': response[1].get('user', {}).get('username') == 'aba-old',
                'new_session_tokens_overwritten': row['access_token'] != replacement[1]['access_token'],
                'stored_version': row['session_version'],
                'schedule': 'pause version1 heartbeat; clear old account; actual new-account login sameID creates version1; resume'}
            assert response[0] == 200 and row['username'] == 'aba-new'
            assert row['access_token'] != replacement[1]['access_token']
            tests['unhandled_handler_exceptions'] = len(fixture.errors)
            assert not fixture.errors
        finally:
            fixture.close()
            record['isolation']['loopback_listener_closed'] = True
    record['isolation']['temporary_fixture_cleaned'] = True
    assert (ROOT/'server/server.py').read_bytes() == server_source
    assert (ROOT/'server/store.py').read_bytes() == store_source
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/'http_tests.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
