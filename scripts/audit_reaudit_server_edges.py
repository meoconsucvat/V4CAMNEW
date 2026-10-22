"""Supplemental remediated-server tests, using only isolated throwaway fixtures.

The actual server source is copied byte-for-byte by the existing Fixture. No
production key/database is opened and no licensing request leaves loopback.
"""
from pathlib import Path
import concurrent.futures
import hashlib
import importlib.util
import json
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/re_audit'
SOURCE = ROOT / 'server/server.py'


def main():
    spec = importlib.util.spec_from_file_location(
        'vcn_existing_isolated_fixture', ROOT / 'scripts/audit_commercial_server_isolated.py')
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    source = SOURCE.read_bytes()
    results = {
        'server_source_sha256': hashlib.sha256(source).hexdigest(),
        'isolation': {'production_source_modified': False,
                      'production_key_or_database_opened': False,
                      'production_network_requests': False,
                      'source_copy_byte_identical': True,
                      'fixture_authority_bits': 3072,
                      'foundation_executed': False},
        'tests': {},
    }
    tests = results['tests']
    with tempfile.TemporaryDirectory(prefix='vcn-reaudit-edges-') as temporary:
        fixture = harness.Fixture(temporary, source)

        def lease(response):
            status, body = response
            if status != 200 or 'lease' not in body:
                return {'status': status, 'error': body.get('error')}
            payload = body['lease']
            signature = fixture.signature(payload, body['lease_signature'])
            ttl = payload['expires_at'] - payload['issued_at']
            bindings = all(payload[name] == hashlib.sha256(body[token].encode()).hexdigest()
                           for name, token in [('session_binding', 'access_token'),
                                               ('renewal_binding', 'renewal_token'),
                                               ('next_nonce_hash', 'next_nonce')])
            return {'status': status, 'rsa_valid': signature['valid'],
                    'signature_bytes': signature['signature_bytes'],
                    'ttl_seconds': ttl, 'ttl_within_active_reader_limit': 0 < ttl <= 95,
                    'five_capabilities': set(payload['capabilities']) == set(fixture.namespace['REQUIRED_CAPABILITIES']),
                    'token_bindings_valid': bindings}

        counter = 0

        def enrolled(label):
            nonlocal counter
            counter += 1
            key = fixture.license(label + '-' + str(counter))
            device = 'EDGE-DEVICE-' + str(counter)
            response = fixture.enroll(key, device)
            assert response[0] == 200
            return key, device, response[1]

        try:
            # A wrong nonempty nonce is rejected, but every falsey representation
            # bypasses the check. Each request uses a fresh challenge/license.
            nonce_results = []
            for label, value in [('omitted', ...), ('empty', ''), ('null', None),
                                 ('false', False), ('zero', 0), ('wrong_nonempty', 'WRONG-NONCE')]:
                key = fixture.license('NONCE-' + label)
                device = 'EDGE-NONCE-' + label
                challenge = fixture.challenge(key, device)
                assert challenge[0] == 200
                body = fixture.body(device, username=key,
                                    challenge_id=challenge[1]['challenge']['challenge_id'])
                if value is not ...:
                    body['challenge_nonce'] = value
                response = fixture.request('login', body)
                expected = 403 if label == 'wrong_nonempty' else 200
                assert response[0] == expected, (label, response[0])
                if expected == 403:
                    assert response[1]['error'] == 'NONCE_MISMATCH'
                nonce_results.append({'input': label, 'response': lease(response)})
            tests['optional_login_nonce'] = nonce_results

            key = fixture.license('CORRECT-NONCE')
            device = 'EDGE-CORRECT-NONCE'
            challenge = fixture.challenge(key, device)
            response = fixture.request('login', fixture.body(device, username=key,
                challenge_id=challenge[1]['challenge']['challenge_id'],
                challenge_nonce=challenge[1]['challenge']['nonce']))
            assert response[0] == 200
            tests['correct_login_nonce_without_device_proof'] = lease(response)

            # Inspect absent/empty/wrong-scheme Authorization separately from a
            # nonempty wrong Bearer value. Rotations use independent fixtures.
            auth_results = []
            for route in ('heartbeat', 'renew', 'logout'):
                for label, authorization in [('omitted', None), ('empty', ''),
                                              ('empty_bearer', 'Bearer '),
                                              ('wrong_scheme', 'Basic placeholder'),
                                              ('wrong_nonempty_bearer', 'Bearer not-valid')]:
                    _, device, _ = enrolled('AUTH-' + route + '-' + label)
                    headers = {} if authorization is None else {'Authorization': authorization}
                    response = fixture.request(route, fixture.body(device), headers)
                    expected = 401 if label == 'wrong_nonempty_bearer' else 200
                    assert response[0] == expected, (route, label, response[0])
                    if expected == 401:
                        assert response[1]['error'] == 'INVALID_TOKEN'
                    auth_results.append({'route': route, 'authorization': label,
                                         'status': response[0], 'error': response[1].get('error'),
                                         'response': lease(response) if route != 'logout' else None})
            tests['optional_authorization'] = auth_results

            # Even correct nonce/token credentials do not cause the claimed
            # device proof or proof freshness to be checked.
            key = fixture.license('INVALID-LOGIN-PROOF')
            device = 'EDGE-INVALID-PROOF'
            challenge = fixture.challenge(key, device)
            response = fixture.request('login', fixture.body(device, username=key,
                challenge_id=challenge[1]['challenge']['challenge_id'],
                challenge_nonce=challenge[1]['challenge']['nonce'],
                device_signature='not-a-valid-ecdsa-signature'))
            assert response[0] == 200
            tests['invalid_login_device_signature'] = lease(response)
            current = response[1]
            for route, token_field in [('heartbeat', 'access_token'), ('renew', 'renewal_token')]:
                response = fixture.request(route, fixture.body(device, request_id='REPLAY',
                    nonce='not-the-session-nonce', issued_at=1,
                    device_signature='not-a-valid-ecdsa-signature'),
                    {'Authorization': 'Bearer ' + current[token_field]})
                assert response[0] == 200
                tests['invalid_' + route + '_device_signature_and_nonce'] = lease(response)
                current = response[1]

            # Query only the seeded disposable row to derive its asserted ID.
            # It is not a production database/device lookup.
            admin_device = fixture.sql("SELECT bound_device_id FROM licenses WHERE license_key='admin'")[0][0]
            admin_challenge = fixture.challenge('admin', admin_device)
            assert admin_challenge[0] == 200
            admin_response = fixture.login('admin', admin_device, admin_challenge[1])
            assert admin_response[0] == 200
            tests['admin_seed_device_id_claim_without_author_device_key'] = {
                'claimed_id_matches_fixture_seed': True,
                'public_key_from_independent_throwaway_device': True,
                'device_signature_supplied': False,
                'response': lease(admin_response),
                'issued_lease_bound_to_throwaway_key_thumbprint': admin_response[1]['lease']['device_key_thumbprint'] == fixture.thumbprint,
            }
            wrong_admin = fixture.challenge('admin', 'EDGE-DIFFERENT-ADMIN-ID')
            assert wrong_admin[0] == 403 and wrong_admin[1]['error'] == 'DEVICE_MISMATCH'
            direct_wrong_admin = fixture.request('login', fixture.body('EDGE-DIFFERENT-ADMIN-ID',
                username='admin', challenge_id=admin_challenge[1]['challenge']['challenge_id'],
                challenge_nonce=admin_challenge[1]['challenge']['nonce']))
            assert direct_wrong_admin[0] == 403 and direct_wrong_admin[1]['error'] == 'CHALLENGE_INVALID'
            fixture.sql('INSERT INTO challenges VALUES (?,?,?,?,?,?)',
                ('synthetic-pre-fix-admin-challenge', 'EDGE-DIFFERENT-ADMIN-ID', 'admin',
                 fixture.thumbprint, 'synthetic-pre-fix-nonce', fixture.now+90))
            legacy_wrong_admin = fixture.request('login', fixture.body('EDGE-DIFFERENT-ADMIN-ID',
                username='admin', challenge_id='synthetic-pre-fix-admin-challenge',
                challenge_nonce='synthetic-pre-fix-nonce'))
            assert legacy_wrong_admin[0] == 403 and legacy_wrong_admin[1]['error'] == 'DEVICE_MISMATCH'
            tests['admin_different_asserted_device_id'] = {
                'challenge': lease(wrong_admin), 'direct_login_using_bound_device_challenge': lease(direct_wrong_admin),
                'login_with_synthetic_legacy_pending_challenge': lease(legacy_wrong_admin),
                'legacy_precondition': 'synthetic pending database row models a challenge issued before admin binding enforcement',
                'login_error_order': 'challenge device parity/consumption occurs before license binding check',
            }

            clip_key, clip_device, clip_session = enrolled('CLIP-ONE-SECOND')
            fixture.sql('UPDATE licenses SET expires_at=? WHERE license_key=?', (fixture.now+1, clip_key))
            clipped = fixture.request('heartbeat', fixture.body(clip_device),
                {'Authorization': 'Bearer ' + clip_session['access_token']})
            clipped_record = lease(clipped)
            assert clipped_record['status'] == 200 and clipped_record['ttl_seconds'] == 1
            assert clipped_record['rsa_valid'] and clipped_record['ttl_within_active_reader_limit']
            tests['clipped_one_second_lease_independent_validation'] = {
                'response': clipped_record,
                'no_license_overrun': clipped[1]['lease']['expires_at'] == fixture.now+1,
                'note': '0<TTL<=95 validates the reconstructed reader; exactly90 is not a schema requirement',
            }

            # Both workers authenticate against the same cached token before
            # either can rotate it. WHERE device_id does not compare tokens.
            _, device, current = enrolled('TOKEN-RACE')
            barrier = threading.Barrier(2)
            fixture.proxy.after_session_read = lambda: barrier.wait(timeout=8)
            body = fixture.body(device, request_id='same-request', nonce=current['next_nonce'],
                                issued_at=fixture.now, device_signature='invalid')
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(fixture.request, 'heartbeat', body,
                                      {'Authorization': 'Bearer ' + current['access_token']}) for _ in range(2)]
                responses = [f.result(timeout=15) for f in futures]
            fixture.proxy.after_session_read = None
            assert [r[0] for r in responses] == [200, 200]
            stored = fixture.sql('SELECT access_token,renewal_token FROM sessions WHERE device_id=?', (device,))[0]
            assert responses[0][1]['access_token'] != responses[1][1]['access_token']
            loser = next(r[1] for r in responses if r[1]['access_token'] != stored[0])
            stale_heartbeat = fixture.request('heartbeat', fixture.body(device),
                                            {'Authorization': 'Bearer ' + loser['access_token']})
            stale_renew = fixture.request('renew', fixture.body(device),
                                        {'Authorization': 'Bearer ' + loser['renewal_token']})
            assert stale_heartbeat[0] == stale_renew[0] == 401
            tests['concurrent_valid_same_token_requests'] = {
                'statuses': [r[0] for r in responses],
                'different_access_tokens': True,
                'valid_signed_leases': sum(lease(r)['rsa_valid'] for r in responses),
                'losing_response_next_heartbeat_status': stale_heartbeat[0],
                'losing_response_renew_fallback_status': stale_renew[0],
                'schedule': 'pause both after cached session SELECT, before token comparison/update',
            }

            # Row existence is not session identity. A deleted row can be
            # recreated under the same primary key while issuance is paused.
            old_key, device, current = enrolled('ABA-OLD')
            new_key = fixture.license('ABA-NEW')
            new_expiry = fixture.now + 3600
            fixture.sql('UPDATE licenses SET activated_at=?,expires_at=?,bound_device_id=? WHERE license_key=?',
                        (fixture.now, new_expiry, device, new_key))
            fetched, resume = threading.Event(), threading.Event()

            def pause():
                fetched.set()
                assert resume.wait(timeout=8)

            fixture.proxy.after_session_read = pause
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(fixture.request, 'heartbeat', fixture.body(device),
                                      {'Authorization': 'Bearer ' + current['access_token']})
                assert fetched.wait(timeout=8)
                fixture.sql('DELETE FROM sessions WHERE device_id=?', (device,))
                fixture.sql('''INSERT INTO sessions (device_id,license_key,username,thumbprint,
                    access_token,renewal_token,current_nonce,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)''',
                    (device, new_key, new_key.lower(), 'different-key-thumbprint',
                     'replacement-session-access', 'replacement-session-renew',
                     'replacement-session-nonce', new_expiry, fixture.now))
                resume.set()
                response = pending.result(timeout=15)
            fixture.proxy.after_session_read = None
            assert response[0] == 200
            stored = fixture.sql('SELECT license_key,username,thumbprint,access_token,expires_at FROM sessions WHERE device_id=?', (device,))[0]
            assert stored[0] == new_key and stored[3] == response[1]['access_token']
            assert stored[4] != new_expiry
            tests['session_delete_recreate_aba'] = {
                'response': lease(response),
                'row_uses_new_license': stored[0] == new_key,
                'response_user_uses_old_license': response[1]['user']['username'] == old_key.lower(),
                'new_session_tokens_overwritten_by_old_inflight_request': stored[3] == response[1]['access_token'],
                'new_session_expiry_overwritten_by_old_license_expiry': stored[4] != new_expiry,
                'row_thumbprint_still_new': stored[2] == 'different-key-thumbprint',
                'response_thumbprint_still_old': response[1]['lease']['device_key_thumbprint'] == fixture.thumbprint,
                'schedule': 'pause after old session SELECT; delete row and recreate another license at same device_id; resume',
            }
            assert not fixture.errors, fixture.errors
            tests['unhandled_handler_exceptions'] = len(fixture.errors)
        finally:
            fixture.close()
        results['isolation']['loopback_listener_closed'] = True
    assert SOURCE.read_bytes() == source
    results['isolation']['temporary_fixture_cleaned'] = True
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'server_edge_tests.json').write_text(json.dumps(results, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
