"""Audit the actual account store against disposable SQLite databases only."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import types

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/telegram_audit'
SOURCE = ROOT / 'server/store.py'
NOW = 2_100_000_000


class ConnectionProxy:
    def __init__(self, raw, barrier):
        self.raw = raw
        self.barrier = barrier

    @property
    def row_factory(self):
        return self.raw.row_factory

    @row_factory.setter
    def row_factory(self, value):
        self.raw.row_factory = value

    def execute(self, query, parameters=()):
        cur = self.raw.execute(query, parameters)
        if 'SELECT * FROM admin_confirmations' in query:
            return CursorProxy(cur, self.barrier)
        return cur

    def __getattr__(self, name):
        return getattr(self.raw, name)


class CursorProxy:
    def __init__(self, raw, barrier):
        self.raw = raw
        self.barrier = barrier

    def fetchone(self):
        row = self.raw.fetchone()
        if row is not None:
            self.barrier.wait(timeout=5)
        return row


def main():
    raw_source = SOURCE.read_bytes()
    results = {'source_sha256': hashlib.sha256(raw_source).hexdigest(),
               'isolation': {'production_store_imported': False,
                             'source_copy_byte_identical': True,
                             'production_database_or_keys_opened': False,
                             'network_or_telegram_calls': False}, 'tests': {}}
    tests = results['tests']
    with tempfile.TemporaryDirectory(prefix='vcn-store-audit-') as temporary:
        directory = Path(temporary)
        copy_path = directory / 'store.py'
        copy_path.write_bytes(raw_source)
        env = {'__name__': 'isolated_store_fixture', '__file__': str(copy_path)}
        exec(compile(raw_source, str(copy_path), 'exec'), env)
        db = Path(env['DB_PATH'])
        assert db.resolve().parent == directory.resolve()
        env['now'] = lambda: NOW

        def scalar(query, parameters=()):
            with env['connect']() as con:
                row = con.execute(query, parameters).fetchone()
                return row[0] if row else None

        # The fixture contains the normal schema and seed, never a copied DB.
        admin = env['get_user']('admin')
        tests['fresh_seed_admin'] = {
            'default_password_is_single_character_one': env['verify_password']('1', admin['password_salt'], admin['password_hash']),
            'max_devices': admin['max_devices'],
            'grant_seconds': admin['expires_at'] - admin['created_at'],
            'seed_device_count': len(env['list_devices']('admin')),
            'seed_device_public_key_empty': not env['list_devices']('admin')[0]['device_public_key']}

        salt, hashed = env['password_hash']('audit-only-password')
        salt2, _ = env['password_hash']('audit-only-password')
        independent = hashlib.pbkdf2_hmac('sha256', b'audit-only-password', bytes.fromhex(salt), 200_000).hex()
        tests['password_kdf'] = {
            'rounds': env['PBKDF2_ROUNDS'], 'salt_bytes': len(bytes.fromhex(salt)),
            'salt_distinct_between_calls': salt != salt2, 'digest_bytes': len(bytes.fromhex(hashed)),
            'independent_pbkdf2_match': hashed == independent,
            'correct_password_valid': env['verify_password']('audit-only-password', salt, hashed),
            'wrong_password_rejected': not env['verify_password']('wrong-audit-password', salt, hashed)}
        assert all(v for k, v in tests['password_kdf'].items() if isinstance(v, bool))

        with env['connect']() as con:
            tests['sqlite_defaults'] = {
                'journal_mode': con.execute('PRAGMA journal_mode').fetchone()[0],
                'busy_timeout_ms': con.execute('PRAGMA busy_timeout').fetchone()[0],
                'foreign_keys': con.execute('PRAGMA foreign_keys').fetchone()[0],
                'check_users_constraints': [r['name'] for r in con.execute('PRAGMA table_info(users)')]}

        env['create_user']('Audit-Empty', '', 30, 1)
        empty = env['get_user']('audit-empty')
        tests['empty_password_accepted_by_store'] = env['verify_password']('', empty['password_salt'], empty['password_hash'])
        tests['username_normalization'] = {
            'ascii_casefold_and_trim': env['normalize_username']('  TESTUSER ') == 'testuser',
            'nonascii_sharp_s_folds_to_ss': env['normalize_username']('Straße') == 'strasse',
            'assessment': 'casefold is not the same operation as Foundation lowercaseString for every Unicode input'}

        def add_state(username, device):
            with env['connect']() as con:
                con.execute('INSERT INTO devices VALUES (?,?,1,?,?,?,?,?,?)',
                            (device, username, NOW, NOW, 'Audit phone', '37', 'audit-key', 'audit-thumb'))
                con.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,1)',
                            (device, username, 'audit-thumb', 'access-'+device, 'renew-'+device,
                             'nonce-'+device, NOW+10000, NOW))
                con.execute('INSERT INTO challenges VALUES (?,?,?,?,?,?)',
                            ('challenge-'+device, device, username, 'audit-thumb', 'nonce-'+device, NOW+90))

        env['create_user']('audit-clear', 'audit-password', 30, 2)
        env['create_user']('audit-other', 'audit-password', 30, 2)
        add_state('audit-clear', 'audit-clear-device')
        add_state('audit-other', 'audit-other-device')
        before = env['get_user']('audit-clear')
        deleted = env['reset_devices']('AUDIT-CLEAR', actor='audit-owner')
        after = env['get_user']('audit-clear')
        tests['clear_preserves_account'] = {
            'deleted_device_count': deleted,
            'expiry_preserved': before['expires_at'] == after['expires_at'],
            'password_hash_and_salt_preserved': (before['password_hash'], before['password_salt']) == (after['password_hash'], after['password_salt']),
            'devices_remaining': scalar('SELECT count(*) FROM devices WHERE username=?', ('audit-clear',)),
            'sessions_remaining': scalar('SELECT count(*) FROM sessions WHERE username=?', ('audit-clear',)),
            'challenges_remaining': scalar('SELECT count(*) FROM challenges WHERE username=?', ('audit-clear',)),
            'other_user_state_preserved': scalar('SELECT count(*) FROM sessions WHERE username=?', ('audit-other',)) == 1}
        assert tests['clear_preserves_account']['expiry_preserved']
        assert tests['clear_preserves_account']['password_hash_and_salt_preserved']
        assert tests['clear_preserves_account']['sessions_remaining'] == tests['clear_preserves_account']['devices_remaining'] == tests['clear_preserves_account']['challenges_remaining'] == 0

        removed = env['remove_device']('audit-clear', 'audit-other-device', actor='audit-owner')
        tests['remove_device_scope'] = {
            'reported_removed': removed,
            'other_user_device_still_present': scalar('SELECT count(*) FROM devices WHERE device_id=?', ('audit-other-device',)) == 1,
            'other_user_session_deleted': scalar('SELECT count(*) FROM sessions WHERE device_id=?', ('audit-other-device',)) == 0}
        assert removed is False and tests['remove_device_scope']['other_user_session_deleted']

        code = env['create_confirmation']('audit-owner', 'delete_user', {'username': 'audit-clear'})
        action, payload = env['consume_confirmation']('audit-intruder', code)
        tests['confirmation_actor_binding'] = {'foreign_actor_consumed': action == 'delete_user',
                                               'payload_target_preserved': payload == {'username': 'audit-clear'}}
        code = env['create_confirmation']('audit-owner', 'reset_devices', {'username': 'audit-clear'})
        tests['confirmation_cancel_actor_binding'] = {'foreign_actor_cancelled': env['cancel_confirmation']('audit-intruder', code)}

        code = env['create_confirmation']('audit-owner', 'delete_user', {'username': 'audit-clear'})
        barrier = threading.Barrier(2)
        original_sqlite = env['sqlite3']
        env['sqlite3'] = types.SimpleNamespace(Row=sqlite3.Row,
            connect=lambda *a, **kw: ConnectionProxy(sqlite3.connect(*a, **kw), barrier))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(env['consume_confirmation'], 'audit-owner', code) for _ in range(2)]
            replay_results = []
            for future in futures:
                try:
                    action, _ = future.result(timeout=20)
                    replay_results.append(action)
                except Exception as error:
                    replay_results.append(type(error).__name__)
        env['sqlite3'] = original_sqlite
        tests['concurrent_confirmation_consume'] = {'results': replay_results,
            'successful_consumptions': replay_results.count('delete_user'),
            'scheduling_seam': 'both completed SELECT rows before either UPDATE'}
        assert replay_results.count('delete_user') == 2

        code = env['create_confirmation']('audit-owner', 'delete_user', {'username': 'audit-clear'}, ttl=90)
        env['now'] = lambda: NOW+91
        try:
            env['consume_confirmation']('audit-owner', code)
            expiry_rejected = False
        except ValueError:
            expiry_rejected = True
        env['now'] = lambda: NOW
        tests['confirmation_timeout'] = {'after_91_seconds_rejected': expiry_rejected}
        assert expiry_rejected

        env['create_user']('audit-expired', 'audit-password', 1, 1)
        add_state('audit-expired', 'audit-expired-device')
        with env['connect']() as con:
            con.execute('UPDATE users SET expires_at=? WHERE username=?', (NOW-1, 'audit-expired'))
        deleted = env['delete_expired_users']('audit-owner')
        tests['delete_expired_cleanup'] = {
            'target_deleted': 'audit-expired' in deleted,
            'devices_remaining': scalar('SELECT count(*) FROM devices WHERE username=?', ('audit-expired',)),
            'sessions_remaining': scalar('SELECT count(*) FROM sessions WHERE username=?', ('audit-expired',)),
            'orphan_challenges_remaining': scalar('SELECT count(*) FROM challenges WHERE username=?', ('audit-expired',))}
        assert tests['delete_expired_cleanup']['orphan_challenges_remaining'] == 1

        # Establish WAL in the synthetic file, keep a live connection open, and
        # show the actual 15-second store busy limit still bounds write waiting.
        holder = sqlite3.connect(db)
        try:
            holder.execute('PRAGMA journal_mode=WAL')
            holder.execute('BEGIN IMMEDIATE')
            holder.execute('UPDATE users SET updated_at=updated_at WHERE username=?', ('audit-clear',))
            started = time.monotonic()
            try:
                env['set_bot_state']('audit-lock', 'audit-value')
                busy_error = None
            except sqlite3.OperationalError as error:
                busy_error = str(error)
            elapsed = time.monotonic()-started
            tests['wal_writer_contention'] = {
                'journal_mode': 'wal', 'store_busy_timeout_ms': 15000,
                'result': busy_error, 'elapsed_seconds': round(elapsed, 3),
                'schedule': 'one held IMMEDIATE writer; store operation uses unchanged default timeout15s'}
            assert busy_error == 'database is locked'
            holder.rollback()

            # Online backup reads committed WAL safely while the live holder
            # prevents last-connection checkpoint cleanup from hiding the WAL.
            holder.execute('INSERT INTO bot_state VALUES (?,?,?)', ('audit-wal-backup', 'committed-fixture', NOW))
            holder.commit()
            snapshot = directory / 'consistent-snapshot.sqlite'
            source_con = sqlite3.connect(db)
            dest_con = sqlite3.connect(snapshot)
            try:
                source_con.backup(dest_con, pages=32, sleep=0.01)
                tests['online_backup_snapshot'] = {
                    'integrity_check': dest_con.execute('PRAGMA integrity_check').fetchone()[0],
                    'latest_committed_wal_row_present': dest_con.execute('SELECT count(*) FROM bot_state WHERE key=?', ('audit-wal-backup',)).fetchone()[0] == 1}
            finally:
                dest_con.close()
                source_con.close()
        finally:
            holder.close()
        assert tests['online_backup_snapshot']['integrity_check'] == 'ok'

        # Restore ordinary SQLite module, but point the copied module at a
        # separate synthetic pre-pivot schema to observe missing migration.
        legacy = directory / 'legacy.sqlite'
        legacy_con = sqlite3.connect(legacy)
        try:
            legacy_con.execute('CREATE TABLE sessions (device_id TEXT PRIMARY KEY,username TEXT,thumbprint TEXT,access_token TEXT,renewal_token TEXT,current_nonce TEXT,expires_at INTEGER,created_at INTEGER)')
            legacy_con.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)',
                               ('audit-legacy-device', 'admin', 'audit-thumb', 'audit-access', 'audit-renew', 'audit-nonce', NOW+1000, NOW))
            legacy_con.commit()
        finally:
            legacy_con.close()
        current_path = env['DB_PATH']
        env['DB_PATH'] = str(legacy)
        env['init_db']()
        with env['connect']() as con:
            columns = [r['name'] for r in con.execute('PRAGMA table_info(sessions)')]
            try:
                con.execute('SELECT session_version FROM sessions').fetchone()
                missing_column_error = None
            except sqlite3.OperationalError as error:
                missing_column_error = str(error)
        tests['pre_pivot_schema_migration'] = {
            'session_version_added': 'session_version' in columns,
            'handler_select_error': missing_column_error,
            'init_db_returned_without_migrating_existing_sessions': missing_column_error is not None}
        env['DB_PATH'] = current_path

    assert SOURCE.read_bytes() == raw_source
    results['isolation']['product_source_unchanged'] = True
    results['isolation']['temporary_databases_closed_and_removed'] = True
    results['case_count'] = len(tests)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/'store_tests.json').write_text(json.dumps(results, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
