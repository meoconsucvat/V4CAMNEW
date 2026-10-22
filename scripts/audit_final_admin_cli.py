"""Exercise actual admin functions only against a disposable, synthetic SQLite DB."""
from pathlib import Path
import ast
import contextlib
import hashlib
import io
import json
import sqlite3
import tempfile
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/final_sign_off'
NOW = 1_800_000_000


def main():
    source_path = ROOT / 'server/admin_cli.py'
    source_bytes = source_path.read_bytes()
    tree = ast.parse(source_bytes.decode('utf-8'))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
                node.name in {'get_connection', 'cmd_unbind', 'cmd_extend', 'cmd_revoke'}]
    server_tree = ast.parse((ROOT / 'server/server.py').read_text(encoding='utf-8'))
    initializer = next(n for n in server_tree.body if isinstance(n, ast.FunctionDef) and n.name == 'init_db')
    create_sql = [node.args[0].value for node in ast.walk(initializer)
                  if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
                  and isinstance(node.args[0].value, str) and node.args[0].value.strip().startswith('CREATE TABLE')]
    results = []
    with tempfile.TemporaryDirectory(prefix='vcnext-admin-audit-') as tmp:
        db = str(Path(tmp) / 'synthetic.sqlite')
        env = {'sqlite3': sqlite3, 'time': SimpleNamespace(time=lambda: NOW,
                strftime=time.strftime, localtime=time.localtime), 'DB_PATH': db}
        exec(compile(ast.Module(body=selected, type_ignores=[]), '<actual isolated admin functions>', 'exec'), env)

        @contextlib.contextmanager
        def connection():
            conn = sqlite3.connect(db)
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

        def reset():
            with connection() as conn:
                for table in ('licenses', 'sessions', 'challenges'):
                    conn.execute('DROP TABLE IF EXISTS ' + table)
                for sql in create_sql:
                    conn.execute(sql)

        def license(key, bound, expires=NOW+172800, status='active'):
            with connection() as conn:
                conn.execute('INSERT INTO licenses VALUES (?,?,?,?,?,?,?,?,?,?)',
                             (key, 'Synthetic Audit', '30d', 30, bound, 'Synthetic phone',
                              status, NOW-28*86400, expires, NOW-28*86400))

        def session(device, key):
            with connection() as conn:
                conn.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?)',
                             (device, key, key.lower(), 'audit-thumb', 'audit-access', 'audit-renewal',
                              'audit-nonce', NOW+172800, NOW))

        def call(name, *args):
            with contextlib.redirect_stdout(io.StringIO()):
                env[name](*args)

        def scalar(sql, args=()):
            with connection() as conn:
                row = conn.execute(sql, args).fetchone()
                return row[0] if row else None

        reset()
        license('VCN-AUDIT-A', 'audit-old-device')
        license('VCN-AUDIT-B', 'audit-other-device')
        session('audit-old-device', 'VCN-AUDIT-A')
        session('audit-orphan-device', 'VCN-AUDIT-A')
        session('audit-other-device', 'VCN-AUDIT-B')
        with connection() as conn:
            conn.execute('INSERT INTO challenges VALUES (?,?,?,?,?,?)',
                         ('audit-challenge', 'audit-old-device', 'vcn-audit-a', 'audit-thumb', 'audit-nonce', NOW+90))
        call('cmd_unbind', 'vcn-audit-a')
        observation = {
            'bound_device_cleared': scalar('SELECT bound_device_id FROM licenses WHERE license_key=?', ('VCN-AUDIT-A',)) is None,
            'normal_old_session_removed': scalar('SELECT COUNT(*) FROM sessions WHERE device_id=?', ('audit-old-device',)) == 0,
            'orphan_sessions_for_license_remaining': scalar('SELECT COUNT(*) FROM sessions WHERE license_key=?', ('VCN-AUDIT-A',)),
            'old_challenges_remaining': scalar('SELECT COUNT(*) FROM challenges WHERE username=?', ('vcn-audit-a',)),
            'activated_at_preserved': scalar('SELECT activated_at FROM licenses WHERE license_key=?', ('VCN-AUDIT-A',)) == NOW-28*86400,
            'expiry_preserved_by_cli': scalar('SELECT expires_at FROM licenses WHERE license_key=?', ('VCN-AUDIT-A',)) == NOW+172800,
            'unrelated_other_device_preserved': scalar('SELECT COUNT(*) FROM sessions WHERE device_id=?', ('audit-other-device',)) == 1,
        }
        assert all(observation[k] for k in ('bound_device_cleared', 'normal_old_session_removed',
                   'activated_at_preserved', 'expiry_preserved_by_cli', 'unrelated_other_device_preserved'))
        assert observation['orphan_sessions_for_license_remaining'] == observation['old_challenges_remaining'] == 1
        results.append({'name': 'unbind does not clean all license state', 'observed': observation})

        reset()
        license('VCN-AUDIT-A', 'audit-shared-device')
        license('VCN-AUDIT-B', 'audit-shared-device')
        session('audit-shared-device', 'VCN-AUDIT-B')
        call('cmd_unbind', 'VCN-AUDIT-A')
        removed_other = scalar('SELECT COUNT(*) FROM sessions WHERE license_key=?', ('VCN-AUDIT-B',)) == 0
        assert removed_other
        results.append({'name': 'unbind can delete another license session on same stored device',
                        'observed': {'unrelated_license_session_deleted': removed_other},
                        'precondition': 'device switched to a second license; sessions is keyed only by device_id'})

        reset()
        license('VCN-AUDIT-A', None, status='revoked')
        session('audit-orphan-device', 'VCN-AUDIT-A')
        call('cmd_unbind', 'VCN-AUDIT-A')
        orphan = scalar('SELECT COUNT(*) FROM sessions')
        revoked = scalar('SELECT status FROM licenses')
        assert orphan == 1 and revoked == 'revoked'
        results.append({'name': 'unbind of already unbound license leaves sessions',
                        'observed': {'orphan_sessions_remaining': orphan, 'revoked_status_preserved': True}})

        reset()
        with connection() as conn:
            conn.execute('INSERT INTO licenses VALUES (?,?,?,?,?,?,?,?,?,?)',
                         ('VCN-AUDIT-READY', 'Synthetic', '30d', 30, None, None, 'active', 0, 0, NOW))
        call('cmd_extend', 'VCN-AUDIT-READY', 7)
        exp = scalar('SELECT expires_at FROM licenses')
        days = scalar('SELECT duration_days FROM licenses')
        assert exp == NOW+7*86400 and days == 30
        results.append({'name': 'extend before first activation does not increase duration_days',
                        'observed': {'stored_expiry_seconds_from_now': exp-NOW, 'duration_days_still': days},
                        'consequence_from_server_source': 'first activation overwrites expires_at with now + duration_days*86400'})

        reset()
        license('VCN-AUDIT-A', 'audit-old-device')
        call('cmd_extend', 'VCN-AUDIT-A', -10)
        exp = scalar('SELECT expires_at FROM licenses')
        assert exp == NOW+172800-10*86400
        results.append({'name': 'negative extend is accepted',
                        'observed': {'license_now_expired': exp < NOW}})

        reset()
        license('VCN-AUDIT-A', 'audit-old-device')
        session('audit-old-device', 'VCN-AUDIT-A')
        session('audit-orphan-device', 'VCN-AUDIT-A')
        with connection() as conn:
            conn.execute('INSERT INTO challenges VALUES (?,?,?,?,?,?)',
                         ('audit-challenge', 'audit-old-device', 'vcn-audit-a', 'audit-thumb', 'audit-nonce', NOW+90))
        call('cmd_revoke', 'VCN-AUDIT-A')
        assert scalar('SELECT status FROM licenses') == 'revoked'
        assert scalar('SELECT COUNT(*) FROM sessions') == 0
        assert scalar('SELECT COUNT(*) FROM challenges') == 1
        results.append({'name': 'revoke by license clears sessions but leaves pending challenges',
                        'observed': {'status': 'revoked', 'sessions_remaining': 0, 'challenges_remaining': 1}})

    assert source_path.read_bytes() == source_bytes
    record = {'date': '2026-10-21', 'admin_source_sha256': hashlib.sha256(source_bytes).hexdigest(),
              'server_source_sha256': hashlib.sha256((ROOT/'server/server.py').read_bytes()).hexdigest(),
              'executed': 'AST-selected actual functions; no source logic edits; disposable SQLite; fixed synthetic clock',
              'production_db_or_private_key_opened': False, 'product_source_unchanged': True,
              'cases': results, 'cases_with_expected_observations': len(results)}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/'admin_tests.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
