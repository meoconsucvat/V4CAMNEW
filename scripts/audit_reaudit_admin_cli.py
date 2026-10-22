"""Re-audit real admin functions against disposable tables, never the product DB."""
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
OUT = ROOT / 'docs/evidence/re_audit'
NOW = 1_800_000_000


def main():
    admin_bytes = (ROOT/'server/admin_cli.py').read_bytes()
    server_bytes = (ROOT/'server/server.py').read_bytes()
    admin_tree, server_tree = ast.parse(admin_bytes), ast.parse(server_bytes)
    selected = [node for node in admin_tree.body if isinstance(node, ast.FunctionDef)
                and node.name in {'get_connection', 'cmd_unbind', 'cmd_extend', 'cmd_revoke'}]
    initializer = next(n for n in server_tree.body if isinstance(n, ast.FunctionDef) and n.name == 'init_db')
    sql_create = [n.args[0].value for n in ast.walk(initializer) if isinstance(n, ast.Call)
                  and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)
                  and n.args[0].value.strip().startswith('CREATE TABLE')]
    cases = []
    with tempfile.TemporaryDirectory(prefix='vcn-reaudit-admin-') as tmp:
        db = str(Path(tmp)/'synthetic.sqlite')
        env = {'sqlite3':sqlite3, 'time':SimpleNamespace(time=lambda:NOW,
                strftime=time.strftime, localtime=time.localtime), 'DB_PATH':db}
        exec(compile(ast.Module(body=selected, type_ignores=[]), '<actual admin functions>', 'exec'), env)

        @contextlib.contextmanager
        def connect():
            conn = sqlite3.connect(db)
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

        def execute(sql, args=()):
            with connect() as conn:
                return conn.execute(sql, args).fetchall()

        def scalar(sql, args=()):
            rows = execute(sql, args)
            return rows[0][0] if rows else None

        def reset():
            with connect() as conn:
                for name in ('licenses','sessions','challenges'):
                    conn.execute('DROP TABLE IF EXISTS '+name)
                for sql in sql_create:
                    conn.execute(sql)

        def license(key, device, activated=NOW-28*86400, expiry=NOW+2*86400, status='active'):
            execute('INSERT INTO licenses VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (key,'Audit','30d',30,device,'Audit phone',status,activated,expiry,NOW-28*86400))

        def session(device, key, username=None):
            execute('INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?)',
                    (device,key,username or (key or '').lower(),'fixture-thumb','fixture-at','fixture-rn',
                     'fixture-nonce',NOW+2*86400,NOW))

        def challenge(label, device, user):
            execute('INSERT INTO challenges VALUES (?,?,?,?,?,?)',
                    (label,device,user,'fixture-thumb','fixture-nonce',NOW+90))

        def call(name,*args):
            with contextlib.redirect_stdout(io.StringIO()):
                env[name](*args)

        reset()
        license('VCN-AUDIT-A','old-device')
        license('VCN-AUDIT-B','other-device')
        session('old-device','VCN-AUDIT-A')
        session('extra-device','VCN-AUDIT-A')
        session('other-device','VCN-AUDIT-B')
        challenge('ch-a','old-device','vCn-AuDiT-a')
        challenge('ch-b','other-device','vcn-audit-b')
        call('cmd_unbind','vcn-audit-a')
        observation = {
            'binding_cleared':scalar('SELECT bound_device_id FROM licenses WHERE license_key=?',('VCN-AUDIT-A',)) is None,
            'target_sessions_remaining':scalar('SELECT COUNT(*) FROM sessions WHERE license_key=?',('VCN-AUDIT-A',)),
            'target_challenges_remaining':scalar('SELECT COUNT(*) FROM challenges WHERE UPPER(username)=UPPER(?)',('VCN-AUDIT-A',)),
            'unrelated_sessions_remaining':scalar('SELECT COUNT(*) FROM sessions WHERE license_key=?',('VCN-AUDIT-B',)),
            'unrelated_challenges_remaining':scalar('SELECT COUNT(*) FROM challenges WHERE username=?',('vcn-audit-b',)),
            'expiry_preserved':scalar('SELECT expires_at FROM licenses WHERE license_key=?',('VCN-AUDIT-A',))==NOW+2*86400,
            'activated_at_preserved':scalar('SELECT activated_at FROM licenses WHERE license_key=?',('VCN-AUDIT-A',))==NOW-28*86400,
        }
        assert observation['binding_cleared'] and observation['expiry_preserved'] and observation['activated_at_preserved']
        assert observation['target_sessions_remaining']==observation['target_challenges_remaining']==0
        assert observation['unrelated_sessions_remaining']==observation['unrelated_challenges_remaining']==1
        cases.append({'name':'normal scoped unbind cleanup and term preservation','observed':observation})

        reset()
        license('VCN-AUDIT-A','shared-device')
        license('VCN-AUDIT-B','shared-device')
        session('shared-device','VCN-AUDIT-B')
        call('cmd_unbind','VCN-AUDIT-A')
        lost = scalar('SELECT COUNT(*) FROM sessions WHERE license_key=?',('VCN-AUDIT-B',))==0
        assert lost
        cases.append({'name':'shared device still deletes unrelated license session',
            'observed':{'unrelated_license_session_deleted':lost},
            'precondition':'device previously bound to license A later logged into B; session is keyed by device_id'})

        reset()
        license('VCN-AUDIT-A',None)
        session('legacy-null',None,'vcn-audit-a')
        session('legacy-case','vcn-audit-a')
        call('cmd_unbind','VCN-AUDIT-A')
        null_left=scalar('SELECT COUNT(*) FROM sessions WHERE license_key IS NULL')
        case_left=scalar('SELECT COUNT(*) FROM sessions WHERE license_key=?',('vcn-audit-a',))
        assert null_left==case_left==1
        cases.append({'name':'legacy NULL or differently cased license_key is not purged',
            'observed':{'null_key_session_remaining':null_left,'case_variant_session_remaining':case_left},
            'precondition':'unbound target license, legacy/manual session row; standard new login stores canonical key'})

        reset()
        license('VCN-AUDIT-READY',None,activated=0,expiry=0)
        call('cmd_extend','vcn-audit-ready',7)
        assert scalar('SELECT duration_days FROM licenses')==37
        assert scalar('SELECT expires_at FROM licenses')==0
        cases.append({'name':'unactivated extension adds plan duration',
                      'observed':{'duration_days':37,'expires_at':0}})
        snapshot=execute('SELECT * FROM licenses')
        call('cmd_extend','VCN-AUDIT-READY',-1)
        call('cmd_extend','VCN-AUDIT-READY',0)
        assert execute('SELECT * FROM licenses')==snapshot
        cases.append({'name':'negative and zero extension rejected without changes','observed':{'unchanged':True}})

        reset()
        license('VCN-AUDIT-A','old-device',status='revoked')
        session('old-device','VCN-AUDIT-A')
        call('cmd_extend','VCN-AUDIT-A',7)
        assert scalar('SELECT status FROM licenses')=='active'
        assert scalar('SELECT expires_at FROM licenses')==NOW+9*86400
        assert scalar('SELECT expires_at FROM sessions')==NOW+9*86400
        cases.append({'name':'activated extension reactivates a revoked license',
            'observed':{'status':'active','remaining_days':9,'session_expiry_updated':True},
            'assessment':'administrator policy behavior; document intentional reactivation or require explicit separate approval'})

        reset()
        license('VCN-AUDIT-A','old-device',status='revoked')
        call('cmd_unbind','VCN-AUDIT-A')
        assert scalar('SELECT status FROM licenses')=='revoked'
        assert scalar('SELECT expires_at FROM licenses')==NOW+2*86400
        cases.append({'name':'unbind preserves revoked status and original expiry',
                      'observed':{'status':'revoked','expiry_unchanged':True}})

        reset()
        execute('DROP TABLE sessions')
        execute('''CREATE TABLE sessions (device_id TEXT PRIMARY KEY, username TEXT,
                    thumbprint TEXT, access_token TEXT, renewal_token TEXT,
                    current_nonce TEXT, expires_at INTEGER, created_at INTEGER)''')
        execute('INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)',
                ('legacy-device','admin','fixture-thumb','fixture-at','fixture-rn',
                 'fixture-nonce',NOW+315360000,NOW))
        migration_env={'sqlite3':sqlite3,'time':SimpleNamespace(time=lambda:NOW),'DB_PATH':db}
        exec(compile(ast.Module(body=[initializer],type_ignores=[]),
                     '<actual init_db migration>', 'exec'),migration_env)
        migration_env['init_db']()
        columns=[r[1] for r in execute('PRAGMA table_info(sessions)')]
        migrated_key=scalar('SELECT license_key FROM sessions WHERE device_id=?',('legacy-device',))
        admin_exists=scalar('SELECT COUNT(*) FROM licenses WHERE license_key=?',('admin',))
        matched=scalar('SELECT COUNT(*) FROM licenses WHERE UPPER(license_key)=UPPER(?)',(migrated_key,))
        assert 'license_key' in columns and migrated_key is None and admin_exists==1 and matched==0
        cases.append({'name':'legacy sessions migration adds column without license backfill',
            'observed':{'license_key_column_present':True,'legacy_admin_license_key':None,
                        'seed_admin_license_exists':True,'renewal_license_lookup_matches':matched},
            'consequence_from_server_source':'heartbeat/renew selects legacy NULL key and finds no license; returns403 LICENSE_EXPIRED and deletes session, even with otherwise valid token'})

    assert (ROOT/'server/admin_cli.py').read_bytes()==admin_bytes
    assert (ROOT/'server/server.py').read_bytes()==server_bytes
    record={'date':'2026-10-21','admin_source_sha256':hashlib.sha256(admin_bytes).hexdigest(),
        'server_source_sha256':hashlib.sha256(server_bytes).hexdigest(),
        'isolation':'AST-selected actual functions, synthetic temporary DB, fixed fixture clock',
        'production_db_or_keys_opened':False,'product_sources_unchanged':True,
        'temporary_database_closed_and_removed':True,'case_count':len(cases),'cases':cases}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'admin_tests.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    main()
