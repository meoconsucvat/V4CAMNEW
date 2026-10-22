"""Execute selected bot dispatch functions with fake store/network only.

No Telegram API or production database/key is accessed. The source's token
assignment is not executed; every network call is a recording stub.
"""
from pathlib import Path
import ast
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import time
import types
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/telegram_audit'
OWNER = 5137016124


class FakeStore:
    def __init__(self):
        self.logs = []
        self.state = {}
        self.actions = []
        self.users = {'audituser': {'username': 'audituser', 'max_devices': 1,
                    'active_devices': 0, 'enabled': 1, 'expires_at': 2_000_086_400}}
        self.DB_PATH = ''

    def now(self):
        return 2_000_000_000

    def normalize_username(self, value):
        return value.strip().casefold()

    def audit(self, *args):
        self.logs.append(args)

    def get_bot_state(self, key, default=''):
        return self.state.get(key, default)

    def set_bot_state(self, key, value):
        self.state[key] = value

    def delete_bot_state(self, key):
        self.state.pop(key, None)

    def get_user(self, username):
        return self.users.get(username)

    def extend_user_seconds(self, username, seconds, actor):
        self.actions.append(('extend', username, seconds, actor))
        self.users[username]['expires_at'] += seconds
        return self.users[username]

    def consume_confirmation(self, actor, code):
        self.actions.append(('consume_confirmation', actor, code))
        return 'user_delete', {'username': 'audituser'}

    def delete_user(self, username, actor):
        self.actions.append(('delete_user', username, actor))


def fixture():
    source = (ROOT/'server/telegram_bot.py').read_bytes()
    tree = ast.parse(source.decode('utf-8'))
    allowed_names = {'ROLE_RANK', 'STOP', 'LOCK_HANDLE', 'USERNAME_RE', 'DURATION_RE',
                     'MAIN_KEYBOARD', 'DURATION_KEYBOARD', 'DEVICE_KEYBOARD',
                     'PASSWORD_KEYBOARD', 'CANCEL_KEYBOARD', 'HELP'}
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))
             or (isinstance(n, ast.ImportFrom) and n.module == '__future__')
             or (isinstance(n, ast.Assign) and all(isinstance(t, ast.Name) and
                 (t.id.startswith('BTN_') or t.id in allowed_names) for t in n.targets))]
    store = FakeStore()
    requests = []

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self): return b'{"ok":false,"description":"synthetic rejection"}'

    def urlopen(request, timeout):
        requests.append({'url': request.full_url, 'data': request.data,
                         'headers': dict(request.header_items()), 'timeout': timeout})
        return Response()

    module = types.ModuleType('vcn_bot_isolated_audit')
    sys.modules[module.__name__] = module
    env = module.__dict__
    env.update({'json': json, 'os': os, 're': re, 'secrets': secrets, 'sys': sys,
                'time': time, 'Path': Path, 'Any': Any, 'dataclass': dataclass,
                'datetime': datetime, 'timezone': timezone, 'store': store,
                'BOT_TOKEN': 'TEST_ONLY_NO_REAL_TOKEN', 'API_TIMEOUT': 25,
                'PRIVATE_ONLY': True, 'CONFIRM_TTL': 90, 'WIZARD_TTL': 600,
                'OWNER_IDS': {OWNER}, 'OPERATOR_IDS': set(), 'VIEWER_IDS': set(),
                'urllib': types.SimpleNamespace(parse=urllib.parse, error=urllib.error,
                    request=types.SimpleNamespace(Request=urllib.request.Request, urlopen=urlopen))})
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<isolated actual bot functions>', 'exec'), env)
    calls = []
    env['send_message'] = lambda *a, **kw: calls.append(('send_message', a, kw))
    env['answer_callback'] = lambda *a, **kw: calls.append(('answer_callback', a, kw))
    env['delete_message'] = lambda *a, **kw: calls.append(('delete_message', a, kw))
    return source, env, store, calls, requests, module


def main():
    source, env, store, calls, requests, module = fixture()
    tests = {}
    def message(sender, chat, kind='private', text='/help'):
        return {'message_id': 10, 'from': {'id': sender},
                'chat': {'id': chat, 'type': kind}, 'text': text}
    def callback(sender, chat, kind='private'):
        return {'id': 'test-callback', 'from': {'id': sender},
                'message': {'message_id': 10, 'chat': {'id': chat, 'type': kind}},
                'data': 'confirm:TESTONLY'}

    env['process_message'](message(123, 123))
    tests['unauthorized_private_message'] = {'mutation_count':len(store.actions),
        'audit_logged': any(x[0] == 'telegram_unauthorized' for x in store.logs)}
    assert tests['unauthorized_private_message']['audit_logged'] and not store.actions

    calls.clear(); store.logs.clear()
    env['process_message'](message(123, -456, 'group'))
    tests['unauthorized_group_message'] = {'mutation_count':len(store.actions), 'audit_logged':bool(store.logs)}
    assert not store.actions and not store.logs

    calls.clear(); store.logs.clear()
    env['process_callback'](callback(123, 123))
    tests['unauthorized_private_callback'] = {'mutation_count':len(store.actions), 'audit_logged':bool(store.logs)}
    assert not store.actions and not store.logs

    env['process_callback'](callback(OWNER, -456, 'group'))
    tests['owner_group_callback'] = {'mutation_count':len(store.actions), 'audit_logged':bool(store.logs)}
    assert not store.actions and not store.logs

    env['process_callback'](callback(OWNER, OWNER))
    tests['owner_private_callback'] = {'delete_invoked': any(x[0] == 'delete_user' for x in store.actions)}
    assert tests['owner_private_callback']['delete_invoked']

    store.actions.clear(); calls.clear()
    env['process_message'](message(OWNER, 777))
    tests['synthetic_private_chat_from_mismatch'] = {
        'response_target':calls[-1][1][0],
        'note':'Synthetic event only; Telegram transport normally supplies authoritative private-chat identity'}

    # Store key omits role: a persisted wizard can be resumed after downgrade.
    owner_actor = f'telegram:{OWNER}:operator'
    viewer_actor = f'telegram:{OWNER}:viewer'
    env['set_wizard'](owner_actor, 'extend', 'duration', {'username': 'audituser'})
    env['handle_wizard']('1d', viewer_actor, 'viewer')
    tests['persisted_wizard_role_downgrade'] = {'viewer_extension_executed': any(x[0] == 'extend' for x in store.actions)}
    assert tests['persisted_wizard_role_downgrade']['viewer_extension_executed']

    # Actual send_message constructed payload has no parse mode or entities.
    send_fn = next(n for n in ast.parse(source.decode()).body if isinstance(n, ast.FunctionDef) and n.name=='send_message')
    exec(compile(ast.Module(body=[send_fn], type_ignores=[]), '<actual send_message>', 'exec'), env)
    captured = []
    env['request_json'] = lambda method, payload=None: captured.append((method, payload)) or {'ok':True}
    invoice = env['created_message']({'username':'audit_user', 'max_devices':1}, 'audit`pass\\word', '30 ngày')
    env['send_message'](OWNER, invoice)
    payload = captured[-1][1]
    tests['invoice_formatting'] = {'literal_backticks_present': '`audit_user`' in payload['text'],
        'parse_mode_present':'parse_mode' in payload, 'entities_present':'entities' in payload,
        'manual_password_allows_backticks_and_backslash':env['validate_password']('audit`pass\\word')=='audit`pass\\word'}
    assert not tests['invoice_formatting']['parse_mode_present'] and not tests['invoice_formatting']['entities_present']

    # Startup only: fake every external/system operation and keep loop stopped.
    startup_methods = []
    env['acquire_lock'] = lambda: None
    env['signal'] = types.SimpleNamespace(SIGINT=2, SIGTERM=15, signal=lambda *args: None)
    env['STOP'] = True
    env['print'] = lambda *args, **kwargs: None
    def startup_request(method, payload=None):
        startup_methods.append(method)
        return {'ok':True, 'result':{'username':'UNEXPECTED_FIXTURE_BOT','id':12345}}
    env['request_json'] = startup_request
    startup_result = env['main']()
    tests['unexpected_bot_identity_not_rejected_at_startup'] = {
        'exit_code':startup_result, 'get_me_called': 'getMe' in startup_methods,
        'configure_commands_attempted': 'setMyCommands' in startup_methods,
        'network_was_mocked':True}
    assert startup_result==0 and 'setMyCommands' in startup_methods

    with tempfile.TemporaryDirectory(prefix='vcn-bot-audit-') as tmp:
        db = Path(tmp)/'live_fixture.sqlite'
        con = sqlite3.connect(db)
        try:
            con.execute('PRAGMA journal_mode=WAL')
            con.execute('PRAGMA wal_autocheckpoint=0')
            con.execute('CREATE TABLE marker(value TEXT)')
            con.execute("INSERT INTO marker VALUES ('checkpointed')")
            con.commit()
            con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            con.execute("INSERT INTO marker VALUES ('committed-only-in-wal')")
            con.commit()
            store.DB_PATH = str(db)
            result = env['handle_command']('/backup', f'telegram:{OWNER}:owner', 'owner', OWNER)
            req = requests[-1]
            raw = req['data'].split(b'Content-Type: application/x-sqlite3\r\n\r\n',1)[1].rsplit(b'\r\n--',1)[0]
            snapshot = Path(tmp)/'uploaded_fixture.sqlite'
            snapshot.write_bytes(raw)
            snapcon = sqlite3.connect(snapshot)
            try:
                uploaded_count = snapcon.execute('SELECT COUNT(*) FROM marker').fetchone()[0]
                integrity = snapcon.execute('PRAGMA quick_check').fetchone()[0]
            finally:
                snapcon.close()
            live_count = con.execute('SELECT COUNT(*) FROM marker').fetchone()[0]
            tests['direct_live_database_backup_under_wal'] = {
                'live_committed_rows':live_count, 'uploaded_rows':uploaded_count,
                'uploaded_quick_check':integrity, 'lost_committed_rows':live_count-uploaded_count,
                'entire_multipart_body_buffered':isinstance(req['data'],bytes)}
            tests['telegram_document_ok_false_ignored'] = {
                'mock_http_response_json_ok':False, 'command_reported_success':'Đã gửi' in result}
            assert live_count==2 and uploaded_count==1 and 'Đã gửi' in result
        finally:
            con.close()

    assert (ROOT/'server/telegram_bot.py').read_bytes()==source
    record = {'source_sha256':hashlib.sha256(source).hexdigest(),
              'network_calls_to_real_services':0, 'production_database_or_keys_opened':False,
              'actual_bot_token_assignment_executed':False, 'tests':tests,
              'product_source_unchanged':True, 'temporary_fixture_cleaned':True}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'bot_tests.json').write_text(json.dumps(record,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps(record,indent=2,ensure_ascii=False))
    sys.modules.pop(module.__name__,None)


if __name__=='__main__':
    main()
