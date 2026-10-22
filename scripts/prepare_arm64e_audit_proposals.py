"""Create and verify review-only source proposals; never import the server."""
from pathlib import Path
import ast
import difflib
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/arm64e/proposals'


def main():
    originals = {name: (ROOT / name).read_bytes() for name in
                 ('server/server.py', 'extracted/control/postinst')}
    server = originals['server/server.py'].decode('utf-8').replace('\r\n', '\n')
    postinst = originals['extracted/control/postinst'].decode('utf-8').replace('\r\n', '\n')
    server = server.replace('CAMERA_TEXT_DIGEST = ',
        '# Build 37 lease readers do not compare this signed compatibility marker.\n'
        '# Preserve its existing value on both arm64 and arm64e clients.\n'
        'LEASE_COMPAT_DIGEST = ', 1)
    insertion = '''CLIENT_BUILD = "37"
# The shipped app is THIN arm64, including when executed on A12+ hardware.
# This allowlist identifies an app artifact; it does not identify the CPU.
SUPPORTED_APP_DIGESTS = {CLIENT_BUILD: frozenset({APP_TEXT_DIGEST})}


def supported_client_artifact(body, headers):
    if not isinstance(body, dict):
        return False
    build = body.get("client_build")
    digest = body.get("binary_digest")
    if not isinstance(build, str) or not isinstance(digest, str):
        return False
    if digest not in SUPPORTED_APP_DIGESTS.get(build, ()):
        return False
    return all(headers.get(name) in (None, expected) for name, expected in (
        ("X-Client-Build", build), ("X-App-Digest", digest)))


'''
    server = server.replace('REQUIRED_CAPABILITIES = [', insertion + 'REQUIRED_CAPABILITIES = [', 1)
    server = server.replace('"binary_digest": CAMERA_TEXT_DIGEST,',
                            '"binary_digest": LEASE_COMPAT_DIGEST,', 1)
    server = server.replace('"build": "37",', '"build": CLIENT_BUILD,')
    server = server.replace('        except Exception:\n            body = {}',
        '        except (ValueError, UnicodeDecodeError):\n'
        '            return self._send_json(400, {"error": "INVALID_JSON"})\n'
        '        if not isinstance(body, dict):\n'
        '            return self._send_json(400, {"error": "INVALID_JSON_OBJECT"})', 1)
    server = server.replace('        now = int(time.time())',
        '        # These clients all report the app digest, never the Camera slice digest.\n'
        '        if path in ("/api/v2/auth/challenge", "/api/v2/auth/login",\n'
        '                    "/api/v2/auth/renew", "/api/v2/auth/heartbeat"):\n'
        '            if not supported_client_artifact(body, self.headers):\n'
        '                return self._send_json(426, {"error": "UNSUPPORTED_CLIENT",\n'
        '                                             "message": "Unsupported app build or digest"})\n'
        '\n'
        '        now = int(time.time())', 1)

    comment_start = postinst.index('# A13 (iPhone 11/SE2):')
    comment_end = postinst.index('case "$machine" in', comment_start)
    model_helper = '''# Query the product model explicitly. Physical iOS uname -m can also return
# iPhone12,*; that original branch is not inherently dead code.
get_hardware_model() {
    model="$(/usr/sbin/sysctl -n hw.machine 2>/dev/null || true)"
    case "$model" in
        iPhone*|iPad*|iPod*) printf '%s\\n' "$model"; return ;;
    esac
    uname -m 2>/dev/null || true
}

# Preserve the existing A13 mediaserverd-only policy until crash logs and
# exact-device tests justify a change. This does not certify PAC safety.
# Keep the RootHide patch markers; they enable path compatibility patches.
machine="$(get_hardware_model)"
'''
    postinst = postinst[:comment_start] + model_helper + postinst[comment_end:]
    proposed = {'server/server.py': server, 'extracted/control/postinst': postinst}
    OUT.mkdir(parents=True, exist_ok=True)
    diff = ''
    for name, candidate in proposed.items():
        dest = OUT / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(candidate, encoding='utf-8', newline='\n')
        diff += ''.join(difflib.unified_diff(
            originals[name].decode('utf-8').replace('\r\n', '\n').splitlines(True),
            candidate.splitlines(True), fromfile='a/' + name, tofile='b/' + name))
    (OUT / 'compatibility.patch').write_text(diff, encoding='utf-8', newline='\n')

    # Parse the entire candidate, but execute only constant assignments and the
    # isolated pure helper. No imports, key reads, SQLite, network or server startup.
    tree = ast.parse(server)
    compile(tree, '<proposed server syntax>', 'exec')
    names = {'APP_TEXT_DIGEST', 'LEASE_COMPAT_DIGEST', 'CLIENT_BUILD', 'SUPPORTED_APP_DIGESTS'}
    nodes = [node for node in tree.body if
             (isinstance(node, ast.Assign) and any(
                 isinstance(t, ast.Name) and t.id in names for t in node.targets))
             or (isinstance(node, ast.FunctionDef) and node.name == 'supported_client_artifact')]
    env = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<isolated compatibility helper>', 'exec'), env)
    valid = {'client_build': '37', 'binary_digest': env['APP_TEXT_DIGEST']}
    tests = []

    def check(name, result):
        assert result, name
        tests.append(name)

    helper = env['supported_client_artifact']
    check('same thin app accepted on arm64', helper(dict(valid, cpu_arch='arm64'), {}))
    check('same thin app accepted on arm64e', helper(dict(valid, cpu_arch='arm64e'), {}))
    check('matching daemon session headers accepted', helper(valid, {
        'X-Client-Build': '37', 'X-App-Digest': env['APP_TEXT_DIGEST']}))
    check('camera arm64 digest is not an app digest', not helper(dict(valid, binary_digest=env['LEASE_COMPAT_DIGEST']), {}))
    check('camera arm64e digest is not an app digest', not helper(dict(valid, binary_digest=
        '60e7f7328417c91f4dd21bf27077d5196b11d8aa698ce7f0c6f78217736a6bba'), {}))
    check('unknown build rejected', not helper(dict(valid, client_build='38'), {}))
    check('numeric build rejected', not helper(dict(valid, client_build=37), {}))
    check('missing digest rejected', not helper({'client_build': '37'}, {}))
    check('non-dictionary rejected', not helper([], {}))
    check('header-body build mismatch rejected', not helper(valid, {'X-Client-Build': '38'}))
    check('header-body digest mismatch rejected', not helper(valid, {'X-App-Digest': '0' * 64}))
    check('legacy lease marker preserved', env['LEASE_COMPAT_DIGEST'] ==
        'd8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943')
    lease_node = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'lease_payload' for t in node.targets))
    lease_fields = dict(zip([x.value for x in lease_node.value.keys], lease_node.value.values))
    check('lease marker source is shared', isinstance(lease_fields['binary_digest'], ast.Name)
          and lease_fields['binary_digest'].id == 'LEASE_COMPAT_DIGEST')
    check('installer retains only existing A13 special case', '    iPhone12,*)' in postinst
          and '    iPhone11,*)' not in postinst and '    iPhone13,*)' not in postinst)

    bash = Path('C:/Program Files/Git/bin/bash.exe')
    syntax = subprocess.run([str(bash), '--noprofile', '--norc', '-n', str(OUT / 'extracted/control/postinst')],
                            capture_output=True, text=True)
    check('postinst shell syntax', syntax.returncode == 0)
    # Exercise model selection only, substituting a mock for the native sysctl
    # path in an isolated string. Never execute the installer body.
    function = model_helper[model_helper.index('get_hardware_model()'):model_helper.index('\n# Preserve')]
    function = function.replace('/usr/sbin/sysctl', 'mock_sysctl')
    model_cases = [('iPhone12,1', 'arm64', 'iPhone12,1'),
                   ('', 'iPhone12,8', 'iPhone12,8'),
                   ('arm64', 'iPhone11,8', 'iPhone11,8'),
                   ('iPhone15,2', 'arm64', 'iPhone15,2'),
                   ('', 'arm64', 'arm64')]
    for native, fallback, expected in model_cases:
        script = (f"mock_sysctl() {{ printf '%s\\n' '{native}'; }}\n"
                  f"uname() {{ printf '%s\\n' '{fallback}'; }}\n" + function + '\nget_hardware_model\n')
        result = subprocess.run([str(bash), '--noprofile', '--norc', '-c', script],
                                capture_output=True, text=True)
        check('model probe ' + repr((native, fallback)), result.returncode == 0 and result.stdout.strip() == expected)

    git = subprocess.run(['git', 'apply', '--check', '--ignore-space-change', str(OUT / 'compatibility.patch')],
                         cwd=ROOT, capture_output=True, text=True)
    check('unified patch applies to current source', git.returncode == 0)
    untouched = all((ROOT / name).read_bytes() == data for name, data in originals.items())
    check('product source byte-identical after audit', untouched)
    result = {'tests_passed': len(tests), 'tests': tests,
              'product_source_unchanged': untouched,
              'server_was_imported_or_launched': False,
              'private_keys_or_customer_db_read': False,
              'patch_applied_to_product': False,
              'syntax_stderr': syntax.stderr, 'git_check_stderr': git.stderr,
              'original_source_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in originals.items()}}
    (OUT / 'verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
