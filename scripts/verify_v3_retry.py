"""Audit the supplied renewal loop with virtual time and injected failures.

No leases are published and no real sleeps occur. The service loads the existing
key in place; its renewal function is replaced with a controlled test double.
"""
from pathlib import Path
from unittest.mock import patch
import contextlib
import hashlib
import importlib.util
import io
import json

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs/evidence/sign_off_v3'


class StopAudit(BaseException):
    """Terminate a successful scenario without altering service error handling."""


def scenario(service, name, failures, successes_to_observe=2, failure_duration=0.0):
    elapsed = [0.0]
    sleeps, attempts, successes = [], [], []
    count = [0]
    log = io.StringIO()

    def sleep(seconds):
        sleeps.append({'at': elapsed[0], 'duration': seconds})
        elapsed[0] += seconds
        if len(sleeps) > 250:
            raise AssertionError('Audit guard: unexpected unbounded sleep sequence')

    def cycle(*args, **kwargs):
        count[0] += 1
        # Startup succeeds; inject the requested number of subsequent failures.
        failed = 2 <= count[0] <= failures + 1
        entry = {'at': elapsed[0], 'outcome': 'exception' if failed else 'commit'}
        attempts.append(entry)
        if failed:
            elapsed[0] += failure_duration
            raise OSError('audit injected publication failure')
        successes.append(elapsed[0])
        if len(successes) >= successes_to_observe:
            raise StopAudit()
        return True

    with patch.object(service.time, 'monotonic', side_effect=lambda: elapsed[0]), \
         patch.object(service.time, 'sleep', side_effect=sleep), \
         patch.object(service, 'renew_lease_cycle', side_effect=cycle), \
         contextlib.redirect_stdout(log):
        try:
            service.run_renewal_service(
                str(ROOT / 'mocks'), str(ROOT / 'mocks/test_server_private_key.pem'))
        except StopAudit:
            pass

    gaps = [b-a for a, b in zip(successes, successes[1:])]
    return {
        'name': name,
        'injected_failures': failures,
        'each_failed_operation_duration': failure_duration,
        'attempts': attempts,
        'attempt_trace': [a['at'] for a in attempts],
        'sleep_calls': sleeps,
        'success_times': successes,
        'success_gaps': gaps,
        'all_success_gaps_strictly_below_90_seconds': all(g < 90 for g in gaps),
        'retry_exhaustion_warning_seen': 'CẢNH BÁO NGUY CẤP' in log.getvalue(),
    }


def main():
    path = ROOT / 'scripts/local_renewal_service.py'
    spec = importlib.util.spec_from_file_location('v3_retry_service', path)
    service = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(service)
    cases = [
        scenario(service, 'nominal', 0),
        scenario(service, 'single_failure', 1, successes_to_observe=3),
        scenario(service, 'double_failure', 2),
        scenario(service, 'last_attempt_recovers', 19),
        scenario(service, 'twenty_failures_exhaust_bound', 20),
        scenario(service, 'twenty_one_failures', 21),
        scenario(service, 'slow_failures_before_bound', 19, failure_duration=0.5),
    ]
    by_name = {c['name']: c for c in cases}
    assert by_name['single_failure']['attempt_trace'] == [0, 45, 47, 92]
    assert by_name['double_failure']['attempt_trace'] == [0, 45, 47, 49]
    assert by_name['last_attempt_recovers']['success_times'] == [0, 83]
    assert by_name['twenty_failures_exhaust_bound']['success_times'] == [0, 130]
    assert by_name['twenty_failures_exhaust_bound']['retry_exhaustion_warning_seen']
    assert by_name['twenty_one_failures']['success_times'] == [0, 132]
    assert by_name['slow_failures_before_bound']['success_times'] == [0, 92.5]
    result = {
        'scope': 'Executed service control flow with virtual time; no device execution',
        'service_source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'ttl_seconds': 90,
        'trace_assertions_pass': True,
        'single_and_double_failure_recover_before_expiry': True,
        'all_tested_failure_scenarios_recover_before_expiry': False,
        'cases': cases,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'retry_scenarios.json').write_text(
        json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({
        'trace_assertions_pass': True,
        'scenarios': [{
            'name': c['name'], 'success_times': c['success_times'],
            'all_gaps_below_90': c['all_success_gaps_strictly_below_90_seconds']
        } for c in cases]
    }, indent=2))


if __name__ == '__main__':
    main()
