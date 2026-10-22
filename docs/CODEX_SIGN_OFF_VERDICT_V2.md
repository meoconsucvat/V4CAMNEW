# VCNext sign-off re-verification, v2

Date: 2026-10-19 (Asia/Saigon). Environment: Windows, Python 3.14.5.

**Verdict: PASS for every requested re-verification check.** Length metadata preservation, PKCS#1 pin selection, coverage of the main and mirror binaries, the selected Darwin clock ID, and the independent ownership-change attempt are confirmed by this run. This closes those specific failed assertions in the earlier report. It does **not** establish complete deployment readiness or a zero-crash guarantee: permission enforcement, recovery from consecutive errors, code signing, and actual iOS execution remain separate concerns documented below.

## Execution and evidence

Executed successfully, exit code 0:

```powershell
python scripts/sign_off_verify.py --output-dir docs/evidence/sign_off_v2
```

The output-directory argument preserves the earlier audit evidence. The harness also ran the requested patcher dry-run and service one-shot commands; both exited 0. It applied the patcher only to isolated copies under `docs/evidence/sign_off_v2/staged_patch/`.

The audit harness was adjusted to redirect staged certificate reads/writes through its staging root, decode patched data using stored length fields, identify mirror paths consistently on Windows, and mock the monotonic clock for deterministic scheduling tests. Neither the patcher nor the renewal service implementation was edited in this audit.

Primary evidence:

- [Requested checks, independently asserted](evidence/sign_off_v2/requested_checks.json).
- [Full measurements, source hashes, per-file/per-offset results and fault injection](evidence/sign_off_v2/verification_results.json).
- [Patcher command](evidence/sign_off_v2/patcher_run.json), [service command](evidence/sign_off_v2/service_run.json), [staged apply log](evidence/sign_off_v2/staged_apply.txt).
- [Audited one-shot lease](evidence/sign_off_v2/CapabilityLease.service.audited.plist).
- [Comparison against the original Debian archive](evidence/sign_off_v2/input_artifact_preservation.json).

## Requested results

| Check | Observed result | Verdict |
|---|---|---|
| `all_runtime_length_preconditions_pass` | `true`, all 14 blocks | PASS |
| `new_pin_matches_server_pkcs1_sha256` | `true` | PASS |
| `blocks` | `14`, across 10 files / 14 Mach-O slices | PASS |
| `text_unchanged` | `true`, every staged `__TEXT,__text` byte identical | PASS |
| `clock_ids` | `[8]` in the mocked Darwin call | PASS |
| `chown_attempted_after_chmod_failed` | `true` in controlled POSIX fault injection | PASS |

The requested output is therefore confirmed:

```json
{
  "all_runtime_length_preconditions_pass": true,
  "new_pin_matches_server_pkcs1_sha256": true,
  "blocks": 14,
  "text_unchanged": true,
  "clock_ids": [8],
  "chown_attempted_after_chmod_failed": true
}
```

## Cryptographic layout and coverage

The generated certificate is **1,071 DER bytes**; Tag 3 ciphertext is **1,088 bytes**; the replacement span is **1,384 bytes**. All nine little-endian 64-bit length fields retain their original values in every block:

| Relative offset | Value |
|---|---:|
| `+0x10` | 16 |
| `+0x28` | 16 |
| `+0x40` | 16 |
| `+0x88` | 64 |
| `+0xb0` | 32 |
| `+0xc8` | 16 |
| `+0xe0` | 16 |
| `+0xf8` | 16 |
| `+0x540` | 1088 |

The harness also reads the existing Tag 3 MAC length at `+0x568`, immediately outside the replacement span; it remains 32. Decryption of both tags uses lengths read from each staged binary, including that external MAC-length field. All 14 decoded certificates match the generated certificate, and all 14 decoded Tag 2 values equal:

```text
e4bdcd62ed447d8dee3b7e7f589c1cc98c53a5f27790d838b9ad136d5d824d06
```

This is SHA-256 of the current RSA public key's **PKCS#1 DER**, not its SubjectPublicKeyInfo DER. The harness's `new_pin_is_server_spki_sha256: false` is expected.

Each location below was checked in both the main tree and `extracted/data/var/mobile/Library/pkgmirror/`:

| Binary | File offsets, in each copy |
|---|---|
| `usr/libexec/VCNNetworkDaemon` | `0xa2c8` |
| `usr/libexec/VCNStreamDaemon` | `0x11238` |
| `Applications/VCNext.app/VCNext` | `0x2b288` |
| `Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib` | `0x1a778`, `0x4b0f8` |
| `Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib` | `0x15768`, `0x3e2a8` |

All changed bytes fall within the declared spans, each entirely inside a `__TEXT,__const` section. File sizes and every `__TEXT,__text` section remain identical. All 10 input binaries remain byte-identical to the original `.deb`; the applied copies are audit artifacts only.

## Renewal checks and remaining limits

The Windows one-shot output has TTL **90 seconds**, all five capability strings, a numeric receipt uptime, and a valid RSA signature under both the current key and the staged certificate's public key. The reconstructed Python reader accepts it with the matching test key and host clock. This is a host model result, not a native iOS verifier result. No `mocks/AuthSession.plist` existed for that command, so it used the service's fallback identity. A separate valid-AuthSession test preserved the supplied fixture identity.

The mocked Darwin clock call selects **8**, correcting the earlier clock-ID defect. No physical-device clock measurement, sleep/wake comparison, Darwin notification delivery, or real iOS ownership assignment was performed.

The single-error scheduling test produces renewal attempts at **0, 45, 47, 92 seconds**: the failure at 45 seconds is retried successfully at 47. Sleep calls begin `[45, 2, 45]`; the final recorded sleep is interrupted to terminate the test. This confirms the requested two-second retry for one transient exception.

The following limits prevent treating these passing assertions as unconditional deployment sign-off:

1. **Permissions are attempted, not enforced.** In [the service](../scripts/local_renewal_service.py), separate exception handlers now allow `chown(501, 501)` after `chmod(0644)` fails. The injected failure nevertheless produces `publication_still_succeeded: true`. Both metadata errors are warnings and publication continues. The implementation calls path-based `os.chmod` / `os.chown`, despite its `fchmod` / `fchown` wording. Verify the final mode, owner, and directory traversal permissions on-device; required metadata failure should prevent replacing a previously readable lease.

2. **Repeated renewal failures can still cross the TTL.** When both the scheduled attempt at 45 seconds and its retry at 47 seconds fail, the loop waits another 45 seconds. The next successful attempt occurs at **92 seconds**, leaving a two-second gap after a 90-second lease. This was reproduced with a deterministic clock in [the consecutive-failure test](evidence/sign_off_v2/consecutive_failure_retry.json). The current loop provides one immediate retry, not continuous two-second retries until recovery. A bounded retry loop must remain within the remaining lease lifetime to support stronger availability claims.

3. **The staged binaries need signing for their final runtime.** Fresh [CodeDirectory checks](evidence/sign_off_v2/code_signature_page_checks.json) cover 21 CodeDirectory records across all 14 slices. Every original record's page hashes match; every staged record has mismatching code-page hashes, while signature blobs remain unchanged. Unchanged text digests preserve the audited text-only self-integrity input, but do not preserve signatures covering changed constant data. Signing and RootHide loading of the final artifact remain unverified.

4. **On-device deployment is still untested.** The service is a Python/ctypes program. This run does not establish its interpreter/dependency availability, launchd supervision, correct resolved data-directory argument, native JSON/signature compatibility, or operation in SpringBoard and mediaserverd on A11/A12+. Notification-failure injection still reports publication success; missing/malformed identity files still produce fallback identities. Those outcomes must be accounted for in the deployment design.

**Final disposition:** accept the requested v2 regression checks as passed. Retain deployment sign-off as pending until the residual failure handling, final signing, and target-device validation are completed. No installable `.deb` was built or certified by this audit.
