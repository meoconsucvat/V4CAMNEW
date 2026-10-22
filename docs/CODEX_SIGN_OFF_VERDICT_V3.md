# VCNext v3 retry and code-signing re-verification

Date: 2026-10-19, Asia/Saigon. Host: Windows, Python 3.14.5.

**Verdict: the existing regression checks PASS, and the two-consecutive-failure defect is fixed. Unconditional lease-expiry prevention and final code-signing sign-off are not established.** The bounded loop still resumes its nominal 45-second sleep after exhausting 20 failed attempts. Page-hash repair can be demonstrated independently of target-device signing and loading.

## Commands and scope

Completed with exit code 0:

```powershell
python scripts/sign_off_verify.py --output-dir docs/evidence/sign_off_v3
python scripts/verify_v3_retry.py
python -X utf8 scripts/verify_v3_code_directory.py
python -X utf8 scripts/verify_audit_artifacts.py
```

The explicit evidence directory preserves the previous audits. The first command also executes the patcher dry-run and the service one-shot command, both with exit code 0. Its apply experiment touches only isolated copies under `docs/evidence/sign_off_v3/staged_patch/`.

The supplied renewal service and authority patcher were not edited. The audit adds a deterministic retry probe and a separate CodeDirectory verification helper. No physical iOS device was used, and no installation candidate was built or signed.

- [Execution manifest and source hashes](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/sign_off_v3/execution_manifest.json).
- [Asserted regression checks](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/sign_off_v3/requested_checks.json).
- [Full original harness results](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/sign_off_v3/verification_results.json).
- [Retry scenarios](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/sign_off_v3/retry_scenarios.json), produced by [the retry probe](/C:/Users/Admin/Desktop/vcnextnew/scripts/verify_v3_retry.py).
- [Original archive comparison](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/sign_off_v3/input_artifact_preservation.json).

## Existing checks: PASS

| Check | Current result |
|---|---|
| `all_runtime_length_preconditions_pass` | `true`, all 14 blocks |
| Nine runtime lengths preserved exactly | `true`: `16,16,16,64,32,16,16,16,1088` |
| `new_pin_matches_server_pkcs1_sha256` | `true` |
| `blocks` | `14` across 10 files |
| `text_unchanged` | `true`, every staged `__TEXT,__text` section |
| Differences confined to declared replacement spans | `true` |
| DER / Tag 3 ciphertext / replacement span | `1071 / 1088 / 1384` bytes |
| Mocked Darwin `clock_ids` | `[8]` |
| `chown_attempted_after_chmod_failed` | `true` |
| All decoded staged certificates and pins match | `true` |
| Service lease TTL / capability set | `90` seconds / all five required grants |
| Service signature under current key and staged authority | Valid in host verification |
| Reconstructed reader with matching host clock and test key | Accepts |

All 10 extracted input binaries remain byte-identical to their corresponding members in the original `.deb`. The unchanged text-section conclusion applies to both the main and `pkgmirror` copies, including arm64 and arm64e slices where present.

The reader result is from the Python model. Darwin clock selection and the ownership-error test are mocks; they do not establish native notification delivery, real POSIX permissions, or runtime lease acceptance on iOS.

## Retry behavior: fixed for two failures, incomplete at exhaustion

The [service loop](/C:/Users/Admin/Desktop/vcnextnew/scripts/local_renewal_service.py:254) now keeps retrying every two seconds within a bounded `range(20)`. The virtual-time probe executes that actual control flow, replacing only time and the renewal operation. Its trace assertions all passed. No real waits or lease publications occur in this probe.

| Injected scenario | Renewal attempt trace or recovery | Result versus 90-second TTL |
|---|---|---|
| No failure | Successful commits at `0, 45` | PASS |
| One failure | Attempts `[0,45,47,92]`; successes `0,47,92` | PASS: successful-commit gaps are 47 and 45 seconds |
| Two failures | Attempts `[0,45,47,49]`; successes `0,49` | PASS: earlier v2 defect is fixed |
| 19 consecutive instantaneous failures | Failures at `45,47,...,81`; success at `83` | PASS under this controlled timing |
| 20 consecutive instantaneous failures | Failures at `45,47,...,83`; next success at `130` | FAIL: old lease expires at 90 |
| 21 consecutive instantaneous failures | Next success at `132` | FAIL |
| 19 failures taking 0.5 seconds each | Next success at `92.5` | FAIL before exhausting the attempt count |

The single-failure trace's final `92` is safe because a new lease was successfully committed at `47`; it is not 92 seconds since the last success.

### Exact remaining control-flow defect

The counter is a bound on **20 total attempts in that batch**, not 20 retries after the initial attempt, and not a wall-clock deadline. In the zero-duration exhaustion test:

```text
t=0     initial renewal succeeds; lease expires at t=90
t=45    batch attempt 1 fails
t=47    batch attempt 2 fails
...
t=83    batch attempt 20 fails
t=85    final two-second retry sleep finishes
        warning is printed; control returns to the outer loop
t=130   next batch starts and succeeds
```

After [the exhaustion warning](/C:/Users/Admin/Desktop/vcnextnew/scripts/local_renewal_service.py:283), there is no control transfer that keeps the service in recovery. Execution falls through to the next iteration at line 254, computes a fresh nominal deadline at line 255, and sleeps at line 258. This contradicts the claim that the loop *only* returns to nominal sleep after success.

Additionally, each failed operation's execution time is added to the two-second delay. With 19 failures of 0.5 seconds, recovery is `45 + 19 * (2 + 0.5) = 92.5` seconds. Counting attempts does not constrain that elapsed time.

**Required behavior for stronger availability claims:** track the last committed lease and its actual expiration deadline, keep an explicit recovery state when the batch limit is reached, and allow nominal sleep only after a verified successful commit. Apply time bounds to renewal operations as well as retry delays. Persistent inability to publish can still cause expiry; the service must report that loss of readiness accurately. A retry policy cannot guarantee successful writes during an unresolved storage or permission failure.

## CodeDirectory sign-off boundary

The CodeDirectory experiment and its exact measurements are recorded in [the rehash evidence](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/sign_off_v3/code_directory_rehash.json), with a reproducible [verification helper](/C:/Users/Admin/Desktop/vcnextnew/scripts/verify_v3_code_directory.py). The experiment operates on in-memory copies; it does not sign or alter extracted inputs.

| CodeDirectory measurement | Result |
|---|---:|
| Mach-O slices inspected | 14 |
| CodeDirectories inspected | 21 |
| Recorded code-page size | 4096 bytes |
| Original code-page hash mismatches | 0 |
| Staged patch code-page hash mismatches | 21 |
| Mismatches after hypothetical in-memory rehash | 0 |
| Text sections and file sizes unchanged after rehash | All |
| CodeDirectory hashes (`cdhash`) changed by rehash | All 21 |

**The in-place page-hash update is feasible for these artifacts.** The seven mirror slices each contain a SHA-1 primary CodeDirectory and a SHA-256 alternate CodeDirectory; both tables must be handled. The helper uses each directory's recorded hash type, page size, hash size, code limit, and slice base, including a shorter final page. The hypothetical differences are confined to existing code-slot hash arrays, with no reallocation or text change. Apple's [signing structures](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h) define these fields and alternate-directory slots.

All 31 present requirements/entitlement special-slot hashes match and remain unchanged by the experiment. Three app Info slots have all-zero hashes; these are absent/unsealed slots rather than newly introduced nonzero mismatches, consistent with Apple's [CodeDirectory slot-presence implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/codedirectory.cpp). These checks concern stored bytes, not entitlement authorization.

Every observed CodeDirectory has flags `0x0`, with `CS_ADHOC` clear. Every inspected SuperBlob lacks a CMS signature slot/BlobWrapper. Parsed embedded requirements contain Apple generic anchor predicates and no embedded cdhash predicate in the observed expressions. These are properties of the supplied artifacts, not a new runtime validation result. No existing CMS signature was authenticated, no requirement satisfaction was tested, and no external trust/cache binding was inspected or updated.

The supplied patcher still does not perform this page-hash repair. **Its staged outputs remain stale on disk**; the experiment only proves that replacing existing hash entries can make the stored page hashes consistent. It does not produce a signed deployment artifact.

Internal code-page hash consistency is a narrower property than acceptance of the final binary by the iOS loader, trust mechanism, and RootHide injection path. An unchanged `__TEXT,__text` digest establishes preservation of that self-integrity input; it is not proof of full-process runtime compatibility or signing acceptance.

## Other v2 limits remain

The latest harness still observes `publication_still_succeeded: true` after an injected `chmod` failure. The requested independent `chown` attempt passes, while successful metadata enforcement remains unproven. Notification-failure injection still reports a successful renewal, and missing/malformed AuthSession files still use fallback identities. These outcomes have not been changed by the retry loop.

Final deployment also requires the actual interpreter/dependencies, supervised launch configuration, resolved RootHide data path, and device-specific behavior to be validated. This host audit provides no new evidence of A11/A12+ launch, sleep/wake stability, SpringBoard operation, or mediaserverd hook stability.

**Disposition:** accept the existing regression checks and the two-failure recovery fix. Keep the broader no-expiry and final signing/runtime sign-off open; the supplied v3 loop still has the demonstrated exhaustion and operation-duration cases above.
