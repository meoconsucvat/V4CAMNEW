# VCNext build 37 — remediation re-audit verdict

Date: **2026-10-21, Asia/Saigon**.

**Formal verdict: package-integrity sign-off passes; unrestricted commercial release sign-off remains withheld.** The canonical ar repair, one-time challenge consumption, license-expiry clipping and migration-term preservation are verified. Authentication is still optional when fields are omitted, device-key possession is not verified, session-update races remain, and unbind can still delete another license's session.

## 1. Commands, identities and evidence

Both requested commands were executed unchanged and completed with exit code **0**:

```text
python scripts/audit_final_package.py
python scripts/audit_commercial_server_isolated.py
```

An exit-zero audit script is not a security pass: the server suite records counterexamples as well as successful checks. Supplemental tests exercised omitted/empty credentials, device proofs, concurrent session rotation and administrative isolation.

| Audited item | Current identity |
| --- | --- |
| Package size | **496,292 bytes** |
| Package SHA-256 | `4d1f8bf580e1c7699865fbafec4302ad28ab9df9a155b8bc13d68330ef51675b` |
| `server/server.py` SHA-256 | `af80e990bf32e9f75d90aad54122a2da278694f101240481761c2ae55ffac496` |
| `server/admin_cli.py` SHA-256 | `042a389b92058eef99a085da20c8828df6ecb8c62c97e9b47510679e93575aad` |

The public download returned HTTP 200 at **02:53:42 UTC / 09:53:42 Asia/Saigon**, and matched the current local package byte-for-byte. This was a read-only artifact GET with ordinary CA/hostname validation, not an iOS TLS-pin or live licensing test. [Download record](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/live_download/verification.json).

Fresh evidence is under [re_audit](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/): [package checks](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/package.json), [independent package invariants](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/package_invariants.json), [requested server-suite output](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/server_tests.json), [supplemental server tests](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/server_edge_tests.json), and [eight admin/migration cases](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/admin_tests.json). Historical `final_sign_off` evidence was preserved and its overwritten JSON outputs restored after retaining the fresh results, so the earlier report keeps its original evidence.

Server tests used byte-identical source copies, fresh throwaway RSA-3072 keys, disposable SQLite databases and loopback HTTP only. Controlled row-read pauses forced permitted concurrency interleavings without changing authorization logic. No production key/database was opened, no production licensing request was sent, and no product source, binary or live service was modified. Final fixtures/listeners closed normally. Apple Foundation and physical iOS execution were not performed.

## 2. Package integrity and A12–A16 preservation — PASS

| Requirement | Result |
| --- | --- |
| All enclosing ar mode fields | Exact eight bytes **`100644  `**, hex **`3130303634342020`**, for all three members |
| ar order/bounds/padding, zstd frames, tar checksums/end markers | Pass |
| Executable files | **10**, all full-file byte-identical to the previously audited customized binaries |
| Original `__TEXT,__text` sections | **14**, unchanged |
| CodeDirectories | **21**, **0 code-page mismatches** |
| Genuine AutoPatches marker symlinks | **5**, correct target `/usr/lib/DynamicPatches/AutoPatches.dylib` |
| Requested preinst/postinst source/archive/mirror parity | Pass |
| Script syntax / model-helper checks | Pass; **6 mocked model-probe cases** |
| Live/local/server-directory package copies | Byte-identical |

The compressed control and data payloads themselves match the previous release. The ar correction changes enclosing metadata, with no new executable, hook, PAC instruction, Mach-O load command, fixup or authenticated-pointer change. **No new compiled binary/PAC regression is introduced by this package revision.** [Package findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/package_findings.md).

This does not certify runtime hook-backend behavior or every A12–A16 device. The previous A13 fresh-config/canary gate, private-method compatibility checks, path/entitlement requirements and external PAC hook-provider assumptions remain. The Camera/Overlay lease consumers still do not compare lease `binary_digest`; no architecture-dependent digest patch is necessary. Physical A12+ camera/overlay validation remains outstanding under the [existing disassembly and support boundaries](/C:/Users/Admin/Desktop/vcnextnew/docs/CODEX_ARM64E_A12_A16_AUDIT.md).

Unchanged installer caveats also remain: main launchd plists start with uid501 metadata and rely on successful postinst chown; ownership/load errors are suppressed; main/mirror prerm contexts differ; real installer-context sysctl access and install/upgrade/removal were not exercised. Those limits are not new PAC failures, but prevent treating integrity checks as a complete installation/runtime guarantee.

## 3. Requested remediation checks

| Claim/check | Observed result | Verdict |
| --- | --- | --- |
| Removed special `admin` bypass | A different asserted device ID receives challenge **403 DEVICE_MISMATCH** | **Specific bypass removed**, but device-ID impersonation remains below |
| Direct rogue admin login | Using the bound device's challenge from another ID: **403 CHALLENGE_INVALID**; a synthetic legacy pending challenge for the rogue ID reaches **403 DEVICE_MISMATCH** | Rejected; exact error depends on validation order |
| Same challenge concurrently consumed | **[200,403]**, exactly **1 valid RSA lease**, no challenge double-spend | **Pass** |
| Different-device first activation | **[200,403 DEVICE_MISMATCH]**, one binding/session | **Pass in forced-overlap test** |
| Wrong nonempty login nonce | **403 NONCE_MISMATCH** | **Pass for supplied wrong nonce**, incomplete presence validation |
| Wrong nonempty heartbeat/renew Bearer token | **401 INVALID_TOKEN** | **Pass for supplied wrong token**, incomplete authentication |
| Delete-without-replacement during in-flight heartbeat | **401 SESSION_REVOKED**, no new lease | **Pass for this interleaving**, replacement/concurrent-update cases remain |
| One second of license remaining | Signed TTL **1 second**, **0 overrun**, valid signature/bindings/capabilities | **Pass** |
| Exactly at license expiry | **403 LICENSE_EXPIRED** | **Pass** |
| Login after signed challenge expiry (+100s) | **403 CHALLENGE_INVALID** | **Pass**; database lifetime now matches signed 90s |
| Unbind/migrate with two days left | Exactly two days remain; **extension_seconds = 0** | **Pass** |
| Normal canonical-key unbind | Relevant sessions/challenges removed; paid expiry preserved | **Pass for normal state**, shared-device isolation fails below |
| Extend unactivated 30-day key by seven days | `duration_days = 37`, `expires_at = 0` | **Pass** |
| Negative/zero extension | No row changes | **Pass** |
| Unhandled handler exceptions in selected suites | **0** in requested and supplemental HTTP cases | **Pass within those inputs** |

The requested suite's `schema_valid:false` for the clipped one-second lease is an **audit-helper limitation**, not a server regression: `Fixture.lease()` still requires TTL to equal exactly90. The reconstructed active reader accepts positive duration up to95. Supplemental validation independently confirmed the one-second reply's RSA signature, bindings, five capabilities and no license overrun. Correct that helper predicate before using it as a pass/fail gate.

Likewise, the requested suite's `admin_rogue_device_login` field reuses the failed challenge response when challenge creation is rejected; it is not itself a direct login POST. The direct-login cases above were separately executed. Neither an inaccurate test label nor exit code zero is used as proof.

## 4. Remaining commercial release blockers

### 4.1 Missing credentials bypass the new checks — P1

At [server.py:488](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:488), [494](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:494), and [586](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:586), the effective rule is:

```python
if bearer_token and bearer_token != expected_token:
    reject()
```

Consequently **omitted Authorization, an empty header, empty Bearer, and a different authentication scheme all succeed** on heartbeat, renew and logout for an existing asserted device ID. Wrong nonempty Bearer fails as intended. A caller can omit the credential rather than tamper with it; renewal can issue valid signed replacement tokens without authentication.

Login has the same presence defect at [server.py:337](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:337): omitted, empty, null, false and zero `challenge_nonce` values all returned HTTP200. Only a wrong truthy nonce was rejected.

Require a nonempty correctly typed nonce/token and then compare it, returning a controlled rejection for missing/empty/malformed input. This is compatible with the audited genuine client, which supplies those fields. Constant-time secret comparison is appropriate; correcting the boolean condition alone does not close the device-proof or concurrency problems below.

### 4.2 Device proof remains unverified; seeded admin ID can be impersonated — P0 impact

Removing the explicit admin branches is a real improvement. It still does not prove that a request came from the author's physical phone. In a disposable fixture, a different client **claimed the seeded admin device ID**, supplied an independently generated P-256 public key, and provided no author-device signature. It received HTTP200 and a valid RSA-signed admin lease bound to the throwaway key's thumbprint.

The server still does not verify login/session `device_signature`, and does not persist the enrolled P-256 public key/full challenge material needed for verification. Supplying an invalid device signature also succeeded; with a valid Bearer token, incorrect heartbeat/renew nonce, old issued_at and invalid proof succeeded. These are explicit supplemental executions.

Bind the license to an authenticated enrollment/key, verify the client's P-256 proof over the exact challenge/session message, and enforce request nonce/freshness. Do not accept a replacement key for an already bound license solely because a caller repeats its device ID. The admin enrollment needs an existing trusted key or a separate authenticated enrollment credential; a public account name plus an asserted identifier is insufficient. Plan trusted enrollment/migration before requiring checks on existing sessions.

### 4.3 Rowcount guards do not prevent stale session replacement — P1

The new rowcount check correctly rejects a heartbeat when its selected row was deleted and remains absent. The UPDATE still matches only `device_id` at [server.py:547](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:547).

Two other permitted interleavings were reproduced:

- **Concurrent valid same-token requests:** both cached the same session, both returned200 with different valid leases/tokens. The losing response's subsequent heartbeat **and** renewal returned401. A legitimate app/NetworkDaemon race can leave a client holding invalidated credentials; the client's other recovery guards do not make this server transition atomic.
- **Delete then recreate the same device row:** an old heartbeat paused after SELECT; its row was deleted and recreated for another license; the old UPDATE then matched the new row and returned200. It overwrote that row's tokens/expiry while keeping its new license/thumbprint, and returned a lease using the old license/thumbprint. Rowcount was nonzero despite stale authorization.

Use a checked session generation/identity, token and nonce/version in the transaction's conditional update, with corresponding license/binding validation. Define authenticated retry/idempotency behavior for concurrent legitimate clients and lost replies. A row's continued existence is not proof that it is the session originally authorized.

### 4.4 Shared-device unbind isolation still fails — P1

`cmd_unbind()` now deletes canonical-license sessions and case-insensitive pending challenges, but retains [admin_cli.py:201](/C:/Users/Admin/Desktop/vcnextnew/server/admin_cli.py:201):

```sql
DELETE FROM sessions WHERE device_id = ?
```

Reproduction: license A remains bound to device D; D subsequently logs in using license B, replacing its device-keyed session. Unbinding A still deletes B's session. Thus the claim “without touching other licenses on shared test devices” is false for current code.

Remove or correctly scope this fallback. Resolve legacy NULL-key sessions with an explicit trusted migration mapping instead of deleting every session at an old device ID. Equivalent unscoped deletion remains in revoke-by-license and deserves the same review. [Admin findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/re_audit/admin_findings.md).

## 5. Upgrade and runtime conditions still requiring verification

Actual migration against the old eight-column session schema added `license_key` but left the legacy admin session's value **NULL**. The current heartbeat/renew license lookup then matches no license and the handler rejects/deletes that session as LICENSE_EXPIRED. This is an executed migration/SQL observation combined with the handler branch, not a claim that the live database currently contains such a row. Backfill or authenticated reenrollment is needed before claiming zero disruption for that state.

Conditional legacy/manual case-variant or NULL-key sessions can also survive canonical-key cleanup. Normal new logins store canonical keys; distinguish those conditional states from ordinary new enrollment. Activated-key extension intentionally changes revoked status back to active; document that administrator policy rather than treating it as a remote bypass.

Package byte identity preserves the prior static arm64e conclusions, not physical-device certification. Actual RootHide installation, AMFI/load admission, the installed PAC hook backend, A13 first-use configuration behavior, Foundation JSON interoperability and camera/overlay coverage still require named device/OS/build testing. Existing code-page and source tests do not establish zero crashes or kernel panics. The [previous physical-device checklist](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/arm64e_findings.md) remains applicable.

## 6. Final disposition

**Approved within scope:** canonical package integrity, unchanged binary/PAC metadata, the demonstrated one-winner challenge consumption, clipped lease deadlines, paid-term preservation, and the selected extension/input improvements.

**Not approved:** unrestricted commercial licensing/deployment. Close mandatory credential and device-proof validation, stale session transitions, shared-license deletion and applicable legacy migration gaps; then rerun negative/concurrency tests and perform physical client interoperability validation. The remediations substantially improve the earlier state, but the current evidence does not support declaring all release blockers closed.
