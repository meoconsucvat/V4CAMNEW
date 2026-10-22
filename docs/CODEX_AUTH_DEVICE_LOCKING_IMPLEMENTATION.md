# VCNext authentication and device-locking implementation

Date: 2026-10-21 (Asia/Saigon). The requested local implementation is complete. **No production deployment or Telegram transmission was performed.**

Release: [VCNext-server-auth-refactor.zip](/C:/Users/Admin/Desktop/vcnextnew/dist/VCNext-server-auth-refactor.zip) (68,381 bytes; 16 entries), with [hash manifest](/C:/Users/Admin/Desktop/vcnextnew/dist/VCNext-server-auth-refactor.manifest.json). Archive SHA-256: `5cb1016a82571e24928dc24c75715db137a5e0b6cbf25417618910ca8c8a394b`. ZIP integrity, exact file contents, source/evidence hashes, syntax and absence of embedded token patterns were verified by the local release builder.

## Delivered behavior

| Requirement | Implementation |
| --- | --- |
| Strict cross-account ownership | The store checks global device ownership before enrollment and never changes `devices.username` in an upsert. A foreign owner gets HTTP 403 `device_bound_to_other_user`. |
| Per-account device quota | Authoritative enabled-device counts are checked under `BEGIN IMMEDIATE`, together with enrollment and session creation. |
| Migration | Owner `/clear` deletes that user's devices/sessions/challenges, increments the authorization epoch and preserves exact expiry and password. |
| Password authentication | Every account, including admin, verifies its real PBKDF2 hash. No empty/default-password bypass. Existing hashes are preserved. |
| Native P-256 proof | Mandatory challenge nonce and Base64 DER ECDSA/P-256/SHA-256 over the entire stored sorted-key challenge. Exact payload/public key are persisted. |
| Atomic login | The store rechecks account status, expiry, password version, epoch, challenge and device quota after acquiring the writer lock; consume/enroll/session/audit changes commit together. |
| Login alerts | Asynchronous HTML alerts to owner 5137016124 through the intended bot, with explicit Vietnam timestamps and no credential-bearing fields. Failed challenge routes also alert. |
| Accurate bot views | `/users` and `/devices` query committed snapshots; enabled/disabled/total device counts are explicit; `/clear` refreshes its result after commit. |
| Developer account | Fresh admin has five slots and a 315,360,000-second grant, with a protected bootstrap/random password; existing account settings are not reset. |

The reference modules under `C:/Users/Admin/Desktop/VCAM_VIP/vcnext_server_lab/` were inspected read-only. Their strict ownership rules and native field contract were used. Their lab soft-pass proof/token fallbacks, pre-proof enrollment and non-atomic transitions were not copied.

## Files

- [store.py](/C:/Users/Admin/Desktop/vcnextnew/server/store.py): shared transactional account/device/session store, additive migrations and revocation epochs.
- [server.py](/C:/Users/Admin/Desktop/vcnextnew/server/server.py): native request parsing, P-256 authentication, signed leases and notification integration.
- [notify.py](/C:/Users/Admin/Desktop/vcnextnew/server/notify.py): isolated asynchronous Telegram worker.
- [telegram_bot.py](/C:/Users/Admin/Desktop/vcnextnew/server/telegram_bot.py): fixed owner/private-chat authorization and current device/account views.
- [deployment guide](/C:/Users/Admin/Desktop/vcnextnew/server/DEPLOY_AUTH_REFACTOR.md), [environment template](/C:/Users/Admin/Desktop/vcnextnew/server/vcnext.env.example), and updated service templates.

Both service templates now load `/opt/vcnext_server/vcnext.env`. Previously only the bot unit had a token, which could not enable notifications inside the separate HTTP process. Embedded token literals were removed. A freshly provisioned credential is required; the credential supplied in chat was not used or copied into the release.

## Verification

All verification uses disposable copies, synthetic keys, loopback HTTP and mocked Telegram. Product modules are never imported from the production source directory by these tests.

Final results: **19 store checks, 30 HTTP result groups and 36 bot/alert checks passed**, all three suites exit 0. The end-to-end HTTP suite observed exactly **38 mocked alerts** (17 accepted, 21 rejected), zero tracked secret leaks, zero unhandled handler exceptions and zero external connections. Additional checks cover a disconnected response writer, a request-body timeout and proof expiry during writer acquisition.

| Suite | Evidence |
| --- | --- |
| Store transactions and migrations | [store_transactions.json](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/auth_refactor/store_transactions.json) |
| HTTP authentication/device locking | [integration_tests.json](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/auth_refactor/integration_tests.json), [findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/auth_refactor/integration_findings.md) |
| Notification worker and bot views | [login_alert_tests.json](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/telegram_audit/login_alert_tests.json), [findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/telegram_audit/login_alert_implementation.md) |

The tests verify Device A/User 1 succeeds; Device A/User 2 is rejected; Device B/User 1 is rejected at quota; clear preserves term/hash; Device B then enrolls successfully. Concurrent first enrollment and same-challenge replay each have one winner. Cross-account concurrent ownership has one winner. Invalid password, nonce, proof and token are rejected. Injected transaction failure rolls back partial device/session state. Clear/password reset invalidate paused logins. A stale session cannot overwrite a replacement generation.

Positive controls verify the native nine-field refresh proof, all five lease capabilities, typed user counts, token/nonce hashes and 384-byte RSA-3072 signatures. A seven-second remaining account term produces a seven-second lease. No Mach-O, certificate slot, code signature or Debian package is modified.

## Deliberate refresh policy

Access/renewal tokens and nonce stay stable during an authenticated session; fresh login rotates them and the unique session ID. Each refresh requires the correct Bearer, enrolled P-256 key, matching session nonce, signed request ID and integer timestamp within 120 seconds. The exact-response cache lasts 241 seconds, enough to cover the maximum acceptance window of a future-dated request. Replaying a request returns its original signed lease without extending timestamps; altered content with a reused ID fails.

This avoids the observed design flaw where a suspended app retains a nonce/token that the daemon has rotated repeatedly. Tests include parallel refreshes, a resumed client after 181 seconds with a fresh proof, and the future-dated replay boundary. The implementation accepts neither an old session's credentials after a new login nor a fake/unsigned request. Physical native app/daemon interoperability remains a deployment test.

## Operational limits and deployment gates

The release is ready for controlled deployment review using the included guide, rather than a claim of verified live operation. Preserve the existing database and signing key; inspect the linked SQLite/vendor WAL fix before rollout. The current Windows fixture runtime uses SQLite 3.50.4; no VPS library version or fix was verified. No finite timeout guarantees zero database contention; controlled busy responses are implemented.

Old challenge rows without proof material require a new challenge. Legacy sessions without the actual enrolled public key require authenticated login. Historical incorrect ownership is not silently repaired: inspect the affected accounts and perform an approved `/clear`. The existing author device thumbprint must match its real native key.

Notifications are nonblocking and have bounded retries, but their in-memory queue does not guarantee delivery through crashes or Telegram outages. Queue admission/delivery failures are logged without secrets. The notifier is not a durable audit ledger. An already issued client lease can remain usable until its short TTL after server revocation. A fresh valid login after clear can legitimately enroll again.

Broader work from the earlier architecture audit, such as versioned higher-cost password verifiers and durable Telegram command/outbox semantics, is not represented as completed by this narrowly scoped authentication/device-locking release.
