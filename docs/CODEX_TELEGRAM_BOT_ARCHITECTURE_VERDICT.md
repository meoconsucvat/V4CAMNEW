# VCNext username/password engine and Telegram administration audit

**Date:** 2026-10-21, Asia/Saigon. **Disposition: architecture viable; current implementation NOT approved for commercial deployment.**

The native username/password workflow, typed account response and sequential multi-device enrollment work in disposable tests. However, the current source accepts empty/default administrator passwords after a password reset, accepts omitted Bearer authentication, overbooks device quotas under concurrency, and allows administrative revocation to lose races with login/session renewal. The bot also uploads the live SQLite main file rather than a consistent snapshot. These are reproduced counterexamples, not hypothetical concerns.

## 1. Scope, source identity and evidence limits

The intended deployment boundary is **13.238.38.121, `/opt/vcnext_server/`, `vc.huxa.xyz`, @VCAM_V5_ADMIN_BOT, owner ID 5137016124**. This audit used local source, disposable databases, newly generated fixture keys, loopback HTTP and mocked Telegram transport. **No Telegram API call, message, backup upload, VPS connection, production database/key read, package rebuild or production-source modification was performed.** Official public documentation was read for the recommendations below. No historical server was contacted.

Current source hashes, rechecked after testing:

| File | SHA-256 |
| --- | --- |
| `server/store.py` | `7d71c743b330e78b32ae5a101b2bcc6f33f4205914a10b36fba0cd0f217debcc` |
| `server/server.py` | `5665bbb2d683ebcbfaec022f9ec28df1366fa1200da2e0930371ee28b95ea6db` |
| `server/telegram_bot.py` | `8a0d6c3e0999e76b6703a9e0830e791cc5ca458fe42411fe66fd223354b1f001` |

Commands executed successfully against isolated fixtures:

```powershell
python -X utf8 scripts/audit_telegram_store_isolated.py
python -X utf8 scripts/audit_telegram_http_isolated.py
python -X utf8 scripts/audit_telegram_bot_isolated.py
```

| Suite | Recorded groups | Evidence |
| --- | ---: | --- |
| Store | 15 | [store_tests.json](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/telegram_audit/store_tests.json), [analysis](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/telegram_audit/store_findings.md) |
| HTTP | 17 | [http_tests.json](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/telegram_audit/http_tests.json), [analysis](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/telegram_audit/http_findings.md) |
| Bot | 11 | [bot_tests.json](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/telegram_audit/bot_tests.json), [analysis](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/telegram_audit/bot_findings.md) |

All three harnesses exited 0. Several assertions deliberately confirm a vulnerability; that exit status means the audit completed, not that the product passed security review. Concurrency cases force legitimate scheduling boundaries around the actual functions to make races reproducible; they do not estimate production attack frequency. Zero unhandled HTTP exceptions occurred in the selected HTTP cases. Store contention separately produced an actual lock exception.

No new Mach-O disassembly, Foundation execution, physical iPhone test or live deployment verification is claimed. The native response/proof requirements referenced below come from the existing [UI and Tag 1 audit](/C:/Users/Admin/Desktop/vcnextnew/docs/CODEX_UI_AND_TAG1_AUDIT.md).

## 2. Release-blocking findings

| Priority | Finding and observed result | Current source |
| --- | --- | --- |
| **P0** | Administrator password bypass: after setting a strong password, both empty password and legacy `1` still obtained valid leases on new devices | [server.py:293](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:293) |
| **P0 operational** | A bot credential was exposed in the request; source and service also embed differing credentials. Startup accepts an unexpected bot identity in the mocked test | [telegram_bot.py:32](/C:/Users/Admin/Desktop/vcnextnew/server/telegram_bot.py:32), [unit:9](/C:/Users/Admin/Desktop/vcnextnew/server/vcnext-bot.service:9), [startup:876](/C:/Users/Admin/Desktop/vcnextnew/server/telegram_bot.py:876) |
| **P1** | Missing Bearer token is accepted for heartbeat and logout; device proof is not verified. A supplied bad token is rejected, but omission bypasses the check | [server.py:400](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:400), [405](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:405), [488](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:488) |
| **P1** | Two concurrent, correctly authenticated logins both succeeded for `max_devices=1`; two device rows persisted | [server.py:302](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:302), [309](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:309) |
| **P1** | Login paused after password verification survived `/clear` or `/setpass` and recreated a session | [server.py:278](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:278), [353](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:353), [store.py:235](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:235), [318](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:318) |
| **P1** | Session version resets to 1 on recreation; a stale heartbeat matched the replacement row and overwrote its tokens | [server.py:353](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:353), [455](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:455) |
| **P1** | `/backup` WAL fixture had two committed rows but uploaded only one; a mocked `{ok:false}` upload response still reported success | [telegram_bot.py:178](/C:/Users/Admin/Desktop/vcnextnew/server/telegram_bot.py:178), [426](/C:/Users/Admin/Desktop/vcnextnew/server/telegram_bot.py:426) |
| **P1 integrity** | Confirmation actor is ignored; two concurrent consumers accepted the same code. Default sequential polling reduces exposure but does not repair the database contract | [store.py:363](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:363), [376](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:376) |
| **P1 migration** | Existing sessions schema without `session_version` is not migrated; the handler SELECT fails in that fixture | [store.py:52](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:52), [server.py:381](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:381) |

The exposed credentials must be revoked/rotated by their owner before deployment. Remove hardcoded defaults and the literal token in the unit; require an explicitly provisioned secret and fail startup if it is missing. No credential value is reproduced in these artifacts. Telegram documents token management through BotFather. [Official bot administration](https://core.telegram.org/bots/features#botfather).

## 3. Username/password data model

### 3.1 Password storage: correct primitive, insufficient current policy

`password_hash()` uses PBKDF2-HMAC-SHA256 with **200,000 iterations**, a random **16-byte salt** represented as 32 hex characters, and a 32-byte output. `verify_password()` recomputes and uses `hmac.compare_digest`. Independent fixture calculation matched, distinct salts were generated, a normal correct password passed and a wrong password failed. [store.py:21](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:21), [43](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:43).

The salt size is appropriate; **200,000 is below OWASP's current 600,000 recommendation for PBKDF2-HMAC-SHA256**. Argon2id is another suitable design if its dependency and memory cost are acceptable. Benchmark the chosen work factor on this VPS, with bounded authentication concurrency. Raising cost does not compensate for weak passwords or bypasses. [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

The store accepts empty passwords, the bot permits one-character passwords, and fresh initialization seeds admin with `1`. These policies are unsuitable for customer account protection. As a benchmark, NIST's current single-factor password guidance specifies at least 15 characters, permits a maximum of at least 64, and calls for compromised/common-password screening and rate limiting. This is a benchmark, not a claim that this product has NIST certification or that every commercial deployment has the same regulatory obligation. [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).

**Required store adjustment:** persist algorithm/version and iteration count per credential, or a self-describing encoded verifier. Keep verification support for existing 200,000-iteration hashes and upgrade after successful authentication. Merely changing `PBKDF2_ROUNDS` globally invalidates existing hashes because their cost is not stored. Enforce one password policy at the shared store boundary, not only inside Telegram command parsing. Never include password plaintext or verifier material in audit events.

### 3.2 Login timing and account discovery

`compare_digest` protects the final equal-length digest comparison; it does not equalize the entire endpoint. Currently `/challenge` discloses `USER_NOT_FOUND`, `USER_DISABLED`, `USER_EXPIRED` and `DEVICE_LIMIT_REACHED` before any password verification. These distinctions were reproduced. Password failures also have their own `INVALID_PASSWORD` response.

For the requested anti-enumeration behavior:

1. Validate bounded field types and ASCII username syntax uniformly. Apply per-account and per-source request budgets, plus a global bound on costly KDF work. The inspected Nginx configuration has no authentication rate-limit policy.
2. The native challenge request does not contain the password. Issue an indistinguishable, short-lived signed challenge for syntactically valid usernames, including unknown/ineligible accounts, or explicitly accept and document account discovery. Do not pretend a timing-safe digest comparison fixes distinct pre-authentication errors.
3. At login, verify an appropriately costed dummy hash for nonexistent accounts; use the same generic invalid-credentials response for unknown users and bad passwords. Avoid claiming mathematically identical network timing; comparable expensive work and identical public error shape are the practical objective.
4. Reveal account-specific quota information only after credential authentication. Log a sanitized internal reason separately.

Remove the admin conditional entirely: every account must pass the same password verification. Challenge nonce must be a required, correctly typed matching value; absent/null currently skips its validation. Current challenge deletion commits before password verification, so one bad-password attempt consumes the challenge. If this consumption-on-attempt policy is retained for abuse control, document it and require a fresh challenge on retry; it is not the same as an atomic authenticated login transition.

### 3.3 Canonical usernames and schema

The bot limits usernames to ASCII letters, digits, underscore, dot and hyphen, length 3–64. The store and HTTP route do not enforce that same boundary. Python `casefold()` is not identical to the app's Foundation `lowercaseString` for every Unicode string, as the existing challenge verifier requires. Enforce the same ASCII policy centrally, then normalize consistently. Arbitrary Unicode support requires explicit Foundation interoperability vectors.

Use explicit, versioned schema migrations before HTTP/bot startup. `CREATE TABLE IF NOT EXISTS` does not add new columns to an existing table. Migrate the prior license-engine accounts, sessions and devices deliberately; do not invent passwords from old hashes or silently reset expiry dates. Back up first, validate schema/data invariants, then start both services against the same resolved database path.

Recommended additions include a stable account ID, `auth_epoch`, versioned password verifier parameters, a non-reused session generation ID, validated enrolled device public keys, and foreign keys for challenges. Add checked positive device quotas, appropriate account/device indexes and expiry indexes. Account-ID references also prevent an old confirmation targeting a username that was deleted and recreated.

## 4. Device enrollment, clearing and session authentication

### 4.1 Device quota and HTTP response

Sequential tests work: a one-slot user rejects a second device; a two-slot user admits two devices and rejects a third. The current challenge response is **HTTP 403** with `error: "DEVICE_LIMIT_REACHED"` and a Vietnamese explanatory message. That code is a reasonable authenticated quota error; 429 should be reserved for request throttling.

Recommended response, **after credentials are valid**:

```json
{"error":"DEVICE_LIMIT_REACHED","message":"Tài khoản đã đạt giới hạn thiết bị. Vui lòng liên hệ quản trị viên để đổi máy."}
```

Challenge checking is advisory only. Login must atomically distinguish an already enrolled, enabled device from a new device and compare the authoritative enrolled count with `max_devices`. Currently list/read, device upsert and session creation use separate transactions. Two valid, distinct device logins both cached count 0, both returned signed HTTP 200 leases reporting count 1, and left count 2 for a one-slot user.

Define enabled-device semantics consistently: `get_user()` counts enabled rows, while `list_devices()` and current quota checks include disabled rows. Recheck enabled state during renewal. `device_id` is currently globally unique, and the login upsert can reassign its username/key. Account switching and enrolled-key rotation must be explicit authenticated transitions rather than a blind overwrite of an asserted identifier.

### 4.2 Required login transaction boundary

The following is an implementation specification, not an applied patch:

```text
Parse bounded request; load credential/account/challenge snapshot.
Verify password and native P-256 proof outside the writer lock.
Prepare replacement tokens and a unique session generation.

BEGIN IMMEDIATE
  Re-read account: enabled, expiry, auth_epoch and credential version unchanged.
  Re-read challenge: account, device, public-key binding, nonce, expiry valid.
  Check enrolled-device ownership/enabled state and authoritative device quota.
  Conditionally consume the valid challenge; require exactly one affected row.
  Enroll/update the authenticated device and create the session together.
  Record account/key binding, unique generation, version and current nonce.
  Insert sanitized audit/idempotency records.
COMMIT

Sign/send the compatible response outside the writer lock.
Handle a lost reply through an authenticated, bounded idempotency policy.
```

If an attempt-consumption transaction is deliberately separate, its result must bind the exact authenticated attempt and account epoch; no lease may follow stale quota or revocation state. Keep KDF, RSA, Telegram and other network work out of long-held database write transactions. A durable response/outbox policy must distinguish a committed session whose reply failed from an uncommitted transition.

### 4.3 `/clear`, `/setpass` and migration

The basic `reset_devices()` transaction **passes**: it deletes that user's devices, sessions and pending challenges while preserving expiry, password hash/salt and other users' state. Therefore it does not reset the subscription term. [store.py:318](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:318).

It does **not** guarantee exclusive migration under concurrency. A login that already passed the old checks can commit afterward; this was reproduced for both clear and password reset. Fix by incrementing `users.auth_epoch` within the same transaction as revocation, and require the unchanged epoch in every issuance/renewal transition. Password reset must also purge challenges and invalidate outstanding enrollment work. Keep expiry and password unchanged for `/clear` as requested.

A former device still knowing the unchanged password can attempt a fresh enrollment after clear. A one-slot quota alone cannot determine which physical phone the owner intended. For an exclusive migration, use an owner-approved next-device enrollment or another explicitly designed migration authorization. Existing signed leases can remain valid until their current short TTL elapses; server cleanup alone cannot instantly erase an already issued local lease.

Additional reproduced cleanup defects:

- `remove_device(username, device_id)` deletes the session by device ID even when its username-scoped device deletion removes zero rows. The test preserved another user's device but deleted its session. Scope both operations by account and device, and require ownership. [store.py:332](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:332).
- `delete_expired_users()` leaves challenge rows behind. Give challenges an account foreign key/cascade or delete them in the same transaction. [store.py:307](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:307).
- `extend_user_seconds()` reads expiry before its write transaction; concurrent extensions can lose an addition. Recompute from the latest row inside the write transaction, with idempotent command IDs. [store.py:217](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:217).

### 4.4 Tokens, proof and non-reused session generations

The current condition `if bearer_token and bearer_token != expected` permits an empty/missing token. Require a nonempty, correctly parsed Bearer value before any heartbeat, renew or logout state change; compare against the endpoint's proper token. Heartbeat uses the access token; renew uses the renewal token; retain the existing client's saved-token logout contract. Do not invent a mandatory new logout proof field absent from the app.

The server also needs the enrolled P-256 public key and the exact challenge/session-proof material to verify the native device signature and freshness. A matching device ID or hash of arbitrary supplied key bytes does not prove possession. Current device rows leave the public-key field empty, login nonce checking is optional, and a heartbeat with a valid token but invalid nonce/proof still succeeded. The app's P-256 request proof and the authority's RSA reply signature serve different directions of authentication.

Current `session_version` checking does give one winner for two ordinary concurrent updates: fixture results were one 200 and one 401. However, session replacement resets version to 1. An old version-1 heartbeat survived deletion/recreation and overwrote the new account's session tokens. Add a random, non-reused generation identifier and bind the update to account, device key, epoch, expected token/nonce and version:

```sql
UPDATE sessions
SET access_token = ?, renewal_token = ?, current_nonce = ?,
    session_version = session_version + 1
WHERE session_id = ? AND username = ? AND device_id = ?
  AND device_key_thumbprint = ? AND auth_epoch = ?
  AND session_version = ? AND current_nonce = ?;
```

This illustrates **proposed schema fields**, not a query runnable against today's schema. Require one affected row and revalidate the account/device within the same transaction. Define authenticated retry/idempotency for simultaneous legitimate app/NetworkDaemon traffic and lost responses; simply rejecting every racing rotation can create customer logout loops.

### 4.5 Developer account and wire compatibility

Fresh initialization currently grants admin 315,360,000 seconds, five slots and one pre-enrolled developer device. It seeds password `1`, with an empty device public key. This is a fixture/source observation; the production row was not inspected. Five slots intentionally permit additional authenticated devices; one seeded phone does not imply an exclusive hardware lock.

Provision a strong administrator password through controlled bootstrap, store its normal versioned verifier, and enroll the developer's **validated real public key**. Do not reset a pre-existing password, expiry or enrollment on restart. Migrate current developer sessions deliberately before enabling required proof checks; a stored thumbprint alone cannot reconstruct the missing public key. Telegram owner identity must not create a separate app-login bypass.

Positive HTTP fixtures verified RSA-3072 PKCS#1 v1.5 SHA-256 signatures (384 signature bytes), all five capabilities, token/nonce bindings and typed `user` fields. With seven account seconds remaining, the signed lease TTL was seven seconds with zero overrun. Preserve `lease_signature`, the existing binding fields and `min(90, remaining_seconds)` while rejecting expired accounts. These Python/ASCII fixtures do not establish universal Foundation JSON byte parity; retain sorted compact serialization and add native vectors for all permitted data before broadening input types.

## 5. SQLite concurrency between HTTP and bot

### 5.1 Current behavior and realistic guarantee

`connect()` sets `timeout=15.0` and foreign keys on; it does **not** enable WAL. A fresh fixture reported journal mode `delete`, busy timeout 15,000 ms and foreign keys 1. Existing production persistence could differ; no live PRAGMA was queried. [store.py:29](/C:/Users/Admin/Desktop/vcnextnew/server/store.py:29).

WAL improves reader/writer coexistence but SQLite still has one writer, and WAL can return `SQLITE_BUSY`. No PRAGMA guarantees zero lock exceptions under arbitrary contention. A WAL fixture with a held writer caused the actual store operation to raise `database is locked` after about 16.2 seconds. [SQLite WAL behavior](https://www.sqlite.org/wal.html).

**Current version prerequisite:** the audit host links SQLite 3.50.4; that is not evidence of the VPS version. SQLite documents a rare WAL-reset corruption bug fixed in 3.51.3+, with backports 3.44.6 and 3.50.7. Verify the VPS Python-linked SQLite and its vendor fix before enabling concurrent WAL. No corruption was observed here. [SQLite WAL-reset advisory, section 11](https://www.sqlite.org/wal.html).

### 5.2 Concrete configuration specification

At controlled initialization, on local storage, enable `PRAGMA journal_mode=WAL` and verify the returned mode. Configure both programs' connections consistently; for example:

```python
# Connection-policy sketch; integrate with explicit transaction management.
con = sqlite3.connect(DB_PATH, timeout=5.0, isolation_level=None)
con.row_factory = sqlite3.Row
con.execute("PRAGMA foreign_keys=ON")
con.execute("PRAGMA busy_timeout=5000")
con.execute("PRAGMA synchronous=FULL")
# For an authoritative write unit:
con.execute("BEGIN IMMEDIATE")
try:
    # Recheck invariants and perform the entire state transition here.
    con.commit()
except BaseException:
    con.rollback()
    raise
```

This explicitly changes transaction handling; do not paste it into the current context manager and assume old implicit-transaction behavior is unchanged. `BEGIN IMMEDIATE` obtains the writer role before quota reads; a finite busy timeout is a wait budget, not a correctness mechanism. `FULL` is the conservative durability choice; select a different setting only with an explicit power-loss tradeoff. [Transactions](https://www.sqlite.org/lang_transaction.html), [PRAGMA reference](https://www.sqlite.org/pragma.html#pragma_busy_timeout).

Catch SQLite busy/locked outcomes at HTTP and bot boundaries. Use bounded jittered retries of the **whole idempotent transaction**, then a controlled HTTP 503/retry response or truthful bot failure. Keep the combined wait/retry budget below the inspected Nginx 10-second upstream read timeout, leaving execution margin. Do not hold database locks during KDF, signing, upload or Telegram polling. Monitor checkpoint progress, WAL size, long readers, disk space and writer latency.

Both service users need access to the database directory and its `-wal`/`-shm` files. Use a dedicated state directory and shared database group with restrictive directory/file modes; do not make the Python code/signing-key directory generally writable. Audit mutations and command-idempotency records should commit with their mutation. Current separate `audit()` calls can fail after the operation has already committed, yielding a misleading failure/retry outcome.

## 6. Telegram authorization, confirmations and delivery

### 6.1 Owner/private-only boundary

The default owner set is `{5137016124}` and private-only defaults true. Sender numeric ID is checked, not display name or a claimed username. Tests confirmed unauthorized private messages and callbacks cannot mutate, and owner group callbacks are rejected. This is a useful starting boundary.

It is configurable: owner/admin environment sets are unioned, optional operator/viewer roles exist, and private-only can be disabled. For the requested deployment, fail startup unless the owner set is exactly the approved singleton, no auxiliary roles are enabled and private-only is true. Apply the same gate to messages, callbacks and every wizard step; constrain backup and credential replies to the owner private chat. A defensive `chat.id == from.id == owner` check is appropriate for this mode. Synthetic inconsistent events were accepted, but **no claim is made that an outsider can forge Telegram's authenticated sender fields**.

Unauthorized private messages are audited; denied groups and denied callbacks return without an audit entry. Add sanitized actor/chat/update IDs and rejection reason on all paths, with rate-bounded logging. Never record complete command text containing passwords or token-bearing API URLs. A persisted operator wizard resumed after downgrade to viewer and executed an extension; re-authorize each step and invalidate pending state when permissions change.

The source and unit identify different token values, and mocked startup accepted an unexpected `getMe` identity before configuring commands. Require a known stable bot ID plus expected username during authorized deployment validation, failing before command registration/polling if identity differs. Local unit paths point to the intended installation, but the active VPS environment and actual bot identity remain unverified.

### 6.2 Destructive confirmation contract

The requested `/del`, `/clear`, `/delexpired` confirmation UI exists, with a default 90-second TTL. The expiry test rejected a code after 91 seconds. Ordinary sequential reuse is rejected, but actor binding and concurrent one-time consumption fail: a foreign actor consumed/cancelled a code, and two forced concurrent consumers both succeeded. Codes have only 32 random bits. Role checking after consumption lets a configured lower role burn another actor's pending owner action even when execution is denied.

Use at least 128 random bits and bind each confirmation to actor ID, private chat, originating message, action, stable target account IDs/versions and expiry. Authorize **before** consumption. Make consumption and mutation one transaction, with a conditional update and exactly-one-row check; cancellation needs the same actor/chat binding. For today's table, an initial minimum predicate is:

```sql
UPDATE admin_confirmations SET consumed = 1
WHERE code = ? AND actor = ? AND consumed = 0 AND expires_at > ?;
```

Then require `rowcount == 1`; the complete design also needs the proposed chat/target-generation columns and transactional mutation/audit. Expiry comparison should consistently reject at the deadline. Disable/remove old inline buttons after a completed/cancelled action as a UI aid, not as the replay control.

`/delexpired` currently previews at most 1,000 expired accounts but stores an empty payload, then deletes all expired accounts at execution time. Freeze the approved account IDs/versions or a clearly specified cutoff and recheck they remain eligible. A user extended after preview must be spared. An account newly expired after preview must not be silently added to an explicitly previewed deletion set.

### 6.3 Consistent `/backup` and acknowledgment

Current `/backup` passes `store.DB_PATH` directly to `send_document()`. The function reads the main file in full and buffers duplicate multipart bytes. In the WAL test, the live database had two committed rows; the uploaded main file restored with only one, even though `quick_check` returned `ok`. Integrity alone does not prove inclusion of committed WAL data. The reproduction is conditional on WAL, not a claim that live production already uses it.

Required sequence:

1. Create a private, uniquely named snapshot file with restrictive permissions. Use SQLite's online backup API on separate source/destination connections with bounded progress/deadline handling; close both before upload. Do not copy the live main file or independently copy DB/WAL/SHM at unrelated instants.
2. Validate the closed snapshot with integrity and foreign-key checks plus expected schema/account invariants. Record its size, SHA-256, schema version and snapshot time. The isolated online-backup control captured the latest committed WAL row correctly.
3. Encrypt the backup as required by the data threat model, using an independently retained recovery key. The DB contains password verifiers and session secrets. A hash-only backup cannot reconstruct plaintext passwords; do not promise otherwise.
4. Upload the immutable artifact through a bounded streaming multipart implementation. Check file size and timeout before starting; avoid blocking all admin handling on a large upload.
5. Parse the Telegram result, require `ok: true`, and retain message/document acknowledgment metadata. Current code ignores JSON and reported success for a mocked HTTP 200 `{ok:false}`. Clean up/retain the snapshot according to an acknowledged-delivery policy, and use a durable pending-job identifier for retries.
6. Test restoration separately in isolation. A delivered DB is not a complete signing-service recovery plan; authority/configuration custody needs its own controlled design. Do not automatically add private keys to this database-only command.

The backup API supports a consistent online copy with short locking steps, not a zero-lock guarantee. Python exposes it as `Connection.backup`; `VACUUM INTO` is an alternative. Use bounded backup steps and avoid long-running read transactions. [SQLite online backup](https://www.sqlite.org/backup.html), [Python backup API](https://docs.python.org/3.14/library/sqlite3.html#sqlite3.Connection.backup).

Telegram documents multipart `sendDocument`, currently up to 50 MB, and returns the sent message on success. Treat transport/API acknowledgment, snapshot consistency and restore success as distinct evidence. [Telegram sendDocument](https://core.telegram.org/bots/api#senddocument).

### 6.4 Delivery idempotency

The polling loop stores the next update offset in `finally`, even after handling fails. A committed mutation can lose its response; process death before offset persistence can also replay `/extend` or another mutation. Add durable unique Telegram update/command IDs, record the mutation result transactionally, and deliver through a retryable outbox. A repeated update must return the existing result without extending twice. Avoid storing plaintext customer credentials in ordinary outbox/audit state; choose a tightly scoped encrypted/ephemeral credential-delivery policy or reset-on-loss workflow.

## 7. Customer messages, keyboard and service isolation

The requested 12-label persistent two-column keyboard is implemented. The quick-command handlers also exist; command-menu registration omits some handlers such as delete/expired/bulk delete. Register the intended menu consistently, while keeping authorization inside every backend path.

Invoices wrap credentials in backticks, but `send_message()` supplies neither parse mode nor entities, so the tested payload contains **literal backticks**. Prefer escaped HTML for credential messages, for example:

```python
from html import escape
text = (
    "🌟 THÔNG TIN KÍCH HOẠT VCNEXT VIP 🌟\n"
    f"👤 Tài khoản: <code>{escape(username)}</code>\n"
    f"🔑 Mật khẩu: <code>{escape(password)}</code>\n"
)
# Supply parse_mode="HTML" only for messages built with escaped dynamic values.
```

Do not globally enable Markdown on existing unescaped messages: accepted passwords can contain backticks/backslashes. Ordinary monospace text does not guarantee a universal one-tap clipboard action; the API offers explicit `copy_text` buttons for that purpose. Validate mobile presentation separately. [Telegram formatting](https://core.telegram.org/bots/api#formatting-options), [CopyTextButton](https://core.telegram.org/bots/api#copytextbutton).

The invoice layout is otherwise understandable. Clearly state whether the term begins at account creation or first login: current `create_user()` starts the duration **at creation**. Source-message deletion is best effort and cannot retract copied credentials or notifications. Keep invoice delivery owner-only and avoid presenting plaintext passwords in `/find`. Replace silent `text[:3900]` truncation with pagination/chunking so account/device/expired lists are not silently incomplete.

`/status` currently reports database counts/time, not host memory, load or actual service health. Session expiry is account-linked and does not mean an iOS daemon is presently healthy. Add bounded, fixed-argument local health checks for the two approved units, host memory/load and recent authenticated activity, with honest unknown/degraded states. No arbitrary user-supplied unit name, command or remote host should reach a subprocess. VPS metrics alone cannot certify `mediaserverd` or camera streaming on a phone.

Both supplied units run as root. For deployment hardening, use dedicated HTTP/bot service principals with only required state access; the bot should not need the RSA signing key. Put writable state in a dedicated directory under the approved installation boundary, keep code immutable to the bot, and use restrictive umask/group permissions. Use supported systemd credential loading or a protected secret file instead of a literal token in a distributed unit. Confirm installed systemd support before selecting directives. [systemd credential facilities](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredential=ID:PATH).

These are review specifications only. No service, credential, owner setting, package or remote process was altered.

## 8. Acceptance gates and formal verdict

| Area | Current verdict | Required evidence before approval |
| --- | --- | --- |
| Username/password + PBKDF2 model | **Conditionally suitable** | Versioned stronger work factor/policy, no admin bypass, bounded anti-enumeration/rate handling |
| Multi-device licensing | **Not approved** | One-slot concurrent enrollment has one winner; account/key/epoch checks; authenticated migration and session-generation tests |
| Shared SQLite | **Not approved as a zero-lock design** | Patched linked SQLite, verified WAL configuration, short atomic writes, controlled busy handling, measured contention behavior |
| Telegram owner/private gates | **Default gates pass; strict deployment unverified** | Exact singleton owner, private-only enforced, expected bot identity, all denial paths audited, no exposed embedded tokens |
| Destructive commands | **Not approved** | Actor-bound atomic one-time confirmation, frozen targets, idempotent updates, complete cleanup |
| Backup | **Not approved** | Consistent snapshot under concurrent writes, bounded upload, verified acknowledgment, isolated restore |
| Invoice/keyboard/status | **Partially implemented** | Escaped formatting/copy UI, pagination, truthful host/service telemetry |

Before release, rerun the adversarial cases with **opposite expected outcomes for the reproduced defects**, alongside the passing normal username/password, two-device, signed lease and expiry-clipping controls. Add account disable/delete/expiry races, challenge replay, old-token replay, key substitution, password-policy migration, interrupted backup/upload and duplicate-update tests. Confirm schema migration against a disposable copy of the actual prior schema before touching production.

Only after code-level fixes pass should an authorized deployment validation inspect the intended VPS's active units, resolved DB path, linked SQLite, owner/private configuration and expected bot identity, followed by controlled owner-chat and physical iOS interoperability tests. Static source plus loopback fixtures do not prove production state, Telegram mobile rendering or A11/arm64e runtime stability.

**Formal verdict: withhold commercial implementation sign-off.** The requested architecture can support the native app, but the current code has confirmed authentication, transaction, revocation and backup defects. The fixes above are concrete release prerequisites; this audit does not authorize or perform a production rollout.
