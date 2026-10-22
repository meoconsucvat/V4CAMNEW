# VCNext authentication/device-locking release

Prepared 2026-10-21 (Asia/Saigon) for **13.238.38.121**, installation directory **`/opt/vcnext_server/`**, virtual host **`vc.huxa.xyz`**, Telegram **`@VCAM_V5_ADMIN_BOT`**, sole owner **5137016124**.

This bundle contains executable Python source and service templates. It contains **no database, signing private key, TLS material, real bot token or Debian package**. Nothing has been deployed by the implementation tests.

## Files to install together

- `server.py`, `store.py`, `notify.py`, `telegram_bot.py`.
- `vcnext.service`, `vcnext-bot.service` service templates.
- `vcnext.env.example` configuration template. Provision the real file as `vcnext.env`; do not deploy the example placeholder as a credential.

Keep the existing `licenses.db`, RSA-3072 `server_private_key.pem`, existing certificates, Nginx configuration and Debian download intact. `admin_cli.py` from the older license-key engine is not included; manage the username/password accounts through the owner-only bot.

Python **3.10+** and `cryptography` are required. Tests used Python 3.14.5 and cryptography 48.0.0. Ensure the Python interpreter selected by each unit has the dependency installed. The supplied units preserve `/usr/bin/python3`; if the existing installation uses a virtual environment, retain that interpreter path in both installed units.

## Configuration needed for login alerts

Both services now require the same file:

```ini
EnvironmentFile=/opt/vcnext_server/vcnext.env
```

Provision that file with owner `root`, mode `0600`, and a **freshly rotated** credential for the intended bot:

```ini
TELEGRAM_BOT_TOKEN=YOUR_ROTATED_CREDENTIAL
TELEGRAM_OWNER_IDS=5137016124
```

The bot and notifier enforce the owner ID and expected bot username in code. Environment variables cannot silently authorize additional administrators or group chats. The notifier checks bot identity in its background worker; the admin bot checks before registering commands. A mismatched bot is rejected. No real credential is embedded in the Python or service files.

The HTTP service needs this environment too: configuring only the polling bot cannot enable HTTP login notifications. The owner must already have opened/started the intended bot's private chat; validate delivery through an authorized operator test after deployment. Never paste the credential into logs or shell history.

## Controlled installation sequence

1. Inspect the currently installed service definitions and record their interpreter, paths and permissions. Back up the four existing modules, both installed units and a **consistent SQLite online-backup snapshot**. Retain recovery material privately. A raw live main-file copy is unsafe with WAL.
2. Verify the Python-linked SQLite version and vendor fixes. WAL is enabled once at store initialization; connections use foreign keys and a 5,000 ms busy timeout. SQLite documents a WAL-reset fix in 3.51.3+, with backports 3.44.6/3.50.7. The Windows test runtime reported 3.50.4, which does not establish the VPS's patch status. [SQLite advisory, section 11](https://www.sqlite.org/wal.html).
3. Stop **only** `vcnext-bot.service` and `vcnext.service` during the coordinated source/schema update. Stage all four modules together and preserve the existing database and authority key. Do not run a copied store module against the live database merely to inspect it: importing it initializes/migrates its local database.
4. Install the protected environment file and updated units, preserving the selected interpreter. Reload systemd, start the HTTP service, then start the bot. Inspect only these units' logs. The HTTP listener remains loopback port 8000 behind the existing Nginx configuration.
5. Validate the owner private chat, `/users`, `/devices admin`, one controlled login and its alert. Test a rejected login and its alert. Perform `/clear` only on an approved test account, confirm it, then enroll the replacement phone. Check preserved expiry and the displayed device counts.
6. Check existing customer login and app/NetworkDaemon refresh on a physical device before broad distribution. No binary or Debian change is needed for this server update.

Schema migration adds challenge payload/public-key/epoch columns and unique session IDs without resetting existing users, passwords, expiry or device ownership. Old pending challenges lacking proof material are rejected and must be reacquired. Existing sessions without an enrolled public key require a fresh username/password + P-256 login. The native challenge supplies that key; it may complete an existing enrollment only if its stored key/thumbprint agrees.

An old database containing only the earlier license-key tables needs a separate, reviewed account-data migration; this release does not invent customer passwords or convert unrelated tables automatically.

## Ownership and migration policy

- Device A enrolled to User 1 cannot be transferred to User 2 by login. The response is HTTP 403 `device_bound_to_other_user`.
- A new device exceeding the account quota receives HTTP 403 `device_limit_reached`. The check is repeated under the enrollment write lock.
- Owner `/clear User1` deletes that user's devices, sessions and challenges and increases its authorization epoch. It preserves the password and exact account expiry. Confirmed old in-flight requests cannot recreate the cleared enrollment.
- A new valid login after clear is allowed; a former device still knowing the password can also attempt a new enrollment. The quota does not determine which phone the owner intends. Control the migration operationally or change the password when exclusive transfer is required.
- Existing incorrect bindings from the old overwrite bug are **not silently reassigned**. Inspect `/devices` for the affected accounts, then use an explicitly approved `/clear` to release the wrong binding. Clearing a user removes all of that user's enrolled devices, so plan customer re-enrollment.
- A newly initialized admin receives five slots and a 315,360,000-second grant. Its password comes from `VCNEXT_ADMIN_INITIAL_PASSWORD` if deliberately provided; otherwise it is random and undisclosed. Set it through owner `/setpass admin` before first app login. Existing admin hashes, term and slots are preserved on restart; no empty/default-password bypass exists.

The binding is to the asserted installation identifier **and validated device key**. It is not a claim of uncloneable hardware attestation on a jailbroken phone. The pre-seeded developer device key thumbprint must match its real native key; do not weaken proof checks to bypass a mismatch.

## Refresh and alert behavior

Login requires the password, mandatory matching challenge nonce and Base64 DER P-256 signature over the complete stored sorted-key challenge. Device enrollment, one-time challenge consumption and session creation commit together under `BEGIN IMMEDIATE`.

Heartbeat/renew require the correct endpoint's Bearer token and the native nine-field P-256 proof. Access token, renewal token and session nonce remain stable **within that session**, avoiding divergence between a suspended app and a continuing daemon. Each refresh has a signed request ID and timestamp, with at most 120 seconds of clock skew. Exact retries return the original cached response/lease; they cannot extend its timestamps. A changed request using the same ID is rejected. Cache retention of 241 seconds covers the complete acceptance window of a future-dated proof. A new login replaces the entire session generation/tokens/nonce; clear/password reset revoke it.

Leases retain the existing five capabilities, RSA-3072 PKCS#1 v1.5 SHA-256 signature, token/nonce bindings, and TTL clipped to `min(90, remaining_account_seconds)`. Already issued offline leases may remain valid for their existing TTL after an administrative clear; deleting server state cannot retract those bytes instantly.

Every completed `/login` success/failure invokes one background alert; a rejected `/challenge` also alerts because the app stops before login. Successful challenges and normal heartbeat/renew do not generate login spam. Messages use HTML escaping and explicit Vietnam time. Passwords, Bearers, nonces and proof signatures are excluded.

The notifier uses one bounded worker, queue capacity 256, up to three attempts and three-second network timeouts. Enqueueing does not wait for Telegram. Delivery is **best effort**, with sanitized error logs for missing configuration, queue overflow, identity mismatch or failed attempts. Its queue is not durable across process death, and Telegram/network availability cannot be guaranteed. If guaranteed recovery of every alert is a requirement, add a persistent outbox before treating these messages as an audit ledger. The database login audit is separate from Telegram delivery.

## Verification and rollback

The workspace contains isolated test suites:

```powershell
python -X utf8 scripts/test_store_auth_transactions.py
python -X utf8 scripts/test_auth_device_locking.py
python -X utf8 scripts/audit_login_notifications_isolated.py
```

They run copied source with temporary databases, generated RSA/P-256 keys, loopback HTTP and fake Telegram transport. They do not test the live VPS, Telegram receipt, Foundation serialization or a physical iPhone.

For rollback, stop these two services, restore the privately retained source/units and the matching pre-migration database snapshot, then restart in order. Restoring the old database discards changes made after that snapshot; plan the maintenance window and reconcile any intervening admin actions. Do not restore a stale snapshot over a running writer or combine an unrelated DB/WAL pair.
