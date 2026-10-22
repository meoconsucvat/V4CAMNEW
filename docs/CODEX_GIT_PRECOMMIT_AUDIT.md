# Git precommit secret-leak and repository-hygiene audit

Date: **2026-10-22, Asia/Saigon**. Intended remote: `https://github.com/meoconsucvat/V4CAMNEW.git`.

## 1. Formal verdict and scope

**PASS for the exact 88-file approved snapshot, using the new ignore policy and the completed checks below: zero unresolved credential/private-key/database findings in that selected set.** This is not a claim that the entire local workspace contains no secrets. It does contain operational credentials, private keys, a database and an old token-bearing backup; those files are explicitly excluded and remain on disk.

The workspace had **no Git repository and no `.gitignore`** at the start. No workspace Git initialization, staging, commit, remote configuration or push was performed. The audit created ignore/attribute rules, a local scanner, documentation and exact staging manifests. It performed no SSH, HTTP, Telegram, deployment, service restart or production database operation. A disposable bare Git metadata directory outside the workspace was used only to test Git's actual ignore behavior, then removed.

**Approval applies to the listed snapshot, not an unrestricted publication of every local file.** Any changed/new content, forced addition, existing remote history or deployment automation needs its corresponding check before publication. This audit does not prove the absence of arbitrarily obfuscated/encrypted secrets.

## 2. Approved staging set

The **complete enumerated list** is [GIT_STAGING_APPROVED.txt](/C:/Users/Admin/Desktop/vcnextnew/docs/GIT_STAGING_APPROVED.txt). The companion [GIT_STAGING_MANIFEST.json](/C:/Users/Admin/Desktop/vcnextnew/docs/GIT_STAGING_MANIFEST.json) records exact paths, file sizes and SHA-256 working-tree hashes. The JSON manifest deliberately excludes its own digest to avoid circular hashing. Treat it as an inventory, not a cryptographic signature.

| Area | Approved files | Scope |
| --- | ---: | --- |
| Root | 3 | `.gitignore`, `.gitattributes`, `README.md` |
| `server/` | 10 | Five Python sources, deployment guide, Nginx config, two systemd units, redacted env example |
| `scripts/` | 44 | First-party Python build/audit/test tools and two camera diagnostic shell scripts |
| `vcam/` | 2 | OBS/streaming README and feeder source |
| `docs/` | 28 | Top-level authored Markdown reports/specs plus the two staging manifests |
| `dist/` | 1 | Only the explicitly scanned `VCAMPLUS-roothide.deb` |
| **Total** | **88** | No keys, live environments, databases, backups or raw evidence |

All ten approved server paths are:

```text
server/DEPLOY_AUTH_REFACTOR.md
server/admin_cli.py
server/nginx.conf
server/notify.py
server/server.py
server/store.py
server/telegram_bot.py
server/vcnext-bot.service
server/vcnext.env.example
server/vcnext.service
```

Use the path-list file for the full source/docs enumeration; directory names alone are not approval to add arbitrary future contents. The ignore policy does not admit all of `docs/` or `dist/` recursively.

### Current distributable identity

The commercial file has changed since the earlier package audit. The **current** secret-scan-approved artifact is:

```text
dist/VCAMPLUS-roothide.deb
479244 bytes
SHA-256 6aa918aa16d93a39299740d9fd3a4bfe24072bc3d2ba90f7b72aa3568de4b4b9
```

The previous 479204-byte `ff13f266…` artifact is not the current file. This audit inspected the current package's nested members for secrets and runtime database/key carriers; it does not transfer an earlier functional/signing verdict to the changed artifact. Public authority certificates, embedded TLS pins, executable digests and endpoints are not private signing keys.

## 3. Findings and exclusions

| Local carrier | Finding / disposition |
| --- | --- |
| `NGUYEN VAN HIEU.pem` | SSH private key; ignored |
| `server/server_private_key.pem` | Signing private key; ignored |
| `mocks/test_server_private_key.pem` | Private key, regardless of fixture filename; entire mocks tree ignored |
| `server/vcnext.env` | Actual Telegram-token-shaped credential; ignored, never copied into this report |
| `server/licenses.db` | SQLite production-state carrier; raw bytes also contain a token-shaped value; ignored, no database rows were queried |
| `.codex-backups/auth-refactor-20261021/source-before.zip` | **Contains a Telegram token signature inside `server/telegram_bot.py`; ignored** |
| `dist/VCNext-server-auth-refactor.zip` | No recognized secret signatures in inspected members, but excluded as an unapproved release archive |
| `docs/evidence/` | Raw analysis databases/binaries, captures, fixture plists and exported evidence; excluded |
| `extracted/`, original/custom root `.deb` files, `server/*.deb` | Operational/native inputs and duplicate artifacts; excluded |
| `__pycache__`, bytecode, logs, temporary/backup/archive files | Excluded |

No sensitive values are reproduced. The backup finding demonstrates why `*.pem`/`*.env` alone is insufficient: a ZIP can contain an old credential-bearing source file whose outer filename does not resemble a secret.

The files have not been deleted or modified. Ignoring a credential does not revoke it or remove an earlier public copy. If this credential or backup has previously been published/shared outside its authorized custody, rotate the affected credential and address that publication separately; this workspace had no local Git history to clean.

### Tested ignore policy

[.gitignore](/C:/Users/Admin/Desktop/vcnextnew/.gitignore) denies unknown root contents, then admits intended source/templates/docs and the single reviewed package. Defense-in-depth rules cover private-key containers, OpenSSH key names, `.env`, `.env.*`, `*.env`, `*.env.*`, database/SQLite sidecars, backups, archives, Python caches and native analysis databases. Only the reviewed `server/vcnext.env.example` is re-included as an environment template.

**21 actual Git ignore probes passed**, including the real SSH/key/env/database paths, `.env.production`, `.env.local`, DB WAL/SHM files, backups, release ZIPs and raw evidence. The intended source files, template and commercial artifact remain eligible. Git's local/global ignore settings were not modified; the tests used an explicit empty global-excludes source for reproducibility.

[.gitattributes](/C:/Users/Admin/Desktop/vcnextnew/.gitattributes) prevents text conversion of `.deb` and declares LF for shell scripts/systemd/Nginx configuration. Manifest checksums describe working-tree bytes; Git may normalize text line endings according to its effective configuration/attributes. The post-staging gate therefore scans actual index bytes as well.

## 4. Secret and template verification

Independent text inspection covered **819 UTF-8 source/documentation/evidence files** and reviewed **26 generic credential-literal candidates**. Those candidates were runtime generation, labels, explicit isolated-test data or placeholders. No production password or bearer/session credential was identified in the approved text. Current source obtains the Telegram credential from environment configuration rather than a hardcoded token. The administrator seed uses an environment-provided password or a random value, not a literal production password.

The exact approved set was additionally checked against the actual credential found inside the excluded historical backup without printing or persisting that credential value. No matching bytes occurred in the approved files. Raw backup/database/environment/key content is not part of the staging manifests.

`server/vcnext.env.example` is appropriate for publication:

```text
TELEGRAM_BOT_TOKEN=REPLACE_WITH_ROTATED_TOKEN
```

Its optional initial admin password is commented and uses an out-of-band provisioning placeholder. The file explains replacement and private ownership/mode. Numeric owner IDs, host/domain names and device identifiers are configuration/operational metadata rather than authentication secrets; some remain in the historical reports/source. This is a secret audit, not anonymization of all infrastructure or personal identifiers.

The local gate [audit_git_precommit.py](/C:/Users/Admin/Desktop/vcnextnew/scripts/audit_git_precommit.py) checks prospective selected files and nested package members for:

- Telegram, AWS-access-key, GitHub and Slack credential patterns, URL credentials and AWS secret assignments.
- Private PEM headers/blocks, including encrypted legacy PEM metadata, OpenSSH private-key magic and parsed plain/encrypted DER private keys.
- SQLite database magic and forbidden key/env/database/session filenames inside archives.
- Bounded AR/Zstandard/TAR/ZIP/gzip/xz/bzip2 contents, with rejection of unsupported/corrupt carriers or exceeded limits.
- Suspicious path metadata, links/out-of-root files, and ignored files that were nevertheless tracked.

After a real repository exists, the same gate also scans index blobs and reachable historical blobs/commit/tag messages, and rejects sensitive/ignored historical paths. There was no index or reachable history in this workspace, so those counts are zero here; this report does not claim an existing history was successfully sanitized. Remote GitHub history was not accessed.

The gate passed **15 synthetic, in-memory self-tests**, covering ordinary/legacy encrypted PEM, plain/encrypted DER, nested ZIP and compressed TAR secrets, SQLite magic, token-bearing path metadata, unsupported archives and benign source. Two reusable-scanner gaps found during independent review were repaired before the final run. No synthetic credential/private key was saved to a publishable file.

Six local archive carriers were independently examined. All four Debian copies and the auth-refactor release ZIP completed bounded signature scans without recognized secrets; the historical backup ZIP produced the finding above. The approved commercial package was additionally parsed by the final gate, including its 5-member control tar and 59-member data tar. Compression did not hide uninspected approved members.

Evidence remains deliberately local/ignored under `docs/evidence/git_precommit/`: `staging_scan.json`, `scanner_selftests.json`, `archive_findings.json`, `text_findings.json` and `independent_approved_scan.json`. This prevents raw/evolving evidence from becoming an accidental publication channel.

## 5. Structure, reproducibility and production isolation

The repository keeps service source/templates in `server/`, automation in `scripts/`, OBS material in `vcam/`, authored specs/reports in `docs/`, and the one reviewed commercial package in `dist/`. The source tree deliberately omits the live environment, authority private key and production database.

This makes publication safer but **does not make a clean clone a self-contained native rebuild**. Several scripts depend on excluded original packages, the extracted tree, local fixture keys, raw evidence or an absolute Downloads logo path. Provision matching authorized inputs separately. Do not commit live keys/data to make an old script run. Python/runtime requirements also differ: this gate uses Python 3.14 Zstandard support and `cryptography`; other optional tools use Pillow, Capstone and LIEF.

The selected files do not configure Git-triggered deployment, and no GitHub deployment workflow is included. Git can execute custom client hooks or filters: verify those before treating later Git operations as isolated. The local configuration-presence check found no `core.hooksPath`, `init.templateDir` or `core.attributesFile` override; no workspace Git metadata existed. This audit made **zero production/network calls**, so it did not change or newly inspect the live VPS. Earlier VPS hash observations remain earlier dated evidence, not a fresh result of this task.

Before pushing, verify the target repository's existing Actions/webhooks/integrations if they could deploy production; those remote settings/history were outside this local audit. No unconditional assertion about an uninspected remote hook is made. Do not run a build/deploy/upload script as part of the Git sequence.

## 6. Authorized next-step sequence

**Local precommit hygiene sign-off: APPROVED for the exact manifest snapshot.** The following commands are a reviewable sequence for the owner or a separately authorized publication step; they were **not executed** during this audit:

```powershell
git init -b main
git remote add origin https://github.com/meoconsucvat/V4CAMNEW.git
python -X utf8 scripts/audit_git_precommit.py
git add --pathspec-from-file=docs/GIT_STAGING_APPROVED.txt
python -X utf8 scripts/audit_git_precommit.py
git diff --cached --name-status
git diff --cached --stat
git commit -m "Add audited VCAMPLUS source and package"
git push -u origin main
```

Proceed only if the gate exits 0, staged paths match the reviewed list and no new/changed credential-bearing content is present. Do not use `git add -f`, indiscriminate archive exceptions, a credential-bearing remote URL or force-push. If origin already contains history, inspect/reconcile that history instead of treating this sequence as an overwrite instruction. Remote access, existing branch state and deployment settings were not certified here.

The publishable-set result is **zero detected unresolved secrets/private keys/production databases under the stated checks**. Operational secrets still exist locally in ignored paths. Future edits require a new scan, and GitHub push success is not claimed until an actual authorized push completes.
