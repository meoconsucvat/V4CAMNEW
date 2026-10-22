# VCNext build 37 — final package, licensing and A11–A16 sign-off audit

Audit date: **2026-10-21, Asia/Saigon**.

**Release verdict: commercial sign-off is withheld.** The rebuilt package preserves the previously audited binaries, and the installer model helper passes the selected shell checks. The current commercial server still permits unauthorized administrator enrollment and unauthenticated renewal, and has reproducible replay, migration and revocation races. Those are release blockers independent of camera/PAC compatibility.

| Area | Formal assessment |
| --- | --- |
| Published package identity | **Verified:** the live download and both local package copies match, 496,292 bytes |
| Binary preservation | **Pass:** 10 unchanged executable files, 14 original text sections, 21 CodeDirectories with zero code-page mismatches |
| Installer source/synchronization | **Pass within tested scope:** four requested preinst/postinst copies match; POSIX-style syntax and mocked model probes pass |
| Completely canonical package metadata | **Not a clean pass:** noncanonical ar modes, inherited ownership metadata and removal-path caveats remain |
| RootHide installer execution, launchd and A12+ camera operation | **Not physically verified in this audit** |
| RSA response shape and token bindings | **Pass in isolated ASCII fixtures:** RSA-3072/PKCS#1 v1.5/SHA-256, five capabilities and 90-second leases |
| Commercial authentication, hardware-lock and one-time challenge claims | **Fail:** confirmed local adversarial counterexamples below |
| Unbinding/migration semantics | **Fail:** stale state, extra issuance and unintended full-term reset |

No production server, database, private key, package source or product binary was changed. The only public endpoint request was a read-only package download; no licensing request or activation was sent to production. Local HTTP tests used a disposable database, freshly generated RSA key and a loopback server. Existing A11 success and live heartbeat traffic remain user-reported; the deployed server source/service configuration was not retrieved over SSH.

## 1. Evidence identity and test scope

| Artifact | SHA-256 |
| --- | --- |
| `VCNext-custom-roothide.deb` | `2a910b69a6b950281fd637513fc12e482a9fafa5267221152e7bdae81b72e21f` |
| Current `server/server.py` | `855d603463f9c00b44c04f9b3ba7450966220fa0b7614c88057ce14e63f5d565` |
| Current `server/admin_cli.py` | `ef7a6b90893ed530dd8e77b5325ae227235a42bb1264c3280a0b0c6a7f7bb2d7` |
| Current preinst | `fec197e04aa7b101958229de9cfb3b074173cafffb3514b44bcd1fab496a2a2e` |
| Current postinst | `5d4ebbb5f7fd90f51c913ba217a6066ef66bc83f94e7d5c3a33fdd55427a1ad9` |

At **2026-10-21 02:11:34 UTC / 09:11:34 Asia/Saigon**, `GET https://vc.huxa.xyz/VCNext-custom-roothide.deb` returned HTTP 200 and byte-identical content. Python's normal CA/hostname validation succeeded. This verifies that download at that time; it is not an iOS TLS-pin test or proof of the deployed Python source. [Download verification](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/live_download/verification.json).

Reproducible audit artifacts:

- [Package/installer results](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/package.json) and [findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/package_findings.md), produced by [audit_final_package.py](/C:/Users/Admin/Desktop/vcnextnew/scripts/audit_final_package.py).
- [Isolated HTTP/server results](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/server_tests.json) and [findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/server_test_findings.md), produced by [audit_commercial_server_isolated.py](/C:/Users/Admin/Desktop/vcnextnew/scripts/audit_commercial_server_isolated.py).
- [Admin command results](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/admin_tests.json), produced by [audit_final_admin_cli.py](/C:/Users/Admin/Desktop/vcnextnew/scripts/audit_final_admin_cli.py).
- [arm64e findings and full device checklist](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/arm64e_findings.md), tied to the [previous disassembly report](/C:/Users/Admin/Desktop/vcnextnew/docs/CODEX_ARM64E_A12_A16_AUDIT.md).

The HTTP harness executes byte-identical server source from a temporary directory, with `__file__` resolving all ordinary key/database paths there and `__name__` preventing normal startup. It uses real SQLite and real RSA signing. Controlled pauses after completed row fetches force permitted concurrency interleavings without replacing SQL or authorization decisions. Tests ran on Windows, Python **3.14.5**, SQLite **3.50.4**; they establish existence of these local behaviors, not their production frequency. The admin harness executes the actual selected functions against synthetic tables. Both final harnesses exited zero; security failures are recorded as observed counterexamples, not mislabelled as security passes. No local HTTP listener remains open.

## 2. Maintainer scripts and package

### 2.1 Model helper: syntax and actual execution boundary

`get_hardware_model()` is synchronized in all four requested script copies and the archives. The copies are LF-only; preinst/postinst control members are executable 0755 with `#!/bin/sh`. Bash POSIX syntax checks pass. Six isolated model-probe cases pass, including `iPhone12,1`, `iPhone14,2`, an iPad identifier, denied/missing sysctl fallback, and a non-product fallback. No dash or actual iOS `/bin/sh` execution was performed.

The function uses POSIX command substitution, quoted `printf`, `case` and `return`. Because it runs as `machine="$(get_hardware_model)"`, its `model` assignment does not leak into the parent shell. The `|| true` on the native query also avoids a preinst `set -e` termination. No syntax/subshell defect was found. Source: [preinst:8](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/preinst:8), [postinst:28](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/postinst:28).

The query names the correct physical-iOS product OID. Apple libc uses `CTL_HW/HW_MACHINE`, and physical iOS XNU obtains the machine product name; `uname -m` can also return `iPhone12,*`. [Apple libc](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/gen/uname.c#L81-L84), [XNU product field](https://github.com/apple-oss-distributions/xnu/blob/xnu-8796.121.2/bsd/kern/kern_mib.c#L521-L560).

**Actual absence of a RootHide postinst sandbox/namespace denial is unverified.** The native executable must be visible and permitted in that exact context. Errors are suppressed; if both probes produce an empty/generic architecture value, the A13 case will not match. A successful command in an ordinary SSH shell is useful but does not prove the maintainer-script context. Retain native sysctl stderr and status during a dedicated installation test.

The historical policy is preserved: only `iPhone12,*` gets a mediaserverd-only filter. Other devices retain the shipped cameracaptured + mediaserverd filter. This is not a new PAC fix and does not justify applying that filter to every arm64e device.

### 2.2 Cleanup and permissions

| Operation | Current source behavior |
| --- | --- |
| Shared directories | Creates Media/Streams; recursively assigns mobile:mobile |
| Shared permissions | `chmod -R u+rwX,go-rwx`: normally owner-only **0600 files / 0700 directories**, not blanket 0644; existing execute bits can survive |
| Stale runtime state | Removes CameraConfig.plist, CameraStatus.plist and CapabilityLease.plist on each postinst invocation |
| Stored session | Removes AuthSession only when the old-version argument is absent; upgrades preserve it for migration |
| A13 canary state | Preinst clears the package flag and runtime canary for iPhone12,* |
| A13 rewritten filter | root:wheel, 0644 |
| Main launchd plists | Attempts root:wheel, 0644 |
| Main daemon executables | Attempts root:wheel, 0755 |
| Service restart | Unload/load operations plus an intentional mediaserverd restart; errors are suppressed and postinst exits zero |

Sources: [postinst:10](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/postinst:10), [postinst:15](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/postinst:15), [postinst:59](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/postinst:59), [postinst:65](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/postinst:65), [postinst:74](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/postinst:74).

Missing state immediately after installation is intentional disarming until the app writes settings and a fresh lease is published. It should not be diagnosed automatically as a loader failure. Validate the actual UID/sandbox of every host needing shared state before changing permissions; making AuthSession broadly readable would expose its tokens/device-key material.

Successful ownership correction matters: the archived main launchd plists initially have numeric **uid 501 / gid 20**, mode 0644. The script suppresses chown and launchctl failures, so its zero exit does not prove root ownership or successful job admission. This is a target validation item and a reason to normalize ownership at packaging time.

### 2.3 Archive validity and remaining defects

Verified: correct ar member order/bounds/padding; `debian-binary = 2.0\n`; both zstd frames decompress; all raw tar checksums and end markers pass; no duplicate/unsafe paths or unexpected special members. Exactly **five genuine type-2 `.roothidepatch` symlinks** target `/usr/lib/DynamicPatches/AutoPatches.dylib`; `.symlink` text files were not substituted. The main/mirror executable policy matches the prior package. All ten executable members have 0755 permissions.

However, all three ar mode fields contain literal **`0o100644`**, rather than canonical octal digits. The builder uses `oct(mode)` at [build_custom_deb.py:39](/C:/Users/Admin/Desktop/vcnextnew/scripts/build_custom_deb.py:39). Exact corrective specification for the next build:

```diff
-    md = oct(mode).ljust(8)[:8]
+    md = format(mode, "o").ljust(8)[:8]
```

This is a format/portability defect, **not a demonstrated dpkg rejection**. The reviewed upstream extractor ignores ar mode while validating member terminators/names/sizes; its writer emits ordinary octal. Windows libarchive can list the package but interprets these enclosing member modes as zero. Installed permissions come from the tar payload. No actual dpkg binary was available locally. [Pinned dpkg ar reader/writer](https://github.com/guillemj/dpkg/blob/7492eb3d9b1e4f325bd4845614eaf126240ba8c7/lib/dpkg/ar.c), [extractor](https://github.com/guillemj/dpkg/blob/7492eb3d9b1e4f325bd4845614eaf126240ba8c7/src/deb/extract.c).

Additional packaging items before a clean release:

- Normalize archive user/group names and numeric IDs. Mirror files retain a build-host name `runner`; main binaries use root/staff metadata. Target name resolution can affect the final owner, so numerical metadata alone is not universal installation proof. [dpkg owner normalization](https://github.com/guillemj/dpkg/blob/7492eb3d9b1e4f325bd4845614eaf126240ba8c7/lib/dpkg/tarfn.c).
- Run target `dpkg-deb --info` and `--contents`, plus fresh install/upgrade/removal tests. Upstream zstd support starts at dpkg 1.21.18; forks can backport it. Record the installed parser version. [Official deb(5)](https://manpages.debian.org/unstable/dpkg-dev/deb.5.en.html).
- Main/mirror **prerm** paths differ (`/Library/LaunchDaemons` versus `/var/jb/Library/LaunchDaemons`). This may reflect inherited RootHide execution contexts; validate removal rather than blindly making them equal.
- Replace the A13 filter atomically in future hardening; current `cat >` truncates the file in place. Record required chown/load errors instead of treating every failure as success. Review postinst action arguments before adding lifecycle guards.
- Refresh `Installed-Size` using the normal packaging tool; 1528 under-represents the full main+mirror payload.

**Formal package sign-off:** binary preservation, script synchronization and the enumerated structural checks pass. A completely canonical metadata/ownership claim and actual RootHide installation/runtime sign-off are not established. Correct the packaging issues before calling this a clean commercial release artifact.

## 3. Commercial licensing security assessment

### 3.1 Release-blocking authentication defects

| Priority | Finding | Concrete evidence |
| --- | --- | --- |
| **P0** | `admin` bypasses binding, status and ordinary expiry policy | Arbitrary new fixture device obtained challenge and login HTTP 200 with a valid signed lease. Challenge bypass [server.py:228](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:228); login bypass [server.py:322](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:322) |
| **P1** | Login does not verify device proof, challenge nonce or password | Valid challenge with all three omitted still returned HTTP 200. Login branch [server.py:298](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:298) |
| **P1** | Heartbeat/renew authenticate only an asserted device ID | Missing Authorization/nonce/proof, or wrong Bearer/replayed invalid proof, returned HTTP 200. [server.py:414](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:414) |
| **P1** | Concurrent one-time challenge consumption fails | Two requests caching the same challenge before deletion both returned HTTP 200 with different tokens and valid signed leases. Delete rowcount ignored at [server.py:319](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:319) |
| **P1** | Unbind can race with issuance and resets plan duration | In-flight heartbeat returned a valid lease after its session was deleted; migrating a key with two days remaining granted a new 30-day term |
| **P2** | Logout is unauthenticated | Device ID alone deleted the session, HTTP 200. [server.py:495](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:495) |

The seeded administrator row does **not** enforce the promised author's-device restriction. The special login branch sets a fresh ten-year deadline on each admin login, and admin heartbeat skips ordinary license status/expiry validation at [server.py:433](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:433). An existing admin session still renewed after its license row was marked revoked/expired in the fixture. Actual CLI revocation removes sessions, but the unrestricted admin login can create another. Preserve developer access through an authenticated, explicitly bound license; do not preserve it through a public special-case bypass.

`supported_client_artifact()` now correctly rejects selected wrong build/digest/types. It is **not authentication**: the build and digest are public constants that a request can assert. `X-Device-ID` overrides body `device_id` at [server.py:207](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:207); a mismatched header/body still renewed the existing header-selected session in the fixture. The current comparison is an identifier lock, not proof of immutable physical hardware. A second physical client claiming the same ID is not distinguished by this code.

The challenge table stores a thumbprint but not the validated device public key/full signed challenge material. Real device-proof verification needs that public key and the exact challenge bytes/dictionary the app signed. Hashing an arbitrary public-key blob and issuing an RSA-signed response does not prove possession of its private key. The app's P-256 ECDSA proof and the authority's RSA signature are different operations.

A separate password can intentionally be unused in a license-key-as-credential design. That does not excuse missing challenge proof/nonce validation or a publicly named administrator bypass. Apply endpoint-specific rules: the existing login signs its challenge; heartbeat/renew sign a session proof; the existing logout sends its saved bearer token and does not establish an additional device-proof field in the audited wire contract. Requiring a new logout field without updating the client would introduce a regression.

### 3.2 First activation: one successful property, one separate race

**Two different asserted device IDs did not both win first activation in the forced-overlap test.** Both challenge rows were fetched before either login continued; results were **[200, 403 DEVICE_MISMATCH]**, one license binding and one session. The current DELETE starts a write transaction before the license read/update, and SQLite serializes writers. The activation and session write commit together. Reporting a double-device activation solely because there is no explicit `BEGIN IMMEDIATE` would be incorrect. [SQLite transactions](https://www.sqlite.org/lang_transaction.html), [Python transaction control](https://docs.python.org/3.14/library/sqlite3.html#transaction-control-via-the-isolation-level-attribute).

That does not make challenge consumption atomic. The challenge SELECT occurs **before** the write lock. Two requests can cache the same row; the second DELETE later affects zero rows, but issuance continues from its cached data. Sequential replay fails with CHALLENGE_INVALID; concurrent replay succeeds twice. This distinction is demonstrated, not hypothetical.

Corrective requirement: define a transaction encompassing challenge freshness/ownership, authenticated proof, one-time consumption and license/session transition; check the conditional consumption succeeds exactly once. Preserve the current one-winner binding property and add rollback/error handling. A writer timeout must return a controlled retry/error response. Changing sqlite autocommit/transaction defaults without retesting can change the observed behavior.

### 3.3 Renewal, revocation and concurrent clients

Both app and NetworkDaemon can rotate tokens. Currently the handler never compares the request token, nonce, proof or session expiry before issuing replacements. New tokens in a signed reply cannot compensate for missing request authentication.

Before issuance, verify the endpoint-appropriate access/renewal token, device proof, current nonce/request freshness, and active license **including binding to that same device/key**. Perform the state transition with a checked session version/nonce or equivalent compare-and-swap. Define behavior for a legitimate concurrent app/daemon request and a lost reply: authenticated idempotency or a tightly bounded documented grace policy must avoid token divergence and accidental logout. An unbounded acceptance of old nonces is not such a policy.

Deploying those checks also requires an authenticated migration/enrollment plan for existing sessions: their stored thumbprints alone cannot supply the missing P-256 public key. Do not silently trust a new caller's key for an already bound license or simply enable mandatory proof checks and assume old sessions will remain compatible. Establish the developer's trusted key/binding and customer reenrollment path before rollout.

In the forced unbind interleaving, heartbeat read its session, unbind cleared binding/deleted the row, then heartbeat's UPDATE affected zero rows. It still returned a valid signed 90-second lease. Recheck state under the issuance transaction and require a successful update; a revocation/session epoch can invalidate cached state. Already-issued leases cannot be erased by deleting a server row: ordinary clients can retain them until their local validity window ends. The CLI's description of immediate disconnection overstates that behavior.

### 3.4 Other expiry/validation defects

- Signed challenges expire after **90 seconds**, but their database rows expire after **120**. Login at +100 seconds succeeded in the fixture. Use one deadline and verify the exact challenge/proof, not a longer independent row lifetime. [server.py:277](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:277), [server.py:287](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:287).
- Lease expiration is always now+90, even when the license expires sooner. A renewal with one second remaining produced a lease valid **89 seconds beyond** the license deadline. Exactly at license expiry, `< now` still allowed renewal. Reject `now >= expires_at` and clip lease expiry to the authorized deadline; handle a remaining interval too short for useful delivery explicitly. [server.py:438](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:438), [server.py:465](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:465).
- JSON-object/build guards are improvements but do not validate all fields. For example, a numeric username reaches `.strip()`; missing device IDs still default to a shared constant, and invalid public-key material can fall back to a fixed thumbprint. These are source findings outside the selected malformed-request executions. Require typed bounded fields, identity/header parity, valid P-256 key material and controlled HTTP errors.
- Rate limits, body-size limits, challenge cleanup, thread/resource bounds, database backup/permissions and Nginx policy were not comprehensively load-tested or inspected on the VPS. Avoid storing/logging raw license secrets and tokens beyond the operational need. The current CLI-generated random suffix is 48 bits; issuance/rate-limit policy should account for the number of active keys rather than treating the app digest as a secret.

## 4. Clock rollback and signed response interoperability

### 4.1 What the clocks actually enforce

The non-admin server uses its own `int(time.time())` for license expiry; an old client `issued_at` did **not** bypass an expired license in the fixture (HTTP 403). A change to the iPhone clock alone does not rewrite the server deadline. Server clock rollback, backup restoration and unchecked administrator adjustments are separate operational risks; maintain server time synchronization and audited expiry changes.

On unchanged client state, the active readers require both:

```text
0 < expires_at - issued_at <= 95 seconds
0 <= NSProcessInfo.systemUptime - received_uptime < that duration
wallClockNow < expires_at
```

Camera arm64e has age rejection at `0x12db4/0x12dbc` and wall expiry at `0x12dc8/0x12dcc`; Overlay equivalents are `0xd0e0/0xd0e8` and `0xd0f4/0xd0f8`. Rolling wall time backward does not remove the **90 awake-second** age limit of an unchanged envelope. Rolling forward can fail early. Sleep/wake and wall-clock manipulation mean this must not be advertised as a strict independent 90-second real-time clock under an adversarial device owner.

In particular, `received_uptime` is unsigned outer-envelope metadata. A jailbroken client with file-write access can reset it and change wall time, or modify the verifier itself. The local two-clock gate is not a tamper-proof commercial anti-replay boundary against that owner. Even normally operating clients can briefly outlive a server license deadline because current leases are not clipped as described above. [Exact reader evidence](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/readers_findings.md).

### 4.2 Response contract: what passed

Every tested successful lease response contained typed token strings, a typed user dictionary, integer version 2, purpose `capability.lease`, issuer/audience, string build `37`, matching identities, all five string capabilities, correct SHA-256 access/renewal/nonce bindings, numeric timestamps and TTL 90. The wire field is **`lease_signature`**; local publication converts it to envelope **`signature`** and adds received uptime. Independent public-key verification accepted **384-byte RSA-3072 PKCS#1 v1.5 SHA-256 signatures**. Challenge signatures also verified.

This supports the reconstructed response shape and normal ASCII serialization path. It does not execute Apple's Foundation or prove arbitrary Unicode/escaping/number equivalence: the fixture generated a throwaway authority and used Python sorted compact JSON. No production-key/embedded-Tag3 match was remeasured in this audit. Preserve the previously verified ASCII build-37 contract and add real Foundation interoperability vectors before widening the accepted schema. Source signer: [server.py:108](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:108).

The actual NetworkDaemon timer is **30 seconds**, observed at `0x100004238`; 120-second successful refresh spacing would exceed a 90-second lease. Multiple missed cycles, a long sleep, TLS/key rotation failure or delayed publication can disable features. A nominal timer interval is not a delivery guarantee. Do not add an independent renewal writer to mask authentication or lifecycle defects without coordinating session/lease publication.

## 5. Unbind, transfer, extension and stale state

The actual `cmd_unbind()` clears bound_device_id/device_name and deletes a session only by the previously bound device ID. It does not remove every session for that license or any pending challenge, and it preserves activated_at/expires_at. [admin_cli.py:185](/C:/Users/Admin/Desktop/vcnextnew/server/admin_cli.py:185).

Six isolated admin-function cases confirmed:

| Case | Result |
| --- | --- |
| Normal old session on unbind | Removed; binding cleared |
| Extra/orphan session for the same license | Remained |
| Pending challenge for old device/license | Remained |
| Already-unbound license with a session | Session remained |
| Device had switched to another license | Unbinding the earlier license deleted the other license's session at the shared device ID |
| Revoke by license | Removed license sessions and marked revoked, but pending challenges remained |

The HTTP integration fixture confirmed a separate policy defect: after unbinding a 30-day key with **two days remaining**, the next login granted **30 days**, adding **28 days**. `if not bound_hwid or activated_at == 0` treats migration as new activation and overwrites the preserved expiry. A pending old-device challenge can also compete for rebinding after an unbind; a clean transfer needs an explicit policy deciding which new enrollment is authorized.

Required transfer behavior should be specified and implemented atomically:

1. Revoke all sessions/challenges associated with the normalized license identity, with correct license scoping; avoid deleting an unrelated session solely because it uses the former device ID.
2. Increment a license/enrollment generation and require it during issuance, closing in-flight stale-session and old-challenge use.
3. Clear the device/key binding while **preserving the paid deadline**. Grant a fresh duration only for a never-activated key (`activated_at == 0`), unless an explicit separately authorized reissue resets the term.
4. Require a fresh authenticated enrollment/proof on the new device; keep revoked/expired licenses revoked/expired. Document the remaining validity of already issued offline leases.

`cmd_extend()` also needs policy tests: extending an unactivated key changes expires_at but leaves duration_days unchanged, so first activation overwrites the extension; negative extension values are accepted. Those behaviors were reproduced. Reject unintended negative values and decide whether an unactivated extension changes its duration or creates a fixed deadline. [admin_cli.py:203](/C:/Users/Admin/Desktop/vcnextnew/server/admin_cli.py:203).

## 6. A12–A16 / PAC final assessment

All ten executable hashes match the prior deep arm64e audit. There is **no newly introduced compiled arm64e regression from these installer/server changes**. This is not an exhaustive proof that no residual binary trap or runtime failure exists.

- Camera arm64e active reader `0x1287c` and lease master `0x11428`, and Overlay reader `0xcba8` / master `0xb754`, do not semantically compare lease `binary_digest`. The existing `d8e4...` compatibility member does not become a rejection merely because Camera arm64e text hashes to `60e7...`. The whole dictionary is still RSA-signed.
- Compiled PAC behavior and external Substrate hook calls remain as audited. Camera's saved originals are authenticated at `0x6840` and `0x803c`; the installed hook provider and AutoPatches-generated paths must still satisfy the runtime ABI.
- A13 mediaserverd retains its fresh CameraConfig timestamp gate: `0x5938: 24110054 B.MI 0x5b5c`. A host restart can leave a valid lease but inactive replacement until the app publishes fresh settings/canary state. The historical cameracaptured crash cause remains unproven.
- Missing/incompatible private render/output selectors can cause hooks to be skipped. A mapped dylib, a running daemon and a valid lease are three different observations; none alone proves replacement frames.

Even on an eligible A12–A16/iOS 15–16.5 pair, loading can fail because system injection is inactive/excluded, the jailbreak is in safe mode, dependencies/rpaths or marker targets are missing, trust/entitlements reject mapping, a backend/ABI is wrong, or path/sandbox access fails. A successful load can still yield no function because of config, lease, private-method or process gates. Other tweaks, memory pressure and frame lifetime/format behavior need target evidence. Clean CodeDirectories do not establish every AMFI or PAC requirement.

Thin arm64 App/NetworkDaemon/StreamDaemon execute natively on arm64e hardware; Apple XNU accepts ARM64_ALL on an arm64e host. That is different from injecting an arm64-only library into an arm64e Apple process. [XNU binary grading](https://github.com/apple-oss-distributions/xnu/blob/xnu-8796.121.2/bsd/dev/arm/kern_machdep.c#L84-L104).

Dopamine **2.x**, Bootstrap and Relaxin remain separate platform cases. The pinned Dopamine manifest includes stable ranges and device/build exclusions; firmware must also exist for the actual device. Bootstrap app injection alone does not prove the complete system-host camera/launchd pipeline. Relaxin requires its own exact-target/runtime validation. iPhone 15 models are not iOS 15/16 Dopamine 2 targets. Refer to the [pinned support matrix](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/platforms.md) and [Dopamine 2 manifest](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/Application/Dopamine/Exploits/dmaFail/Info.plist).

## 7. Exact physical A12+ diagnostic checklist

These are **future on-device collection instructions**, not commands executed during this audit. Use a dedicated test license/device after authentication fixes. Collect the initial failure state before rebooting, reinstalling or restarting a host. Preserve stderr and exit status; do not hide failures with `|| true`.

### A. Identify the real device, firmware and runtime

```sh
id
date -u '+%Y-%m-%dT%H:%M:%SZ'
uname -m
/usr/sbin/sysctl -n hw.machine
/usr/sbin/sysctl -n kern.osproductversion
/usr/sbin/sysctl -n kern.osversion
/usr/sbin/sysctl -n hw.cputype
/usr/sbin/sysctl -n hw.cpusubtype
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' com.vcnext.app rootless-compat mobilesubstrate
```

Record actual installed hook-provider and PatchLoader/AutoPatches versions too; a compatibility package's API name does not identify its implementation. Repeat the native sysctl probe with errors visible in the actual maintainer-script context during a test installation.

### B. Check installed files, ownership and filters

Use the RootHide bootstrap/root terminal. `/var/jb` below is its legacy compatibility namespace. If absent there, substitute the current expanded root obtained from that installed environment; do not guess a previous randomized directory or create links to hide an error.

```sh
VCNROOT=/var/jb
VCNSTATE="$VCNROOT/var/mobile/Library/VCNext"
VCNDYLIBS="$VCNROOT/Library/MobileSubstrate/DynamicLibraries"
dpkg -L com.vcnext.app
ls -ldn "$VCNSTATE" "$VCNSTATE/Media" "$VCNSTATE/Streams"
ls -ln "$VCNROOT/Library/LaunchDaemons/com.vcnext.networkd.plist" "$VCNROOT/Library/LaunchDaemons/com.vcnext.streamd.plist"
ls -ln "$VCNROOT/usr/libexec/VCNNetworkDaemon" "$VCNROOT/usr/libexec/VCNStreamDaemon"
cat "$VCNDYLIBS/VCNextCamera.plist"
readlink "$VCNDYLIBS/VCNextCamera.dylib.roothidepatch"
readlink "$VCNDYLIBS/VCNextOverlay.dylib.roothidepatch"
ls -ln "$VCNROOT/usr/lib/DynamicPatches/AutoPatches.dylib"
```

Validate all five markers, including app/daemons. On iPhone 11/A13, expect mediaserverd-only after install; on iPhone 13 Pro/A15, expect the unchanged dual filter unless a separately justified policy was installed. Check ordinary files are not group/other writable and launchd plists ended root-owned.

### C. Establish jobs and injection independently

```sh
launchctl print system/com.vcnext.networkd
launchctl print system/com.vcnext.streamd
launchctl list | grep -E 'com\.vcnext\.(networkd|streamd)'
ps -A -o pid,ppid,user,comm | grep -E 'VCNNetworkDaemon|VCNStreamDaemon|mediaserverd|cameracaptured|SpringBoard'
```

If that launchd domain is not the installed environment's domain, resolve the correct one before concluding a job is absent. Record exit/restart status and actual host UIDs. Establish loaded Camera/Overlay/AutoPatches/provider paths, UUIDs and selected architecture through existing authorized mapping/instrumentation or crash Binary Images. `ps` alone does not prove injection. Optional existing `vmmap`/`log` collection and full commands are in the [detailed protocol](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/final_sign_off/arm64e_findings.md); missing/denied diagnostic tools are observability limits.

### D. Inspect safe state metadata and crash evidence

```sh
ls -ln "$VCNSTATE/CameraConfig.plist" "$VCNSTATE/CameraStatus.plist" "$VCNSTATE/CapabilityLease.plist" "$VCNSTATE/A13CameraCanary"
plutil -lint "$VCNSTATE/CameraConfig.plist"
plutil -lint "$VCNSTATE/CameraStatus.plist"
plutil -lint "$VCNSTATE/CapabilityLease.plist"
```

After intentional postinst cleanup, open the app and apply normal settings, then inspect timestamps again. For A13, compare fresh config time with host startup. Check non-secret lease types/capabilities/expiry and renewal observations privately. Do **not** dump AuthSession.plist: it includes credentials/device-key data. Plist syntax is not RSA verification, and epoch-minus-boot-time is not an exact measurement of the reader's awake clock.

Retain relevant mediaserverd, cameracaptured, SpringBoard, VCN daemon, JetsamEvent and panic-full reports from actual rootfs CrashReporter/Analytics locations. RootHide CLI may expose them through `/rootfs/...`. Record timestamp, exception subtype, faulting thread, PC/LR, backtrace and Binary Images. A host PID change does not by itself prove a PAC failure or a kernel panic. Detailed collection paths are in the linked protocol.

### E. Execute the acceptance matrix and record results

For each exact model/OS build/jailbreak/backend combination, verify fresh install, upgrade and removal; login/restore/logout; several successful 30-second renewals across multiple 90-second windows; concurrent app/background traffic; network loss/recovery; sleep/wake and clock skew; host restart and A13 fresh configuration; front/rear preview, still/video and supported third-party camera consumers; media/stream replacement; floating controls/color sync; and memory-pressure/crash behavior. Compare with the user's working A11 baseline. Save frame/status evidence as well as process logs.

## 8. Required actions before commercial distribution

1. **Remove public admin bypass and authenticate every issuance/deletion operation.** Verify device P-256 proof, endpoint-appropriate token, nonce/request freshness and current bound license. Retain legitimate developer access through the same enforceable policy.
2. **Fix transactional challenge/session transitions and migration.** One-time consumption must have one winner; unbind/revoke must prevent stale issuance and clear relevant state; migration must preserve the paid deadline; app/daemon token races must recover predictably.
3. **Unify and enforce deadlines.** Align signed/database challenge expiry, reject at the exact license deadline and prevent leases outliving authorized expiry. Document offline/revocation latency.
4. **Normalize package metadata and validate on real dpkg/RootHide.** Correct ar formatting, owner/group metadata, disk-size metadata, ownership/load error handling, and removal behavior while retaining binary hashes and markers.
5. **Obtain named physical A12+ passes and actual deployment evidence.** Verify Foundation/TLS pin/authority interoperability, job admission and camera/overlay coverage. The public download hash alone does not prove the running server source or Nginx/service policy.

The archive and installer improvements are real, and normal identifier-level first activation has a demonstrated single-winner property. They do not close the commercial authentication and state-machine defects. This package/server pair should not receive an unrestricted commercial sign-off in its current form.

### Audit execution limitation

An initial failed disposable HTTP fixture may remain under the Windows temporary directory with only its generated test key/database; a failed admin fixture may similarly retain synthetic data. Successful final runs closed their listeners/connections and cleaned their fixtures. Automatic approval review rejected removal of the initial HTTP fixture with the stated reason **“blocked by policy”**; no alternate deletion was attempted. This cleanup limitation affected no production key, database or product file and is recorded in the server evidence.
