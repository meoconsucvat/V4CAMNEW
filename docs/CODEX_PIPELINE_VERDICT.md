# VCNext build 37: production pipeline architecture verdict

Audit date: 2026-10-19, Asia/Saigon. Intended target: iPhone 8 Plus/A11, the exact installed iOS 15/16 and Dopamine 2 RootHide builds still to be recorded.

**Verdict: the design is feasible, but it is not complete or established as production-ready. Do not treat the five stages as a 100% sound deployment recipe yet.** The equal-length hostname fixes the previous allocation problem, and separating TLS authentication from the response-signing authority is correct for the audited app. The remaining concrete blockers are the incomplete heartbeat contract, unverified NetworkDaemon behavior, incompatible existing patcher inputs, incomplete signing/trust procedure, and installer/runtime validation gaps.

The request refers to six stages but enumerates five. The missing sixth activity is final artifact and device acceptance; without it, neither a working web server nor a well-formed archive establishes end-to-end operation.

No project scripts, cryptographic generators, binary-analysis processes, packaging tools, certificate clients, or maintainer scripts were executed in this audit. No VPS/domain request, production change, binary edit or package build was performed. Work consisted of reading existing artifacts/source, reviewing current primary documentation, and writing this report. The DNS address `13.238.38.121`, Ubuntu version and open-port status are user-supplied deployment facts, not independently verified server observations.

## Decision by stage

| Stage | Architectural verdict | What prevents unconditional acceptance |
|---|---|---|
| 1. Tag 1 `vc.huxa.xyz` | **PASS for analytical size and configuration parity** | Candidate encryption/parser acceptance has not been executed; daemon getter coverage is not exhaustive |
| 2. Separate TLS pin and authority | **Correct for the app, conditional operationally** | Explicit TLS key type/reuse/rotation and chain policy required; NetworkDaemon delegate not proven equivalent |
| 3. REST authority | **INCOMPLETE as specified** | Heartbeat must return full session response; inbound device proofs, correlation, persistence and concurrent rotation need defined behavior |
| 4. Patch and rehash | **Size-feasible, not a complete signing procedure** | Existing patcher conflates Tag 2/3 keys; rehash changes cdhash and does not establish trust/loader acceptance |
| 5. Debian/RootHide package | **Necessary conventions identified, not certified** | Maintainer-script paths/modes/failures, installed compatibility versions, signing and actual archive metadata need validation |

This verdict uses [the UI/Tag 1 audit](/C:/Users/Admin/Desktop/vcnextnew/docs/CODEX_UI_AND_TAG1_AUDIT.md), [v3 sign-off](/C:/Users/Admin/Desktop/vcnextnew/docs/CODEX_SIGN_OFF_VERDICT_V3.md), and [the RootHide audit](/C:/Users/Admin/Desktop/vcnextnew/docs/05_ROOTHIDE_ECOSYSTEM_COMPATIBILITY.md), with their retained disassembly/source evidence. Earlier prose in `docs/00`, `docs/02`, `docs/03` and `docs/06` contains superseded assumptions; it does not override the more precise instruction-backed findings.

## Stage 1 — endpoint configuration

### Size and queried keys

Both `anix204.xyz` and `vc.huxa.xyz` contain 11 ASCII bytes. Replacing their two occurrences in the original compact JSON preserves **298 plaintext bytes**. The established two-padding formula gives:

```text
inner ciphertext = 16 * (floor(298 / 16) + 1) = 304 bytes
outer ciphertext = 304 + 16 = 320 bytes
```

Thus the proposed literal JSON fits the existing allocation without shortening routes, changing offsets or adding whitespace. This is a derivation from [previous authenticated measurements](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/tag1_layout.json), not a newly executed encryption test.

All nine original keys remain present: `api_base_url`, `api_host`, `audience`, `challenge_path`, `heartbeat_path`, `issuer`, `login_path`, `logout_path`, `renew_path`. All five route strings, issuer and audience are unchanged. This preserves the configuration data used by the audited app and common embedded helpers across all 14 locations. It does not substitute for tracing every NetworkDaemon/StreamDaemon getter or any separately encoded network behavior.

The app rejects a request URL unless scheme is exactly `https` and parsed host equals `api_host` (`0x100006048`–`0x1000060a8`). Both proposed fields agree. Do not later replace just one value, switch to an IP URL, add a proxy hostname, or depend on a cross-host redirect to correct a mismatch.

### No hidden terminator requirement

Tag 1 initializer `0x1000212f4` supplies decrypted **NSData** to `NSJSONSerialization`, options 0; see [the initializer](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/tag1_initializer_decompile.json). The original authenticated plaintext ends with `}`. No extra delimiter or C-string NUL is required. Both CBC padding layers are removed by decryption before JSON parsing; AES padding bytes must not be retained as JSON content. An added NUL changes the plaintext and must not be assumed acceptable to Foundation.

Preserve the complete salt/IV/ciphertext/MAC relationship. Tag 1 has **five additional live lengths**, `[16,16,16,320,32]`, at relative `+0x10,+0x28,+0x40,+0x188,+0x1b0`. These are separate from the nine fields inside the earlier Tag 2/3 replacement span. All three tags together have 15 length fields, including the final Tag 3 MAC length outside that span. A patcher preserving only the old nine is not sufficient for a newly constructed Tag 1 record.

The four randomized auxiliary REST paths are encoded separately from Tag 1; changing only the hostname intentionally retains those paths, now directed at the new base URL.

## Stage 2 — TLS key pin and response authority

### Correct separation, with a daemon evidence limit

The app's [TLS helper](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/decompile_1000203b0.json) performs these distinct operations:

1. `SecTrustEvaluateWithError` at `0x1000203e0`.
2. `SecTrustCopyKey` at `0x1000203ec`.
3. `SecKeyCopyExternalRepresentation` at `0x100020404`.
4. SHA-256 at `0x100020478` and comparison against the 32-byte Tag 2 value.

The [delegate](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/decompile_100008e0c.json) cancels on failure. Tag 3 is separately used to verify signed challenge/lease JSON through helper `0x100020214`.

For the proposed RSA TLS workflow, Tag 2 must contain the **32 raw hash bytes of the presented leaf public key's PKCS#1 DER**. It is not the CA key, leaf-certificate DER hash, PEM text hash, usual SPKI pin, or the 64 ASCII characters of a hex digest. Tag 3 remains the independently sized 1,071-byte response-signing certificate; the Let's Encrypt leaf/full chain does not belong in that slot.

This separation is proven for the app. No retained NetworkDaemon delegate disassembly establishes its identical policy. [The older network specification](/C:/Users/Admin/Desktop/vcnextnew/docs/02_SECURITY_SPEC_LAYER2_NETWORK_TLS.md:117) describes Tag 3 key comparison **or** Tag 2 comparison without offsets. That ambiguity must be resolved before claiming that `VCNAuthHeartbeatDelegate` accepts separated keys. A shared symbol name or repeated encrypted block is not sufficient proof of identical active callers.

### Certificate algorithm, chain and renewal

Certbot currently defaults new certificates to **ECDSA P-256**. The proposed PKCS#1 extraction therefore requires an explicitly selected RSA TLS key. The app helper itself has no observed RSA-only TLS gate; EC could work with Apple's EC external-key representation, but it would not use the stated RSA pin computation. Keep one explicit algorithm for this deployment. Certbot also replaces keys on renewal by default; persist its `reuse-key` policy if unattended renewals must keep the single embedded pin. A new-key override or lost/recreated certificate lineage can change that key. [Certbot key and renewal documentation](https://eff-certbot.readthedocs.io/en/stable/using.html#rsa-and-ecdsa-keys).

Renewing a certificate **with the same public key** preserves the pin despite changed certificate bytes. A genuinely rotated key breaks old clients. The observed helper accepts one exact pin; no backup-pin mechanism was demonstrated. Key reuse solves routine renewal continuity, not compromise recovery. Plan an explicit client/package migration for key replacement; changing the domain's server key and expecting old packages to continue is incompatible with this design.

System trust still applies before pinning. Let's Encrypt documents X1 support from iOS 10 and native X2 support from iOS 16. Serve a complete currently valid chain with an appropriate path for iOS 15; do not assume every newer root is natively trusted. Matching Tag 2 does not rescue a self-signed, expired, wrong-host or incomplete-chain TLS certificate. [Compatibility](https://letsencrypt.org/docs/certificate-compatibility/), [current chain options](https://letsencrypt.org/certificates/).

Do not hardcode renewal as “after 60–90 days.” As reviewed on the audit date, the classic profile lists 90-day validity while tlsserver lists 45 days; profile and issuance policy affect the schedule. Renew automatically well before expiry and verify the deployed key/chain after a successful renewal. [Let's Encrypt profiles](https://letsencrypt.org/docs/profiles/).

The pin must match the **actual TLS terminator**. A reverse proxy, load balancer or CDN may present a different key from the origin. Every IPv4/IPv6 destination serving this hostname must be consistent. nginx can select between RSA/ECDSA certificates; two independently keyed leaf certificates are incompatible with one fixed pin unless the client supports both. [nginx certificate selection](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate).

A long-lived custom TLS certificate is not an automatic improvement: public trust, hostname validation and expiry remain necessary. Keep the public TLS renewal lifecycle separate from the private response authority. Keep both private keys on the server side; do not ship the authority private key or an independent offline signer in the `.deb`.

## Stage 3 — REST contract and continuous lease freshness

### Successful responses: heartbeat must use the full contract

The challenge envelope and login/renew envelope are substantially aligned with the app audit. However, **“heartbeat returns refreshed lease and signature” is incomplete if interpreted literally.** Heartbeat/renew reply block `0x1000085b0` invokes the same consumer `0x100007730` as login. Each successful response needs:

| Response member | Required behavior |
|---|---|
| `access_token` | Nonempty string |
| `renewal_token` | Selected nonempty string; omission/wrong type may use current token, but explicit empty string fails |
| `next_nonce` | Nonempty string |
| `user.username` | Nonempty string |
| `user.active_devices`, `user.max_devices` | JSON numbers |
| `lease` | Dictionary with valid signature and semantic fields |
| `lease_signature` | Nonempty Base64 RSA signature, not a `signature` alias |

Returning existing tokens is possible if their bindings remain consistent; returning newly rotated tokens requires matching the new values everywhere. Optional numeric `user.expires_at` controls account display state independently of the signed lease expiry. `server_time` is not required, and server uptime must not be used as device `received_uptime`.

Inside the signed lease, explicitly include version 2, purpose `capability.lease`, issuer/audience, local device ID/key thumbprint, build string `"37"`, numeric issued/expires with positive TTL 90, and **all five grant strings**:

```text
camera.fake-frame   camera.obs   media.import
camera.controls     camera.color-sync
```

The three binding fields are lowercase hex SHA-256 of the **UTF-8 bytes of the selected response values**, not hashes of JSON-quoted strings or arbitrary offline fixtures. Consumer call `0x100007a8c` passes the selected tokens/nonce to verifier `0x100020cc4`; comparisons occur at `0x100021138`, `0x100021150`, `0x100021168`. [Verifier evidence](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/lease_verify_findings.md).

“Sorted JSON” must mean bytes matching Foundation options 2, not merely an arbitrary serializer's ordered dictionary. Use the exact typed dictionary being returned, finite numeric values, and consistent token/string encoding. Integer epoch timestamps avoid an unnecessary float-format variable. A native Foundation golden-byte/signature check remains necessary; earlier Python roundtrips do not prove every Unicode, escaping or numeric representation case.

### Challenge and inbound requests need a complete state model

The proposed signed challenge has the observed required fields and the correct **app text digest** `4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2`. Preserve that role distinction: it is not Camera's digest, and a NetworkDaemon request's digest source has not been traced. The app challenge ceiling is 120 seconds; the app lease master allows 185 seconds, but active app/Camera/Overlay disk readers impose 95 seconds. Ninety seconds is the cross-reader policy.

The actual app challenge request (`0x100006808`) carries:

```text
protocol_version, request_id, username, device_id,
device_public_key, client_build, binary_digest
```

The device public key is Base64 of SecKey external P-256 public bytes. The request does not supply a trusted thumbprint field: derive the matching thumbprint from that key and retain the device binding. This third key is distinct from the TLS and authority keys.

Login block `0x1000072a8` sends `username`, `password`, `device_id`, `device_name`, `client_build`, `binary_digest`, `challenge_nonce`, `challenge_id`, `device_signature`. Your proposed challenge omits `challenge_id`. That is not itself rejected by the native challenge verifier, but login then substitutes an empty correlation string. Define correlation explicitly; including a signed challenge ID is the straightforward contract. Retain the **entire signed challenge dictionary**: the device ECDSA proof covers Foundation sorted JSON of that dictionary, not merely its nonce. [Challenge/proof evidence](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/lease_verify_challenge_findings.md).

Heartbeat/renew proof construction at `0x100007fec` is also specific:

```text
Signed device proof:
  version, purpose, request_id, nonce, device_id, build,
  binary_digest, session_binding, issued_at

Wire request body:
  request_id, nonce, device_id, client_build,
  binary_digest, issued_at, device_signature
```

The server reconstructs that proof with the endpoint's purpose (`auth.heartbeat` or `auth.renew`) and the request bearer token. Here `session_binding` hashes the token actually used for the request; renew uses the renewal token. This request proof is distinct from the **response lease**, whose session/renewal bindings refer to the selected response tokens.

Account credentials, challenge expiry/use, device proof, nonce and token validity must be validated rather than accepting any well-shaped request. Define replay rejection and retry/idempotency behavior together: rejecting every repeat without handling a successfully committed but lost reply can strand an otherwise authorized client.

### LoginHandler and feature gates

No additional successful-response top-level field was found solely for `loginHandler`. Its invocation follows successful verification and storage; HTTP 200 alone cannot invoke it. The app writes AuthSession (0600) and CapabilityLease (0644) separately, adds local `systemUptime`, posts capability/state/floating notifications, then updates session state. A second-write failure has no observed rollback of the first.

All camera sections are still subject to per-capability checks, local configuration, live status, filesystem access and actual injection. Home health `0x100016d2c` can invoke logout when the local lease is invalid and AuthSession is absent. Successful login is therefore not a guarantee that every camera/OBS/media/overlay operation works. The inspected UI uses stacked sections/segmented controls, not an established independent tab login protocol.

### The unclosed background-daemon dependency

The server only answers requests; it cannot refresh a local plist without a functioning device requester/publisher. The original launchd plist proves root execution, `RunAtLoad` and `KeepAlive`; it proves neither successful network renewal cadence nor publication before a 90-second lease expires with the app suspended or closed.

There is no saved instruction-level NetworkDaemon contract/scheduler/delegate export in the reviewed evidence. That prevents a complete answer about its TLS key separation, inbound proof, response schema, token rotation, local receipt uptime, retry schedule and publication behavior. The old blueprint's 120–150-second cadence, if literal, would be incompatible with 90-second leases; it is unverified prose, not a measured implementation result.

Prefer the original supervised native renewal path once that behavior is established. Do not retain the previous local private-key signing writer alongside it: it has fixed offline bindings, a demonstrated retry-exhaustion gap, and would race the server-controlled state. Removing that writer from the design does not by itself prove the original daemon meets the deadline.

### VPS topology and failure handling

A single TLS terminator on 443 forwarding to a supervised loopback/Unix-socket FastAPI service is a reasonable small deployment. FastAPI is a Python application framework, not a compiled native daemon. Separate TLS renewal/reload from API worker restarts, and trust forwarded headers only from the intended proxy. [FastAPI HTTPS deployment](https://fastapi.tiangolo.com/deployment/https/).

Persist challenge/session/revocation state across restarts and share it across workers; an in-memory per-worker dictionary is insufficient for rotating tokens. Commit tokens, nonce and the corresponding response lease consistently. Bound backend work and request latency. Account for concurrent app/NetworkDaemon renewals, duplicate notifications, delayed older responses, deployment restart, crash after state commit and loss of the response.

The four auxiliary GET/POST routes can return `{}` promptly; their observed app requests have no response completion handler. They should not create/revoke authentication sessions based on randomized headers. Add deliberate handling for the app's once-only **HEAD to `/`**; this is separate from those four routes. Return errors from real auth routes in the observed `message`/`error` shape with appropriate HTTP status; avoid HTML error pages and unintended trailing-slash or cross-host redirects.

Port 80 availability supports an HTTP-01 deployment approach, not proof of successful issuance or renewal. DNS A/AAAA, SNI, public routing, ACME validation and served certificate remain prerequisites. Neither EC2 reachability nor the stated Ubuntu release proves device reachability, clock synchronization, service availability, or TLS pin agreement. No server probes were made here.

## Stage 4 — final binary identity, signing and trust

### Existing tools do not implement the new separation

The current [authority patcher](/C:/Users/Admin/Desktop/vcnextnew/scripts/patch_authority_in_binaries.py:50) derives Tag 2 from the **Tag 3 signing certificate**, then patches only Tag 2/3. It does not implement Stage 1 or accept the proposed independent production TLS pin through its main workflow. The TLS certificate's public key must become a separate public input; the server signing key/certificate must not silently determine it.

The current [mock server](/C:/Users/Admin/Desktop/vcnextnew/mocks/auth_server.py:74) remains incompatible: unsigned/unwrapped challenge, `signature` instead of `lease_signature`, absent user dictionary, and independently generated token/nonce values after lease creation. The existing lease generator/local signer use static offline binding hashes. This source review is not a claim that the proposed FastAPI authority already exists or passes these contracts.

Patch all main/mirror instances using validated per-slice locations; preserve each live length and neighboring record. Then perform the final signing/trust preparation, re-read the final Mach-O layout, verify decrypted tag values and text digests, and archive those final bytes. Signing tools may alter load-command/signature storage; do not assume earlier file offsets remain authoritative after any such change. No mutation may follow the final verification without repeating the affected checks.

### Page rehash: necessary consistency, insufficient trust proof

The [earlier experiment](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/sign_off_v3/code_directory_rehash.json) established that existing code-slot arrays can be updated in memory, with all text bytes and sizes unchanged. There are **21 CodeDirectories across 14 slices**; the mirrors include SHA-1 primary and SHA-256 alternate directories. It did not establish iOS signing/AMFI acceptance.

Use each directory's recorded hash type, page size, hash size, code limit and slice base, including the last partial page. The observed signing-page size is 4096 bytes; this is not an assertion about the CPU VM page size. Recompute all relevant covered pages in every directory, not only a stale list of previous mismatches.

**Twenty-one is the directory count, not a permanent mismatch count.** Adding Tag 1 touches an additional page in each arm64e Camera copy: ciphertext spans file `0x4af88`–`0x4b0c8`, crossing `0x4b000`, before the old Tag 2/3 region. From existing layout, full replacement is expected to affect 24 code-slot entries across the 21 directories rather than the previous experiment's 21. This is a static derivation, not an executed combined patch. A correct verifier must compute the actual final set instead of asserting “21 mismatches.”

Rehashing changes the **cdhash**. RootHide's pinned Dopamine 2 source has separate recursive collection and trust-cache insertion paths: [signatures.m](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/BaseBin/libjailbreak/src/roothider/signatures.m#L238-L275), [trust insertion](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c#L31-L57). Updating a hash table does not itself perform that trust operation or prove the particular installed loader accepts the resulting signature.

**A supported final-signature validation/creation and RootHide trust/loading step is required in the deployment specification. `ldid -S` is one possible signing tool invocation, not a universal sufficient command and not the only possible implementation.** A correct low-level signer could construct equivalent valid ad-hoc metadata; that has not been demonstrated by page rehash alone. The original observed CodeDirectories have flags zero, no CMS slot, and embedded requirements; do not label that state a newly verified standard ad-hoc signature. Conversely, the pinned source only declares `csd_superblob_is_adhoc_signed`; its implementation was not reviewed, so clear flags alone do not prove that helper rejects the artifact. Preserve each binary's required entitlements/requirements and inspect the actual signing result. A bare signing invocation that discards entitlements can break functionality; signing alone also does not prove target trust admission.

### Special slots

An in-place edit restricted to **ordinary code-slot hashes** does not alter Info.plist, requirements, XML/DER entitlements, or their stored special-slot hashes. The prior experiment found all 31 present requirements/entitlement hashes matching, with three app Info slots zero/unsealed. It did not establish entitlement authorization or requirement satisfaction.

If a later signing pass, bundle metadata edit or resource change modifies a special-slot input, regenerate and verify the appropriate seals. Never extend the earlier special-slot result to a different final artifact automatically. Unchanged `__TEXT,__text` preserves the measured text-digest input; it does not guarantee every hook, process, signature or self-integrity path succeeds.

## Stage 5 — archive and RootHide preservation

### Markers and loader behavior

The original archive evidence contains **five main-payload POSIX symlinks**, each named exactly `<binary>.roothidepatch`, targeting `/usr/lib/DynamicPatches/AutoPatches.dylib`. It does not contain five additional mirror markers. Preserve that manifest; do not manufacture mirror injection markers without a reason. [Original manifest](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/overlay/artifact_preservation.json).

The Windows `*.roothidepatch.symlink` files are extraction representations, not runtime markers. Reconstruct actual symlink tar entries and preserve their link targets; do not dereference them into copied modules, ship only the text files, or turn the target into a Windows link. Archive metadata is decisive even if a build host cannot represent the link natively.

Correct markers satisfy an image-discovery precondition. They do not guarantee injection: PatchLoader must be present/loaded, the target module and dependencies must resolve, injection filters must select the actual host, and final binaries must be admitted. PatchLoader dispatches a module; AutoPatches performs selected in-memory compatibility edits. Neither audited module provides the broad “re-sign at boot” guarantee stated in the existing `postinst` comment.

Preserve `Pre-Depends: rootless-compat (>=0.9)`, the intended injector dependency and package architecture conventions. The pinned public AutoPatches source identifies version 0.6, so it does not certify an unknown installed >=0.9 implementation. `Architecture: iphoneos-arm64e` is the existing RootHide package label, not proof that A11 should run arm64e: A11 must load the arm64 slices. Verify the actual bootstrap architecture and exact iOS/jailbreak support rather than treating all iOS 15/16 builds as equivalent.

### Debian structure and metadata

`data.tar.zst` and `control.tar.zst` are valid choices for a compatible dpkg. The `.deb` is an `ar` archive with required ordering: `debian-binary` containing `2.0\n`, then control tarball, then data tarball. Upstream zstd support starts at dpkg 1.21.18; the target bootstrap's implementation/version is what matters, not Sileo's name or the Ubuntu build host. [Debian format specification](https://manpages.debian.org/unstable/dpkg-dev/deb.5.en.html).

Preserve numeric ownership, executable bits, directories, link types/targets, LF script line endings and the original payload paths. Do not let Windows defaults determine archive modes. Keep runtime state owned/readable as intended while package code and launchd definitions retain their required protected ownership/modes. Give the custom build a distinct package version and accurate Installed-Size/checksums; exclude `.symlink` representations, IDA workfiles, audit copies, mocks and private keys from the data/control archives.

### Actual maintainer-script pitfalls

The current [postinst](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/postinst) is not a neutral packaging detail:

| Existing behavior | Architectural consequence |
|---|---|
| Hardcodes `/var/jb`; launch plists use logical `/usr/libexec/...` | Requires the actual RootHide installer/virtual-root/launchd path conversion; ordinary Ubuntu/rootless path assumptions cannot validate it |
| Recursively `chown mobile:mobile`, then `chmod u+rwX,go-rwx` on shared state | Directories become owner-only; later 0644 lease files do not help a different unprivileged UID traverse those directories. Verify actual reader credentials and any already-running/open-file behavior |
| Deletes CameraConfig, CameraStatus and CapabilityLease | Upgrade/install deliberately disarms features until fresh state is published; zero interruption cannot be promised |
| Removes AuthSession when maintainer argument 2 is empty | Fresh install requires login; upgrade argument handling must preserve the intended device identity migration |
| Attempts launchctl load/unload and uicache with failures ignored | Script exit 0 does not demonstrate running daemons, app registration or correct domain/path |
| Calls `killall mediaserverd` | Intentional restart interrupts active camera sessions; this is not a zero-disruption upgrade |
| A13 filter rewrite only for `iPhone12,*` | A11 uses its existing filter; do not assume the A13 mitigation executes on iPhone 8 Plus |

The [prerm](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/prerm) uses `/Library/LaunchDaemons/...`, unlike postinst's explicit `/var/jb` prefix. That difference must be interpreted in the actual compatibility environment; otherwise removal can leave services running. Neither script was run here.

Postinst privacy modes and the app's later atomic file writes must be assessed together. App persistence itself ignores chmod/chown failure after a successful plist write. For production readiness, verify resulting ownership **and parent-directory traversal**, not merely the plist's intended mode or a successful notification call.

## Architectural stress cases and the missing acceptance stage

| Stress case | Required behavior/evidence before release |
|---|---|
| TLS certificate renewed with same key | Trust-valid full chain, unchanged presented-key pin, terminator reload without breaking lease freshness |
| TLS key changed or RSA/ECDSA selection differs | Coordinated package/pin migration; old fixed-pin clients cannot be assumed to work |
| API restart or multiple workers | Durable shared session/challenge state; retry responses do not strand rotated tokens |
| App and daemon renew together | Consistent nonce/token rotation, idempotent recovery, no older response overwriting newer state |
| Cellular loss, DNS failure or slow response | Bounded client attempts before actual expiry; clear feature fallback/readiness state when recovery is impossible |
| Phone sleeps or reboots | Epoch expiry still applies even though awake uptime pauses; reboot changes the receipt clock domain. Fresh renewal is required, not merely a cached plist |
| App closed/suspended | Original NetworkDaemon proven to renew, verify, store and notify before the 90-second expiry |
| Directory/mode or second-file write fails | Detect incomplete session/capability publication and recover without a false successful login |
| RootHide rerandomizes its root | Root/mobile/injected clients and launchd resolve the same current logical state tree |
| Final artifact installed/upgraded/removed | Correct links/modes, trust admission, daemon jobs, UI registration and no stale services; installer disruptions accounted for |
| Valid, missing, expired and malformed lease | Expected UI/overlay/camera behavior, no unexpected SpringBoard/mediaserverd termination, video/IPC continuity measured |

The previous Option A retry result remains a warning against count-only scheduling: 20 failures returned to nominal sleep and recovered at 130 seconds; slow failures crossed TTL even before exhausting the count. That evidence does not prove the original daemon has the same defect, but it also cannot be used to certify it. A server cannot guarantee continuous authorization through an unresolved outage with a fixed 90-second validity window.

The appropriate next engineering gates are therefore concrete: complete the original daemon's instruction-level contract/scheduling audit; freeze the typed request/response and rotation rules; specify production TLS key/chain/renewal and independent patch inputs; select and validate the actual RootHide signing/trust flow; then build and inspect an isolated candidate and test it on the exact A11 device. A single EC2 instance remains a single availability dependency; retaining the same TLS key can simplify a future replacement host, but it does not supply failover or durable state by itself.

**Final disposition:** accept the equal-length Tag 1 choice and the app-side separation of TLS/authority roles as design decisions. Keep production sign-off pending until the explicit integration and acceptance gaps above are resolved. No deployment was performed, and no new runtime success is claimed.
