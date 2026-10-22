# VCNext v3 lease and Option A final verification

Date: 2026-10-19, Asia/Saigon. Scope: v3 source/output verification and review of the proposed native renewal service. This is a host-side audit and architecture verdict, not an iPhone deployment test. No iOS binary was modified or executed.

## Verdict

**The default v3 sample passes the five-capability, schema, 90-second duration, corrected digest, and RSA-3072 round-trip checks. Several prior defects are resolved. They are not all resolved, and native deployment is not yet verified.**

**Option A remains the preferred offline architecture:** one supervised native service, immediate startup refresh, a 90-second signed lease renewed approximately every 45 seconds, same-directory atomic replacement, then `notify_post`. The proposed `mobile:mobile` / `0644` lease mode can support the intended readers, but it is not sufficient by itself: directory traversal, process credentials, sandbox access, file protection, replacement-inode metadata and writer coordination still matter. Darwin notifications are system-wide across user sessions; they are not durable messages or consumer acknowledgements.

There is still no reviewed implementation of that native service. The shipped network job continues to execute the original `VCNNetworkDaemon`; a design paragraph and its existing `KeepAlive` settings do not implement local signing/renewal. Claims of indefinite uptime, zero crashes, absence of all egress, or compatibility across all five binaries are not established by this audit.

## 1. Execution and evidence

Executed successfully:

```powershell
python scripts/lease_generator.py
python scripts/cross_audit_verify.py --output-dir docs/evidence/final_audit/cross_harness
python scripts/verify_audit_artifacts.py
```

The generator exited 0 and printed successful verification with `TTL=90s, KeySize=3072b`. The harness also completed successfully. Its old TTL-200 probe assumed generation would return a payload; v3 correctly raises `ValueError`. The audit harness was updated to record that expected rejection, use receipt-relative synthetic clock cases, add TTL/capability boundary probes, and accept an output directory. Production generator/server/crypto code was not edited. Versioned output preserves the previous cross-audit evidence.

Evidence files:

- [Generator execution](evidence/final_audit/cross_harness/generator_run.json).
- [Inspected sample snapshot](evidence/final_audit/cross_harness/CapabilityLease_sample.audited.plist).
- [Exact Python-signed JSON bytes](evidence/final_audit/cross_harness/sample_signed_bytes.python.json).
- [All verification results](evidence/final_audit/cross_harness/verification_results.json).
- [Reviewed input hashes and shipped launchd configuration](evidence/final_audit/review_manifest.json).
- [Original-package preservation check](evidence/final_audit/artifact_preservation.json): **10/10 extracted Mach-O files remain byte-identical to the supplied `.deb`.**

Tests and simulated reader predicates run on Windows. They do not execute Foundation's iOS serializer, `SecKeyVerifySignature` on the phone, launchd, filesystem permissions on iOS, or Darwin notifications between target processes. The live sample expires shortly after generation; the snapshot records a test fixture, not a persistent deployment lease.

## 2. Resolved v3 findings

| Previously reported defect | Current observation | Status |
|---|---|---|
| Missing functional Camera grants | Default array is exactly `camera.fake-frame`, `camera.obs`, `media.import`, `camera.controls`, `camera.color-sync`; all five are strings | **Resolved for the default sample** |
| Generator allowed TTL >95 | Generation rejects -1, 0, 95.1 and 200 seconds; accepts 1, 90 and 95 | **Upper/lower input guards added; fractional edge remains** |
| Wrong arm64e constant | Independent LIEF measurement and generator parser both return `60e7f7328417c91f4dd21bf27077d5196b11d8aa698ce7f0c6f78217736a6bba` | **Resolved for the supplied Camera binary** |
| Outer/inner identity mismatches accepted by verifier | Changing outer `device_id` or outer thumbprint now returns false | **Resolved for those comparisons** |
| Issuer/audience mismatches accepted | Test-signed wrong issuer and wrong audience now return false | **Resolved** |
| Main command did not fail on failed helper verification | Main now calls `sys.exit(1)` when helper returns false | **Resolved in source** |
| Incorrect Camera active-reader documentation | Updated docs now identify Camera `0x121b0` and Overlay `0xc48c` as 95-second active readers | **Resolved for this distinction** |

The sample's version is integer `2`; purpose/issuer/audience/build/identities are strings; build is `"37"`; issue/expiry are numeric integer epochs; receipt is a float; duration is exactly 90 seconds; and the outer/inner identity fields agree. Numeric integer epochs meet the readers' `NSNumber`/`doubleValue` requirements.

The arm64 text digest remains correctly measured as `d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943`. A correct section measurement does not establish a universal runtime `binary_digest` target: the earlier audit traced mainBundle-based digest helpers, while the active Camera/Overlay lease readers do not compare this field.

### RSA and certificate measurements

| Measurement | Observed |
|---|---:|
| Test private key size | 3072 bits |
| Custom certificate public key size | 3072 bits |
| Custom certificate matches test private key | Yes |
| Custom certificate DER size | 1,040 bytes |
| Custom DER file matches PEM certificate encoding | Yes |
| Sample RSA signature size | 384 bytes |
| Sample verifies under current test public key | Yes |
| Sample verifies under original embedded Camera authority | **No** |

The Camera and Overlay still contain the original matching certificate; their original RSA key is also 3072 bits but has a **different public modulus**. Upgrading a replacement key's size does not establish that it is the same key or trusted by these unchanged binaries. The key/certificate correspondence is fixed for the custom fixture; the installed-authority mismatch remains until a separately authorized, verified trust integration is performed. No such binary integration was performed here.

The crypto inverse fixture still passes: decrypting and re-encrypting the original Camera Tag 3 block with its existing parameters reproduces its ciphertext/HMAC, and a changed MAC is rejected. However:

| Tag 3 representation | Original | Current custom certificate |
|---|---:|---:|
| DER plaintext | 1,071 bytes | 1,040 bytes |
| Double-CBC ciphertext | 1,088 bytes | **1,072 bytes** |

The custom plaintext is smaller than the original, but its encrypted block is **16 bytes shorter**. Approximate DER size matching is not proof of a valid drop-in encrypted block. Stored lengths, allocation, HMAC and every relevant slice/copy still need consistent verification in a future packaging phase. Merely copying shorter ciphertext while preserving the old read length is not validated by the current tests.

## 3. Remaining generator/verifier defects and limits

### 3.1 The receipt marker is still simulated

The command explicitly supplies `current_uptime=100.0`; omitting it also falls back to `100.0`. It does not measure the phone's uptime. For this sample, an otherwise valid reader accepts the monotonic interval only when the phone's uptime is in **`[100.0,190.0)`**, with its wall clock also before the signed expiry. The native service must obtain `NSProcessInfo.systemUptime` on that same phone and boot.

The helper still returns true for the following cases rejected by the reconstructed native predicate model:

| Case | v3 Python helper | Reader model |
|---|---|---|
| Simulated phone uptime 3,600; receipt 100 | Accepts | Rejects |
| Simulated phone uptime 99; receipt 100 | Accepts | Rejects |
| Signed wall-clock expiry already reached | Accepts | Rejects |
| `received_uptime` is a string | Accepts | Rejects |

These four residual failures are recorded in the harness output. The verifier remains incomplete for native time/class checking, despite its “comprehensive/native verified” wording. The comparison model is host-side analyst code, not a target-device execution.

### 3.2 The general API does not strictly enforce its advertised contract

- **Fractional duration:** `ttl_seconds=0.5` passes the new input guard, but `int(ttl_seconds)` truncates it to zero. Generation returns a zero-duration lease and its verifier rejects it. Preserve the requested positive numeric duration or explicitly reject unsupported fractional inputs; the normal 90-second profile is unaffected.
- **Capability override:** the default has all five grants, but an override containing only `camera.fake-frame` and `camera.controls` is generated and accepted by the helper. It verifies only those two mandatory strings. If the contract requires all five features, that contract is not enforced for overrides.
- **Capability element classes:** an array with all five names plus integer `42` is accepted by the helper. The default output is correctly typed; the helper does not enforce an all-strings array.

The native reader itself checks the array class and requested capability membership rather than universally requiring all five grants. Distinguish that actual reader policy from this project's full-feature issuance policy.

### 3.3 Serialization, session and parser limits remain

The default sample still uses a restricted ASCII/integer JSON profile, so a compact sorted-key representation is plausible, but native Foundation byte identity remains **unverified**. The earlier [Foundation serialization analysis](CODEX_CROSS_AUDIT_VERDICT.md) documents slash, Unicode, key-comparison and numeric-format differences. The new RSA size does not resolve those differences.

The generator's session/renewal/nonce hashes remain based on fixed offline strings; they are not evidence of agreement with an actual App/Network session. The active Camera/Overlay readers do not test these bindings, while other consumers may. The unchanged mock server still returns independent generated tokens. Full five-process session integration is not established.

An additional [public-key role check](evidence/final_audit/public_key_role_checks.json) confirms that the sample's `device_key_thumbprint` equals SHA-256 of the **custom server RSA SubjectPublicKeyInfo**, rather than establishing a thumbprint of a device P-256 identity key. Its outer/inner copies agree, so the active readers' envelope comparison passes. For real device/session integration, use the value required by the actual device-key contract; equality between two copied sample fields is not hardware/device-key validation. The custom public-key export itself does match the custom certificate.

The Mach-O parser's historical slice fallback, synthesized digest on parse failure, and swapped-FAT-endian handling also remain. Its normal arm64/arm64e measurements pass for the supplied file; it must not report a fallback constant as proof that a different or malformed artifact parsed successfully.

## 4. Option A plan review

**Accept the design direction, conditional on implementation and device verification.** Use a long-lived foreground service supervised by launchd, with a serial internal timer around 45 seconds and an immediate first refresh. `RunAtLoad` and `KeepAlive` handle launch/supervision; they do not themselves implement the 45-second renewal logic. Apple's [launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) describes that supervision model; its OS X examples are not a substitute for RootHide/iOS job validation.

The shipped plist still contains:

```text
Label:            com.vcnext.networkd
ProgramArguments: /usr/libexec/VCNNetworkDaemon
UserName:         root
RunAtLoad:        true
KeepAlive:        true
```

No new native publisher source or executable was found in the reviewed implementation paths. Reusing this label requires replacing its execution role deliberately and preventing the original network process, app or another refresher from becoming a competing lease writer. The existing postinst deletes previous lease state and loads the original network job. The future service must account for install/upgrade/startup ordering and retain coherent identity/session behavior for all consumers.

At a successful 45-second cadence, a 90-second lease has about 45 seconds of nominal remaining lifetime. This margin absorbs some ordinary delay; it does not prove that signing failure, suspension, key/file unavailability, a hung process, or repeated I/O failure can never exceed the remaining lifetime. KeepAlive cannot diagnose every hang. Refresh immediately when runnable after restart/wake and handle wall-clock changes; a gap beyond expiry still disables unchanged readers.

### 4.1 `mobile:mobile` / `0644`: compatible in principle, with remaining edges

1. **Directory access is independent of file mode.** `0644` allows the owner to read/write and other users to read. Each reader must still traverse every parent directory. The shipped postinst applies `chown -R mobile:mobile` and `chmod -R u+rwX,go-rwx` to the shared tree; newly created ordinary directories therefore become owner-only, typically `0700`. A non-mobile/non-privileged host cannot reach a file there simply because that file is `0644`. Record the effective UID/groups and sandbox access of SpringBoard, mediaserverd/cameracaptured and both daemons on the target rather than assuming all injected hosts share one identity.
2. **Atomic replacement publishes a new inode.** A root-run service can accidentally publish a root-owned `0600` temporary file and make the final lease unreadable to mobile. Apply and verify the intended `mobile:mobile` / `0644` metadata **on the completed temporary inode before rename**, using descriptor-based operations; verify all errors. The old file's mode/owner/protection are not automatically inherited.
3. **Rename depends on directory permissions and the filesystem.** File write permission is not the permission that controls replacement of a directory entry. Create the temporary file in the same resolved directory/filesystem; use a unique exclusively created temporary file, write and close it completely, then replace the destination. Preserve the last good destination on failure. Apple's [rename manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/rename.2.html) documents same-filesystem requirements and namespace replacement. Atomic visibility is separate from power-loss durability; handle flush/durability requirements and failures explicitly.
4. **`0644` does not override sandbox or Data Protection.** A readable POSIX mode does not make a protected file or signing key accessible before first unlock. Apple's [Complete Until First User Authentication documentation](https://developer.apple.com/documentation/foundation/fileprotectiontype/completeuntilfirstuserauthentication?language=objc) describes continued access after the first unlock. Choose compatible protection for the intended lifecycle and handle unavailable protected data without a rapid restart loop. Check both key access and lease-file access across reboot and lock/unlock.
5. **The signing key needs separate permissions.** Do not give the private signing key the lease's `0644` mode. Its owner/credentials and protection must match the service that signs, while the published lease remains readable by its consumers. Root-only key access and mobile-readable output are different requirements.
6. **`mobile:mobile` / `0644` is not single-writer enforcement.** The owner can edit the file, and a process with write access to its directory can replace the entry. Coordinate writers and reject malformed local input. Atomic rename prevents partial files, but not an older competing writer replacing a newer complete lease.
7. **RootHide path agreement must be observed.** A bare `/Library/LaunchDaemons` or `/usr/libexec` path is logical within the jailbreak environment. Resolve current `jbroot` correctly and ensure the publisher and readers reach the same shared file after rerandomization. `libroot` alone is not a universal file-API interposition guarantee; retain the conversion/marker dependencies documented in [the ecosystem audit](05_ROOTHIDE_ECOSYSTEM_COMPATIBILITY.md).

These are Unix/iOS lifecycle conditions, not A11 PAC-specific workarounds. A11 uses the arm64 path without hardware PAC, but that does not prove code trust, sandbox access or crash-free execution. Mode changes alone cannot establish those properties. Windows tests cannot validate effective iOS ownership, ACLs, protection classes or sandbox decisions.

### 4.2 Darwin notification propagation

The exact event name is **`com.vcnext.capability.changed`**. The Overlay observer at `0x4488` registers it through `CFNotificationCenterGetDarwinNotifyCenter`; callback `0x448c` requests refresh `0x4490`. Apple's [Darwin-center documentation](https://developer.apple.com/documentation/corefoundation/cfnotificationcentergetdarwinnotifycenter()?language=objc) ties this center to `<notify.h>`, with system-wide rather than per-user-session notifications. Therefore a root producer and mobile consumer do not require a custom per-UID relay solely because their UIDs differ.

Remaining propagation conditions are:

- Post **after** successful file publication and check for `NOTIFY_STATUS_OK`; a failed write must not be announced as a successful renewal.
- A successful post is not proof that a particular consumer registered, received the event, reloaded the right file, or accepted its signature. There is no payload containing the new lease or an acceptance acknowledgement in this design.
- Notifications can coalesce, and delivery can be delayed or lost under the API's documented queue constraints. They are not a durable replay log for processes that register later. See Apple's [notify manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/notify.3.html).
- CF Darwin delivery needs the receiving main run loop running in a suitable common mode. A busy/suspended process is not forced to execute merely by a “deliver immediately” flag; Darwin ignores several distributed-notification parameters. On-device sandbox/notification access still needs verification.
- Overlay's one-second refresh timer provides a fallback, subject to run-loop scheduling. Camera obtains capabilities through its configuration path, independently of the Overlay timer. Both positive lease caches can briefly reuse a still-valid lease within their 0.5-second cache window. Posting is not a guarantee of immediate signature revalidation in every process.

The robust pattern is **committed file state as the source of truth, notification as a refresh hint**, and normal consumer/startup reads as recovery. With atomic publication, coalescing several renewals into one reload is acceptable when the consumer reads the latest complete file. It is not evidence that a 45-second publisher can never stall or that a 90-second lease can never expire.

## 5. Documentation corrections and acceptance boundary

The updated 95-second reader distinction and default capabilities/digests are supported. Remaining specification statements need qualification:

- “No SpringBoard crash,” “never switches off,” and “all five binaries operate indefinitely” are untested outcomes. A matching timer plan cannot prove them.
- Keeping original instruction bytes avoids adding an instruction patch; it does not establish PAC/loader/trust correctness of every deployed image. Source-supported RootHide mechanisms are not physical-device validation.
- `0x116b4` is a section-range parser; its caller's mainBundle-derived file selection remains relevant. A correct Camera text hash does not establish universal self-hash success.
- Capability identifiers and instruction addresses are different evidence. The established Overlay **call instructions** are `0x46e8` for `camera.controls` and `0x47b8` for `camera.color-sync`. The `0x1224d` / `0x1225d` references in the v3 prose are not those verified call instructions; Camera `0x178dd` is a string location, while its color capability call is `0xa968`.
- Offline signing by the proposed service does not itself prove that other still-installed components produce zero network traffic.

Before deployment acceptance, require native Foundation/Security verification under the intended installed authority; real phone uptime/epoch values; the built service and final launchd configuration; actual root/mobile read/write and notification observations; and a run covering multiple renewals, expired/invalid leases, service restart, unavailable key/file, lock/sleep/wake, respring, reboot and upgrade. Observe both UI and frame/IPC behavior, not just notification-post success. No such device run was performed in this phase.

**Final disposition:** default v3 fixture substantially corrected; general verifier/edge-input defects and trust integration remain. Option A is conditionally sound as a design, with filesystem and notification edge cases explicitly identified. **Not yet deployment-validated or zero-crash certified.**
