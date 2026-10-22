# VCNext build 37: cross-audit verdict

Date: 2026-10-19, Asia/Saigon. Scope: the updated source files, generated sample, supplied Camera/Overlay binaries, and renewal architecture. No iOS binary was modified, re-signed, injected, or executed. HTTP/TLS tests used temporary loopback listeners only; all were stopped. No production licensing endpoint was contacted.

## Verdict

**The updated sample passes the requested basic field/class checks and the Python RSA round trip, but it does not establish native compatibility or functional camera readiness. Do not mark this implementation deployment-verified.**

The material findings are:

1. The sample has TTL **90 seconds**, string build `"37"`, a string-array capabilities field, numeric epoch timestamps, and a double receipt marker. However, its receipt marker is hardcoded to **120.0**, not measured on the phone.
2. The sample is signed by the custom test key. The unchanged Camera and Overlay embed a **different public key**. It cannot authenticate to these unchanged readers.
3. The Camera configuration requests **`camera.fake-frame`, `camera.obs`, and `media.import`**, all absent from the generated capabilities. A structurally valid lease can therefore leave camera/stream features gated even if the overlay controls appear.
4. The Camera's **active reader at `0x121b0` also limits duration to 95 seconds**. Its exported master at `0x10e1c` has the separate 185-second limit and no observed internal callers. The updated spec still conflates these paths.
5. The arm64 Camera text digest is correct. The documented arm64e constant is incorrect for the supplied artifact; the measured value is `60e7f7328417c91f4dd21bf27077d5196b11d8aa698ce7f0c6f78217736a6bba`.
6. Python compact sorted-key JSON is a plausible byte match for this restricted ASCII/integer sample, but **no iOS Foundation byte comparison was performed**. It is not a general implementation of Foundation's serializer.
7. The mock serves HTTP and TLS locally, but its signed session/renewal/nonce bindings do not match the tokens/nonces it returns. Transport success is not native protocol success.

**Renewal recommendation:** for the requested offline A11 environment, prefer **Option A: one supervised native on-device renewal service**, with a 90-second lease renewed about every **45 seconds**, correct same-device clocks, and atomic file publication. This is the lowest-risk architecture among the proposed options for preserving the existing readers. It still requires a trusted signing authority, complete capability/consumer integration, and device validation. Option B does not solve the independent Camera reader or other consumers. For centralized licensing, use Option C with an on-device renewal client and a complete verified protocol; serving the present Python mock is insufficient.

## 1. What was run and preserved

The requested command was run successfully:

```powershell
python scripts/lease_generator.py
```

It printed a successful RSA verification with TTL 90 and exited 0. The audit then ran a reproducible verification harness and bounded transport probes:

```powershell
python scripts/cross_audit_verify.py
python scripts/cross_audit_mock_probe.py
```

The harness reruns the generator, parses the **written plist**, verifies its signature, independently parses Camera section bounds using LIEF, tests the validator's missing checks, and exercises the encryption inverse. It does not execute Apple code. Its reconstructed predicate model is explicitly an analyst model, not a native test.

Evidence:

- [Generator execution record](evidence/cross_audit/generator_run.json).
- [Audited plist snapshot](evidence/cross_audit/CapabilityLease_sample.audited.plist) and [exact Python-signed JSON bytes](evidence/cross_audit/sample_signed_bytes.python.json).
- [Verification results, source hashes, and negative cases](evidence/cross_audit/verification_results.json).
- [Loopback HTTP/TLS results](evidence/cross_audit/mock_transport_results.json).
- [Camera master](evidence/cross_audit/camera_master.json), [active reader](evidence/cross_audit/camera_runtime_reader.json), [configuration consumer](evidence/cross_audit/camera_configuration.json), and [reader xrefs](evidence/cross_audit/camera_reader_xrefs.json).
- Complete [Camera arm64 assembly](evidence/cross_audit/camera_arm64_text.asm) and [arm64e assembly](evidence/cross_audit/camera_arm64e_text.asm), plus [instruction scan coverage](evidence/cross_audit/camera_instruction_coverage.json).

The existing generator, crypto engine, mock server, and specifications were reviewed without editing them. The generated sample was intentionally refreshed by the requested execution; any pre-existing sample was copied to `evidence/cross_audit/CapabilityLease_sample.before.plist`. No private-key bytes were copied into audit evidence or printed. Sample timestamps/hashes change on a rerun; use the JSON evidence associated with the corresponding snapshot.

All offsets below are **unslid virtual addresses in the arm64 slice**, not offsets into the complete FAT file. Camera's arm64 slice starts at full-file offset `0x4000`; its arm64e slice starts at `0x34000`. The package identity and unchanged extracted Mach-O files are checked against the original Debian archive by [the preservation verifier](../scripts/verify_audit_artifacts.py).

## 2. Generated payload validity

### 2.1 Field and type checks

`plistlib` round-trip inspection established these actual values/types. Integers and reals in this plist are compatible with Foundation `NSNumber`; the native readers call `doubleValue`, so the two epoch fields do not have to be encoded as plist `<real>` values.

| Requirement | Generated sample | Result |
|---|---|---|
| Envelope and inner lease dictionaries | Python `dict` / plist dictionaries | Pass |
| `version` | Integer `2` | Pass |
| `purpose` | String `capability.lease` | Pass |
| `issuer`, `audience` | Strings `vcnext-main`, `vcnext-ios` | Pass for the reviewed expected values |
| `build` | String `37` | Pass |
| Device ID and thumbprint | Strings; outer/inner copies match | Pass for the two readers' envelope comparisons; no physical device identity validation |
| `capabilities` | Array of six strings, including `camera.controls` and `camera.color-sync` | Class check passes; Camera functional grants incomplete |
| `received_uptime` | Float `120.0` | Class check passes; actual-device timing unresolved/usually incompatible |
| `issued_at`, `expires_at` | Integer epoch values; difference `90` | Numeric class and duration checks pass |
| Signature | Base64 decoding to 256 bytes; RSA-2048 test key | Pass with the matching test public key; fail against unchanged embedded authority |
| `binary_digest` | Stated arm64 Camera `__TEXT,__text` hash | Correct measurement of that file section; neither active reader compares this field |

For the sample's fixed `received_uptime`, the monotonic test only succeeds when the phone's own uptime is in **`[120.0, 210.0)`**, while its wall clock must also be before the signed expiry. A Windows-generated receipt value does not acquire meaning on a phone merely because it is numeric. This sample is a short-lived fixture, not an installable persistent lease. Re-running the generator on a host still writes `120.0`.

The generator API does **not** enforce a 90/95-second upper bound: calling it with `ttl_seconds=200` generated a 200-second payload. Its verifier rejected that duration, but generation itself allowed it. Fractional TTL inputs are truncated by `int(ttl_seconds)`; the default 90-second invocation is correct, while the broader claim that the function enforces TTL is not.

### 2.2 The Python verifier is incomplete

The helper is documented as a comprehensive reconstruction of `0xc48c`, but it does not check issuer, audience, outer/inner identity agreement, receipt value class, phone uptime delta, or current wall-clock expiry. It also checks only that capabilities is a list, without ensuring its elements are strings. The generated sample does contain strings; this is a limitation of the verifier rather than a sample type failure.

The harness produced eight negative cases that the supplied helper accepted but the reconstructed reader rejected:

- Simulated device uptime of 3,600 seconds with the sample's receipt of 120.
- Simulated device uptime of 100 seconds, before that receipt.
- Current epoch time beyond the signed expiry.
- An outer device ID that differs from the signed lease.
- An outer thumbprint that differs from the signed lease.
- A different issuer in a newly test-signed lease.
- A different audience in a newly test-signed lease.
- A string rather than a number for `received_uptime`.

These are host model comparisons, not iOS execution. They demonstrate why the successful helper message must not be presented as full native validation. The script's main block also does not convert a false helper result into an explicit nonzero process exit status.

### 2.3 Signing authority

The Camera certificate initializer at `0x11864` supplies the Tag 3 block to the crypto decoder. The audit decrypted that **original binary block** without altering it and confirmed its DER bytes match `mocks/server_cert.pem`. The Overlay's corresponding Tag 3 block decrypts to the same certificate.

That original certificate has a **3072-bit RSA key**; the current test key and custom certificate have matching **2048-bit RSA keys**. The test signature verified with the latter and failed with the original embedded public key. The algorithm identifier `RSASignatureMessagePKCS1v15SHA256` specifies signing/padding/hash behavior; it does not imply that the original embedded key must be 2048 bits.

Therefore a correctly serialized lease signed by the current test key still does not authenticate to the unchanged readers. Installing a PEM beside a script or successfully creating a TLS listener does not change the readers' embedded authority. Any future authorized trust change must be independently audited across all consumers; it was not performed here.

### 2.4 Foundation serialization: bounded result

Camera `0x103b8` is `MOV W3,#2`; its serializer call is at **`0x103c0`**, and `SecKeyVerifySignature` is at **`0x1049c`**. Overlay uses the corresponding `0xa694` / `0xa69c` / `0xa778` sequence. See [Camera RSA decompilation](evidence/cross_audit/camera_rsa.json) and the raw assembly.

The generator's current payload contains only ASCII strings, lowercase ASCII field names, and integer numbers. No signed string contains `/`; `received_uptime` is outside the signed payload. Compact JSON with sorted keys is consistent with the simple representation needed for this fixture. Nevertheless, no iOS 15/16 Foundation output was captured and compared with the [757-byte Python fixture](evidence/cross_audit/sample_signed_bytes.python.json), so strict target byte identity remains **unverified**.

General equivalence is false. The [pinned Foundation reference source](https://github.com/swiftlang/swift-corelibs-foundation/blob/21b3196b33a64d53a0989881fc9a486227b4a316/Sources/Foundation/JSONSerialization.swift#L24-L36) defines sorted keys as option `2` and a separate no-slash-escaping option. Its [string writer](https://github.com/swiftlang/swift-corelibs-foundation/blob/21b3196b33a64d53a0989881fc9a486227b4a316/Sources/Foundation/JSONSerialization.swift#L459-L493) and [key comparison](https://github.com/swiftlang/swift-corelibs-foundation/blob/21b3196b33a64d53a0989881fc9a486227b4a316/Sources/Foundation/JSONSerialization.swift#L576-L590) show relevant differences:

- Python's default `ensure_ascii=True` emits `caf\u00e9`; the reference writer emits Unicode characters as UTF-8.
- Python emits `a/b`; option `2` in the reference writer escapes the slash as `a\/b`.
- Python key ordering is not a promise of the same numeric/case-aware string comparison used by that reference implementation.
- Numeric formatting needs a native fixture if signed fields later become floating-point values.

This open-source reference corroborates the risks; it is not the iOS 15/16 Darwin binary. For a native on-device signer, use the same Foundation API/options. For a Python remote authority, constrain the payload profile and require golden-byte comparisons plus native `SecKeyVerifySignature` results on both target OS versions before claiming full interoperability.

## 3. Camera checks: the requested range versus the active path

The requested `0x1108c`–`0x112d4` range is inside exported master `_VCN5d92c005b0c38441000a` (`0x10e1c`). It is not a complete validation path by itself: token/nonce hashing happens earlier and the time helper is invoked afterward at `0x112e4`.

The master requires a valid RSA signature, schema strings, array capabilities, expected device information, and bindings equal to SHA-256 of the supplied session/renewal/nonce text. It passes **185.0** to `0x10c74`. The generator's fixed offline binding hashes match only those specific strings, not an arbitrary real `AuthSession` or arbitrary returned mock tokens. No real device session was supplied. No internal callers of this exported Camera master were found by IDA or the complete direct-branch scan of either slice.

The configuration consumer actually calls capability function `0x120fc`, which calls reader **`0x121b0`**, then RSA helper `0x1036c`. That reader matches the Overlay's envelope and short-duration design. Important arm64 instruction anchors:

| Camera address / bytes | Meaning |
|---|---|
| `0x122c0` | Load stored `CapabilityLease.plist` through `dictionaryWithContentsOfFile:` |
| `0x123a8`–`0x124f0` | Receipt, issue and expiry presence/type processing |
| `0x12518`–`0x12670` | Version, purpose, issuer, audience, build and envelope identity comparisons |
| `0x126bc: 0900d8d2`, `0x126c0: e90ae8f2` | Construct IEEE-754 `0x4057c00000000000` = **95.0** |
| `0x126d8: 41090054` | Reject combined array/duration predicate failure |
| `0x126e4: eb080054` | Reject negative uptime delta |
| `0x126ec: a5080054` | Reject uptime delta >= duration |
| `0x126fc: 0d080054` | Reject wall-clock expiry |
| `0x12708: 19f7ff97` | Call RSA verifier `0x1036c` |

Both readers use a positive cache capped at 0.5 seconds, with independent uptime and wall-expiry bounds. The Camera reader is called from its configuration path; it does not need the Overlay's one-second timer to expire capabilities.

### Camera capability names are functional checks

`-[VCNd322545034651df4a1c9 configuration]` at `0xa6f4` contains these calls to `0x120fc`:

| Call instruction | Exact requested capability | Present in sample? |
|---|---|---|
| `0xa8f0` (`031e0094`) | `camera.fake-frame` | **No** |
| `0xa904` (`fe1d0094`) | `camera.obs` | **No** |
| `0xa914` (`fa1d0094`) | `media.import` | **No** |
| `0xa968` (`e51d0094`) | `camera.color-sync` | Yes, but its configuration call is gated by the fake-frame result |

If `camera.fake-frame` is false, the code sets the OBS grant false and the media-import-denied state true. `setStreamEnabled:` and `setPrivacyBlocked:` depend on these results (`0xa930`, `0xae28`). The exact resulting picture depends on CameraConfig and the rendering path; this audit does not assert a reproduced black frame or crash. It does establish that `virtual_camera` and `rtmp_streaming` are **not aliases** for these checks in the supplied Camera code.

### Digest verification

Independent LIEF parsing and the updated generator parser agree:

| Supplied Camera slice | `__TEXT,__text` size | Measured SHA-256 |
|---|---:|---|
| arm64 | 59,876 bytes | `d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943` |
| arm64e | 61,664 bytes | `60e7f7328417c91f4dd21bf27077d5196b11d8aa698ce7f0c6f78217736a6bba` |

The code's `ARM64E_TEXT_DIGEST = 96e6...` constant and the updated docs do not match this artifact. The sample defaults to arm64, so that discrepancy does not change this A11 sample's digest, but it invalidates the stated cross-architecture baseline.

Also, measuring the Camera file's section does not establish what every consumer considers `binary_digest`. Camera's digest initializer `0xffe0` reads **`NSBundle.mainBundle.executablePath`**, then its section parser at `0x116b4` selects `__TEXT,__text`. Inside an injected host this is not evidence of hashing the Camera dylib's own path. Neither active Camera nor Overlay reader checks `binary_digest` at all. The master/challenge/API consumers must be traced individually before assigning a universal digest meaning.

The updated parser still has permissive fallbacks: an absent requested FAT slice uses a fixed historical range, and failure to find text returns the arm64 constant. It recognizes a swapped FAT magic but still parses its table as big-endian. These branches should not be treated as evidence of a successful parse; the supplied normal FAT file did parse correctly.

## 4. Crypto engine and mock server review

### 4.1 Encryption inverse

`encrypt_payload_block` passed an independent fixture check: the original Camera Tag 3 certificate was decrypted from its binary block, re-encrypted using its existing salt/IVs, and produced **identical ciphertext and HMAC**. Round trips at plaintext lengths 0, 1, 15, 16, 17, 31, 32, 128 and 1,024 passed; a modified MAC was rejected. This confirms the inverse against the reviewed Tag 3 fixture, beyond merely encrypting/decrypting newly generated data with the same functions.

That result does not certify a binary-repacking implementation. Original Tag 3 plaintext/ciphertext lengths are **1,071 / 1,088 bytes**; the custom certificate produces **784 / 816 bytes**. A future replacement must reconcile the stored lengths, block allocation, HMAC and every consuming slice/copy. No replacement bytes were written. Changing only data outside `__text` preserves its mathematical text digest, but does not establish complete loader, trust, protocol or runtime correctness.

### 4.2 HTTP/TLS probe results

Temporary Python HTTPServer instances bound to **127.0.0.1 on ephemeral ports** returned 200 for challenge/login/heartbeat/renew. The TLS probe loaded the custom certificate and existing test key successfully; the client explicitly trusted that certificate and omitted hostname verification. All listeners were shut down. This proves local transport operation, **not** native URLSession trust, hostname validation, pinning, protocol acceptance, or successful on-device lease storage.

The mock's remaining integration gaps are concrete:

- Login/heartbeat/renew return fresh tokens and nonce, but the signed binding fields remain hashes of fixed offline strings. All three corresponding binding comparisons in the probe were false.
- Challenge is an unsigned four-field mock response. It is not evidence that the native signed-challenge flow is implemented.
- Empty JSON bodies are accepted as active sessions. This is fixture behavior, not a tested authentication/session state machine; logout likewise does not prove revocation enforcement.
- `current_uptime=time.time()` is epoch time, not device uptime. Currently the response **discards the envelope** and returns only `lease` and `signature` plus session fields, so the wrong receipt marker is not actually transmitted by this code. A native client may intentionally construct the local envelope itself; the HTTP response need not equal the on-disk plist. The receiving/writing contract must be verified, and any receipt marker must be measured on the phone.
- The default command runs **HTTP** on `0.0.0.0:8443`; TLS requires `--ssl`. A successful custom-cert TLS handshake does not make unchanged VCNext trust that authority. The prior TLS-helper audit shows trust evaluation as well as pin comparison.

Consequently Option C needs protocol/authority integration and a renewal client, not just a running `auth_server.py` process.

## 5. Renewal architecture comparison for iPhone 8 Plus

The following is an engineering recommendation derived from the verified readers and platform mechanisms. It is not a device-test result. The exact Dopamine RootHide/iOS build remains a deployment precondition, as detailed in [the ecosystem report](05_ROOTHIDE_ECOSYSTEM_COMPATIBILITY.md).

| Option | Main advantage | Material failure/maintenance costs | Verdict |
|---|---|---|---|
| **A. Supervised native local renewal service** | Preserves existing reader instructions; works without network; failures are separated from SpringBoard/mediaserverd | Requires trusted signing authority, correct clocks/permissions/RootHide paths, atomic publication, supervision and one writer; local signing-key custody | **Preferred for the requested offline A11 design**, conditional on resolving the sample/integration failures |
| **B. Patch four Overlay branches** | Removes selected checks in one reader | Does not affect Camera `0x121b0`, other processes, signatures, capability names or session bindings; changes executable bytes/trust requirements; offset and ABI maintenance | **Not recommended** as a system-wide reliability solution |
| **C. Local/LAN/VPS authority plus client** | Centralized signing/policy and easier key custody off-device for LAN/VPS | Needs a supervised on-device client, full protocol/TLS compatibility, low latency and reachability within the short expiry; local HTTP adds an unnecessary hop for fully offline signing | Appropriate for centralized licensing; **current mock is not ready** |

### Why patching only the listed Overlay offsets is incomplete

`0xc9b4` rejects a combined capabilities-array and positive/maximum-duration predicate; it is not a pure standalone TTL switch. `0xc9c0` rejects a negative uptime delta, `0xc9c8` rejects an expired monotonic interval, and `0xc9d8` rejects wall expiry. Removing these branches would alter validation semantics and still leave the separate Camera checks at `0x126d8`, `0x126e4`, `0x126ec`, and `0x126fc`. Other package processes were not re-audited end-to-end in this turn.

A11's lack of hardware PAC removes PAC-specific behavior from its arm64 execution path; it does not remove code-signature/trust requirements, instruction correctness, cache/race concerns, or independent process policies. The same offsets do not apply to arm64e. This report proposes no patch bytes and makes no binary changes.

### Recommended Option A design

Use **one small native Foundation/Security service**, started and supervised by the supported jailbreak's launchd environment. Avoid a periodic shell/Python process chain for the deployment path when a native service can use the same serializer and time APIs as the readers. Apple's [launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) establishes supervision/KeepAlive and foreground-job behavior; it is an OS X reference, so jailbreak-specific loading/entitlements still need validation.

The service should:

1. **Refresh immediately at service startup**, including after reboot/restart. Generate a fresh signed payload and use the phone's `NSProcessInfo.systemUptime` for its receipt marker and `NSDate` epoch time for issue/expiry. Do not copy host uptime, elapsed process runtime, or server epoch time into `received_uptime`. Do not assume a persisted marker belongs to the current boot.
2. **Publish a 90-second lease about every 45 seconds** on a serial execution path. At a successful 45-second cadence, nominal remaining lifetime is about 45 seconds; a 60-second cadence leaves only about 30. Integer timestamp truncation and processing delay reduce the wall-clock margin slightly. Schedule against monotonic deadlines, measure the remaining signed lifetime, and retry recoverable failures while budget remains; no timer is a hard real-time guarantee.
3. **Keep work out of injected host threads.** Serialization, RSA signing and filesystem publication belong in the service, not additional SpringBoard/mediaserverd timers or callbacks. The existing readers still perform their own validation; this architecture does not eliminate that cost or guarantee host crash freedom.
4. **Use one atomic publication transaction.** Validate the entire typed payload and signature before publication. Write a unique temporary file in the same resolved directory, apply owner/mode and compatible file-protection metadata, finish/close it, then rename it over the final path; notify only after success. Never truncate the live plist or delete it before replacement. Same-filesystem rename provides namespace replacement semantics; durable write requirements are separate. See Apple's [rename manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/rename.2.html).
5. **Resolve paths through the active RootHide environment.** Service and root/mobile readers must reach the same shared file after rerandomization. Preserve actual `.roothidepatch` links where applicable; a text `.symlink` file is not the runtime marker. Confirm receipt directory/file permissions for both mobile injected hosts and the root daemon. Atomic rename creates a new inode, so old metadata is not automatically inherited.
6. **Send `notify_post("com.vcnext.capability.changed")` after commit**, checking the return status. Notifications are a refresh hint, not the lease itself or an acknowledgement; consumers must read committed state. Apple's [notify manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/notify.3.html) documents the post/registration mechanism. Overlay polling is a fallback, but not a guaranteed latency bound.
7. **Coordinate all writers.** A separate refresher must not race the original network daemon, an app session writer, or logout/revocation cleanup. Choose one publication owner and a coherent identity/session model. Otherwise a perfectly formed local lease can be overwritten or removed by another component. Startup scripts currently delete old lease state intentionally.
8. **Recover safely from delay, lock/sleep and clock changes.** Refresh as soon as runnable after wake/restart and respond to relevant time changes. Use appropriate file-protection/access behavior. A stale lease must be allowed to expire; editing only `received_uptime` cannot extend the signed wall expiry. Root privileges and KeepAlive do not guarantee execution during every sleep or resource-pressure interval.
9. **Handle signing-key custody deliberately.** Local signing requires access to a signing key trusted by the readers; any device holding a shared authority private key also holds that authority's issuance capability. For centrally controlled licensing prefer off-device signing, with the device acting only as the renewal client. Do not confuse a TLS private key, a device P-256 identity key, and a lease-authority key.

On write/signing failure, preserve the last complete lease, record a bounded diagnostic and retry under a capped policy. Do not repeatedly restart the camera host as a renewal mechanism. Supervision can recover a stopped service; it does not prove that a hung service, inaccessible key, invalid data, or persistent write failure will resolve within 90 seconds. A gap longer than the signed lifetime necessarily permits the unchanged readers to disable features.

For Option C, the same local publication/clocks/supervision requirements apply. LAN/VPS signing adds network timing and outage dependence; an off-device server cannot supply the phone's boot uptime. A local HTTP authority still needs both a server and writer/client, whereas direct local signing avoids that extra transport when offline availability is the objective. An offline gap exceeding the remaining signed lifetime cannot be covered by caching an already expired 90-second lease.

## 6. Required corrections and release evidence

The current updated specs should retain the following distinctions:

- **Camera active reader: 95 seconds; Camera exported master: 185 seconds.** A table that assigns Camera only a 185-second limit remains inaccurate for normal configuration capability checks.
- **Correct field classes do not prove functional grants.** Record the exact capability identifiers used by every intended feature/process.
- **Correct Camera section hash does not prove the runtime digest target.** Reconcile mainBundle-based hashing and consumers before making a universal self-integrity claim.
- **RootHide mechanisms were source-verified; device compatibility was not.** The progress tracker’s “verified” label must not be read as a passed A11 deployment test.
- **TLS, encryption inverse, lease signature, identity/session binding and reader acceptance are separate checks.** Passing one does not imply all the others.

To change this verdict to a native acceptance pass, obtain: iOS 15/16 Foundation golden-byte fixtures for the generated payload; `SecKeyVerifySignature` results under the intended installed authority; the actual phone uptime/epoch and accepted envelope; exact capability grants verified in Camera/Overlay; coherent App/Network/Stream identity and renewal behavior; loaded arm64 slice and RootHide dependency versions; and a controlled A11 run spanning multiple renewals, expiry recovery, lock/sleep/wake, service restart, respring and reboot. Capture logs, process exits/crashes and frame/IPC continuity. A twelve-hour or similar soak can supply empirical stability evidence; it still does not prove an absolute zero-crash property.

**Task status:** generator execution/inspection, source review, Camera/Overlay static cross-check, crypto inverse fixtures and loopback transport probes are complete. Actual Foundation/iOS execution, on-device renewal implementation and deployment testing were outside this observational phase and remain unverified.
