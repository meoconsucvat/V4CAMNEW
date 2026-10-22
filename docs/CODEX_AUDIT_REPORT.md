# VCNext 0.16.73 build 37: overlay and lifecycle audit

Audit date: 2026-10-19 (Asia/Saigon). Scope: observational static analysis of the supplied package. No iOS binaries were executed, patched, re-signed, or deployed. This report establishes code paths and compatibility constraints; it does **not** establish zero crashes, zero regressions, or deployment readiness on a physical device.

## Findings that affect the existing design

1. **The exported master verifier at arm64 VA `0xb0f8` has no observed internal callers.** The actual overlay UI uses `_VCN583d21a4038aaf46dd3e` at `0xc3d8`, then a separate lease reader at `0xc48c`, then RSA verification at `0xa648`.
2. **Capabilities are checked both periodically and on notifications.** A repeating, main-run-loop `NSTimer` runs every 1.0 second, and three Darwin notifications also request a refresh. The 100 ms dispatch timer is a separate screen/color sampling facility.
3. **The live UI reader limits lease duration to 95 seconds.** The unused exported master has a different, 185-second duration limit. These numbers are duration limits, not equivalent grace windows or evidence that a ten-year lease works.
4. **The RSA verifier signs sorted-key JSON data, not binary-plist bytes.** Plist is the storage container. The existing generator's local sign/verify round-trip does not match this overlay verifier.
5. **No overlay-self-file integrity gate was found on the traced UI path.** There is a bundled digest helper, but it reads `NSBundle.mainBundle.executablePath` and hashes that file's selected `__TEXT,__text` section. This is not evidence that the overlay hashes its own signed dylib file.
6. **Missing/expired/incorrectly signed leases normally disable the UI without an explicit assertion.** Some malformed plist value types reach unchecked Objective-C selectors before signature verification and can raise an exception. Universal crash-free failure handling is therefore not supported by the static evidence.

RootHide mechanics and platform support are documented separately in [05_ROOTHIDE_ECOSYSTEM_COMPATIBILITY.md](05_ROOTHIDE_ECOSYSTEM_COMPATIBILITY.md).

## Identity, address convention, and reproducibility

All addresses below are **unslid virtual addresses within the named Mach-O slice**, unless explicitly labeled otherwise. They are not offsets into the complete FAT file. Here, the relevant file-backed sections have equal slice-relative VA and file offset. Thus arm64 VA `0xb0f8` is full-file offset `0x4000 + 0xb0f8 = 0xf0f8`. A live address additionally requires that image's ASLR slide.

| Artifact | SHA-256 |
|---|---|
| Original `VCNext-0.16.73-roothide.deb` | `7018a14aa4f82b36158af76cba2942c513a35d622a1e6e3015dc363e917fa88a` |
| Main `VCNextOverlay.dylib` (329,920 bytes) | `45c4ec6e948b7b6746a4f31a40a7db3f9203f47e59cf4f5b244012d72e2f71f8` |
| `pkgmirror/.../VCNextOverlay.dylib` (330,896 bytes) | `25f3eb4c031d24ef0aa21393bbc7927455b2803dae568c58c6617bd2a1b0a58e` |

Both files contain arm64 subtype `0` and arm64e subtype `0x80000002`. FAT slice offsets are `0x4000` and `0x2c000`, respectively. The main file's two slice sizes are each `0x248c0`; the mirror's are each `0x24c90`. Their corresponding `__text` bytes are identical, although the complete files and slice hashes differ. That comparison does not establish equivalence of loader behavior or signatures.

Analysis used IDA/Hex-Rays through `mcp__ida_re` for the arm64 slice, independently corroborated with LIEF 0.17.6 and Capstone 5.0.8. REA's `open_binary` rejected this ARM-only FAT artifact on its Windows host with `FAT binary has no host-compatible x64 architecture`; the available IDA provider supplied the native analysis instead. The saved IDA outputs are direct provider evidence, not fabricated REA Evidence IDs.

The independent scan decoded every aligned instruction word in `__text`: 10,778 arm64 instructions and 11,420 arm64e instructions, with no undecoded words, for both main and mirror. Coverage of direct `B`/`BL` instructions is complete within these sections. Computed calls, external consumers of exported symbols, dynamic Objective-C dispatch, and loader-generated code remain separate limitations. The arm64e body was inspected as assembly, not independently Hex-Rays-decompiled.

Reproduce from the workspace root:

```powershell
python scripts/audit_overlay_static.py
python scripts/verify_audit_artifacts.py
```

These scripts write only derived evidence. [artifact_preservation.json](evidence/overlay/artifact_preservation.json) compares all **10 Mach-O members** in the original Debian data archive with their extracted copies and records byte identity for every member. The original archive also proves that its five markers are real `<binary>.roothidepatch` symlinks; the extracted `.symlink` text files are a representation of those links.

Primary evidence: [static_inventory.json](evidence/overlay/static_inventory.json), [arm64 assembly](evidence/overlay/main_arm64_text.asm), [arm64e assembly](evidence/overlay/main_arm64e_text.asm), [arm64 direct branches](evidence/overlay/main_arm64_direct_branches.json), and the focused IDA JSON files linked below. `function_inventory.json` / `all_funcs.json` contain a provider-returned partial function listing; complete raw scan bounds and function-start records are in `static_inventory.json`.

## 1. Master verifier callers and the real capability path

### 1.1 Callers of `0xb0f8`

The symbol table identifies `_VCN5d92c005b0c38441000a` at arm64 `0xb0f8` and arm64e `0xb754`. IDA's [xref query](evidence/overlay/verifier_xrefs.json) returned zero incoming references to arm64 `0xb0f8`. Independently, all four complete `__text` scans found **zero direct `B` or `BL` instructions** to the matching master verifier in either architecture or copy.

The supplemental raw 64-bit pointer scan finds the master's value in the Mach-O symbol table: arm64 slice offset `0x21d30`, arm64e `0x21d38`. These are `nlist_64.n_value` records in `__LINKEDIT`, not function-pointer callbacks. The export is retained, so an external consumer could theoretically resolve it. No such call is established here. The overlay's sole observed `dlsym` call (`0x6068`) resolves `CARenderServerRenderDisplay`, not this verifier.

The [full master decompilation](evidence/overlay/verifier_full.json) and [assembly](evidence/overlay/verifier.json) show:

```c
// Analyst reconstruction; names for parameters express inferred roles.
bool exportedMaster(lease, signature, accessToken, renewalToken, nextNonce,
                    expectedDeviceID, expectedThumbprint, NSError **error) {
    accessBinding  = sha256hex(UTF8(accessToken));  // calls at b208
    renewalBinding = sha256hex(UTF8(renewalToken)); // b264
    nonceHash      = sha256hex(UTF8(nextNonce));    // b2c0
    ok = verifyRSAJSON(lease, signature);          // b354 -> a648
    ok &= schemaVersionPurposeIssuerAudience(lease);
    ok &= matchesExpectedDeviceAndThumbprint(lease);
    ok &= matchesBuildAndBindings(lease, "37", accessBinding,
                                 renewalBinding, nonceHash);
    ok &= isNSArray(lease["capabilities"]);
    ok &= checkIssuedExpires(lease, 185.0);        // b5c0 -> af50
    if (!ok && error)
        *error = NSError("com.vcnext.security", 498,
                         "Capability lease verification failed");
    return ok;
}
```

The bindings are compared against hashes of supplied token/nonce text, not arbitrary UUIDs. At `0xb5b0`, `MOV X8,#0x4067200000000000` and the following `FMOV D0,X8` pass `185.0` to `0xaf50`. That helper also requires numeric `issued_at`/`expires_at`, `issued_at <= now + 120`, `expires_at > now - 5`, `expires_at > issued_at`, and `expires_at - issued_at <= suppliedLimit`. These are facts about this exported function, **not** the active UI reader's policy.

### 1.2 UI entry points

| arm64 instruction | Observed operation |
|---|---|
| `0x46e8` (`3c1f0094`) | `BL 0xc3d8` with capability `camera.controls` when floating control preference is enabled |
| `0x47b8` (`081f0094`) | `BL 0xc3d8` with capability `camera.color-sync` when that preference is enabled |
| `0x4db8` (`881d0094`) | `BL 0xc3d8` to guard command execution with `camera.controls` |
| `0xc3fc` | `BL 0xc48c`, loading/caching the current verified lease |
| `0xc414` / `0xc440` / `0xc450` | Obtain `capabilities`, require `NSArray`, send `containsObject:` for requested capability |
| `0xc9e4` (`19f7ff97`) | `BL 0xa648`, RSA verification after reader's schema/time checks |

See [refresh decompilation](evidence/overlay/decompile_0x4490.json), [capability check](evidence/overlay/decompile_0xc3d8.json), and [lease reader](evidence/overlay/full_0xc48c.json). A separate exported boolean helper at `0xcbc4` also calls `0xc48c`, returning whether a non-nil lease exists.

The active reader loads `/var/jb/var/mobile/Library/VCNext/CapabilityLease.plist` at `0xc59c`. It compares device identifiers to **top-level fields in that same stored lease envelope**, not to `AuthSession.plist` in this function. It does not call `0xb0f8` or read `binary_digest` on this path. That is a local observation, not proof that the other package components omit session, device, or digest checks.

## 2. Floating button lifecycle, notifications, and timers

### 2.1 Initialization and refresh

`__TEXT,__init_offsets` contains `0x4000`. That constructor checks the process name is `SpringBoard` (`0x4024`–`0x4038`) and the OS major version is in **15 through 17 inclusive** (`0x408c`–`0x40a4`). This package-level allowance does not imply that every requested jailbreak supports each OS version.

The constructor parses the numeric family in `uname().machine`. Families `iPhone9,*` through `iPhone14,*` get an 8-second initial delay and up to five 1-second activation retries (`0x4134`–`0x4188`). Other/unparsed machines use 45 seconds and one retry. This includes both `iPhone10,*` and `iPhone12,*`; it is not an A13-only branch. The retry path (`0x41bc`) waits for an active application/window scene, then eventually proceeds after its retry budget. Source reconstruction: [constructor](evidence/overlay/decompile_0x4000.json), [activation retry](evidence/overlay/decompile_0x41bc.json).

Initialization at `0x4944` runs once on the main thread and registers application activation, scene activation, orientation, and protected-data lock/unlock notifications. It sets the UI-ready flag at `0x4b78`, creates the repeating timer, then calls refresh `0x4490` immediately at `0x4bb4`.

Refresh `0x4490` marshals itself to the main queue when needed (`0x44b0`, `0x45bc`). Before UI readiness it records a pending refresh rather than constructing views (`0x44c4`, `0x45c4`). It reloads settings and `CameraConfig.plist`, then combines the selected preferences with capability checks. Missing or incorrectly typed `CameraConfig` booleans fall back to the settings object's values.

If enabled, `-[VCN6abc1e316393d5712ffe setSystemWideEnabled:]` at `0x7134` selects a window scene, creates an overlay window/controller as needed, and invokes `installOverlayInView:` (`0x74e0`). The button is created with `UIButton buttonWithType:` at `0x77e4`, sized 44 x 44, assigned action `togglePanel` (`0x7ae0`), given `dragFloatingButton:` (`0x7afc`), and retained by `setFloatingButton:` (`0x7b54`). If disabled, the same manager calls `clearOverlay` at `0x7294`.

`clearOverlay` (`0x6fe0`) hides its window (`0x7004`), removes the view (`0x7024`), and clears retained view/button/panel/controller/window references (`0x7038`–`0x7074`). The lock state disables user interaction and hides accessibility elements for the floating button; the color-picker controller additionally hides/cancels sampling when locked. Lock handling is distinct from lease validation.

### 2.2 Notifications and the two timers

Observer installation at `0x4400` registers the same callback `0x448c` for:

- `com.vcnext.floating.changed`: registration `0x4438`.
- `com.vcnext.state.changed`: registration `0x445c`.
- `com.vcnext.capability.changed`: registration `0x4488`.

`0x448c` tail-branches to refresh `0x4490`. `com.vcnext.auth.session.changed` exists as a string but is **not** registered by this observer installer. String presence alone is not a subscription.

| Timer | Setup and callback | Purpose |
|---|---|---|
| Repeating **1.0 s** `NSTimer` | `0x4ba0: FMOV D0,#1.0`; `0x4ba4: MOV W2,#1`; `0x4ba8: BL` scheduled-timer selector; block `0x18520` invokes `0x4ff4`, which branches to `0x4490` | Refresh settings and capabilities; remove overlay after invalidation/expiry on an eligible refresh |
| Dispatch source **100 ms**, 10 ms leeway | `0x6464`: `dispatch_source_set_timer(...,100000000,10000000)`; event block calls `0x64d8` | Screen/color sampling (`vcnd835274b52391ae8c637`), separate from periodic lease refresh |

Timer callbacks run subject to scheduling/run-loop behavior. One second is the configured interval, not a proven maximum hide latency during UI tracking, suspension, load, or notification delays.

Evidence: [observer setup](evidence/overlay/decompile_0x4400.json), [UI initialization](evidence/overlay/full_0x4944.json), [1-second callback](evidence/overlay/full_0x4ff4.json), [sampling setup](evidence/overlay/decompile_0x63c8.json), [sampling callback](evidence/overlay/decompile_0x64d8.json).

## 3. The UI lease reader: exact constraints and pseudocode

The `0xc48c` reader protects its shared positive cache using `objc_sync_enter/exit`. A cached lease is reused only if all the following hold: uptime has not moved backward; less than 0.5 seconds elapsed since its last disk validation; uptime remains before its monotonic expiry; and wall-clock time remains before its epoch expiry (`0xc534`–`0xc56c`). A failure clears the positive cache. Nil failures do not satisfy the cache fast path.

```c
// Analyst pseudocode, reconstructed from c48c..cb88; not original source.
NSDictionary *currentUILease(void) {
    double uptime = processInfo.systemUptime;
    synchronized(cacheLock) {
        double now = NSDate.date.timeIntervalSince1970;
        if (cache && uptime >= lastCheck && uptime-lastCheck < 0.5 &&
            uptime < monotonicExpiry && now < wallExpiry)
            return cache;

        lastCheck = uptime;
        cache = nil;
        monotonicExpiry = wallExpiry = 0;
        NSDictionary *envelope = loadDictionary(leasePath);
        NSDictionary *lease = dictionaryOrNil(envelope[@"lease"]);
        NSString *signature = stringOrNil(envelope[@"signature"]);
        NSNumber *received = numberOrNil(envelope[@"received_uptime"]);
        NSNumber *issued = numberOrNil(lease[@"issued_at"]);
        NSNumber *expires = numberOrNil(lease[@"expires_at"]);
        double ttl = expires.doubleValue - issued.doubleValue;

        // Several messages below lack class checks in the actual code.
        bool ok = lease && signature.length && received && issued && expires;
        ok = ok && [lease[@"version"] integerValue] == 2;
        ok = ok && [lease[@"purpose"] isEqualToString:@"capability.lease"];
        ok = ok && [lease[@"issuer"] isEqualToString:expectedIssuer()];
        ok = ok && [lease[@"audience"] isEqualToString:expectedAudience()];
        ok = ok && [lease[@"build"] isEqualToString:expectedBuild()];
        ok = ok && [lease[@"device_id"] isEqualToString:envelope[@"device_id"]];
        ok = ok && [lease[@"device_key_thumbprint"]
                          isEqualToString:envelope[@"device_key_thumbprint"]];
        ok = ok && isNSArray(lease[@"capabilities"]);
        ok = ok && ttl > 0 && ttl <= 95.0;
        ok = ok && uptime-received.doubleValue >= 0;
        ok = ok && uptime-received.doubleValue < ttl;
        ok = ok && expires.doubleValue > now;
        ok = ok && verifyRSAJSON(lease, signature); // c9e4 -> a648
        if (ok) {
            cache = lease;
            monotonicExpiry = received.doubleValue + ttl;
            wallExpiry = expires.doubleValue;
        }
        return cache;
    }
}
```

For ordinary finite timestamps, these conditions directly describe the acceptance path. The `95.0` constant is constructed as IEEE-754 `0x4057c00000000000`:

```asm
; arm64 VA       raw bytes   instruction
0xc990           6821601e    FCMP D11,#0.0
0xc994           e8d79f1a    CSET W8,GT
0xc998           0900d8d2    MOV X9,#0xc00000000000
0xc99c           e90ae8f2    MOVK X9,#0x4057,LSL#48
0xc9a0           2001679e    FMOV D0,X9
0xc9a4           6021601e    FCMP D11,D0
0xc9a8           e883881a    CSEL W8,WZR,W8,HI
0xc9b4           41090054    B.NE 0xcadc
0xc9c0           eb080054    B.LT 0xcadc       ; negative uptime delta
0xc9c8           a5080054    B.PL 0xcadc       ; delta >= ttl
0xc9d8           0d080054    B.LE 0xcad8       ; wall expiry reached
0xc9e4           19f7ff97    BL 0xa648         ; verify signature
```

The arm64e reader starts at `0xcba8`; its corresponding 95-second constant is at `0xd0b8`–`0xd0c8`, with the same constant bytes and comparisons, followed by `0xd104: BL 0xac90`. Corresponding `__text` bodies in pkgmirror match their main counterparts byte-for-byte.

### Storage format versus signed message

At `0xa694`, `MOV W3,#2` sets the options argument to `NSJSONSerialization dataWithJSONObject:options:error:` called at `0xa69c`. The decoded selector and class are in [RSA helper decompilation](evidence/overlay/full_0xa648.json). `2` is the `sortedKeys` writing option, as corroborated by [Foundation's option definition](https://github.com/swiftlang/swift-corelibs-foundation/blob/main/Sources/Foundation/JSONSerialization.swift#L25-L36). Base64 decoding follows at `0xa6d4`; `SecKeyVerifySignature` is called at `0xa778` with `kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256`.

Thus the outer plist's XML/binary encoding is not the signed byte sequence. Do not treat Python `plistlib.dumps(...,FMT_BINARY)` or an arbitrary JSON encoder's sorted output as automatically equivalent to Foundation's serialization. Byte-for-byte number, Unicode, and escaping behavior needs an iOS fixture before a cross-language server can claim compatibility. No replacement authority or signing implementation was built in this audit.

## 4. Secondary hashes and re-signing sensitivity

The complete import and direct-call scan finds exactly three `_CC_SHA256` call sites in each architecture:

| Function role | arm64 function / SHA call | arm64e function / SHA call | Input actually hashed |
|---|---|---|---|
| Generic bytes-to-hex | `0xa514` / `0xa548` | `0xab44` / `0xab7c` | Caller-supplied bytes, including token/nonce strings and executable text bytes |
| TLS key pin check | `0xa7e4` / `0xa8ac` | `0xae30` / `0xaefc` | `SecKeyCopyExternalRepresentation` of a trust object's key |
| Generic NSData-to-hex export | `0xbc78` / `0xbd00` | `0xc330` / `0xc3bc` | Caller-supplied `NSData`; no internal callers observed |

References and full bodies: [SHA helper](evidence/overlay/decompile_0xa514.json), [TLS helper](evidence/overlay/decompile_0xa7e4.json), [data hash helper](evidence/overlay/decompile_0xbc78.json), [helper xrefs](evidence/overlay/digest_helpers_xrefs.json). HMAC and AES imports also exist for the bundled encrypted-data helpers; their presence alone is not a self-integrity check.

The executable-digest path is present:

```text
export _VCNd701a509fa148a7ce9f7 @ a278
  -> dispatch_once @ e7d0
  -> initializer @ a2bc
     -> [NSBundle mainBundle] @ a2e0
     -> executablePath @ a2f0
     -> NSData dataWithContentsOfFile:options:error: @ a328
     -> Mach-O/FAT parsing @ b990
     -> select __TEXT,__text using section offset and size
     -> SHA256(hex) @ a3fc -> a514
```

The parser checks 64-bit ARM CPU type and walks `LC_SEGMENT_64` (`0x19`), looking for segment `__TEXT` and section `__text` (`0xbac8`–`0xbb14`). Its FAT walk selects a matching ARM64 record in archive order; it does not prove selection of the running CPU subtype. It hashes only the selected section, not the whole FAT file, whole slice, or `LC_CODE_SIGNATURE` blob. Evidence: [digest initializer](evidence/overlay/full_0xa2bc.json), [range parser](evidence/overlay/macho_digest_range.json).

An internal reference at `0xad18` obtains that digest for the exported `auth.challenge` validator `_VCN5bbd0dd44b5ff4202184` (`0xaa08`), which compares a `binary_digest` field at `0xad2c`. No internal callers of that challenge validator were observed; it is not in the traced overlay visibility path. In an injected process, `mainBundle` ordinarily describes the host executable, so treating this code as hashing `VCNextOverlay.dylib` would be an unsupported inference.

**Bounded conclusion:** no internal overlay-self-file hashing/abort mechanism triggered by re-signing was identified. Ordinary replacement of signature blobs outside `__text` would not change this helper's selected bytes. RootHide runtime instrumentation may change mapped instructions or CFStrings; the helper reads file bytes, and no blanket immunity to other consumers or different runtime versions follows. External use of exports, undiscovered computed paths, and actual installed patch modules remain runtime unknowns.

## 5. Lease failure behavior and stability limits

| Input/state | Observed static path | Expected UI result / limitation |
|---|---|---|
| Missing, unreadable, or non-dictionary lease file | Reader gets nil; required-value checks fail; positive cache remains nil | Capability false; refresh calls `setSystemWideEnabled:false`, which clears overlay |
| Missing signature, missing numeric `received_uptime`, nonnumeric issued/expiry, wrong capabilities container | Explicit class/presence guards reject | Same disable/clear path; no explicit assertion or process termination |
| Expired lease, negative uptime delta, duration >95 s | Time guards reject before RSA | Same disable/clear path on next eligible refresh |
| Correctly typed schema but invalid signature/base64/certificate | RSA helper returns false | Same disable/clear path |
| Wrong capability names in an otherwise accepted lease | `containsObject:` false | Requested control disabled; e.g. `virtual_camera` is not `camera.controls` |
| Wrong object type for `version`, `purpose`, `issuer`, `audience`, `build`, or compared IDs | Some selectors are sent without an `isKindOfClass:` check before RSA | **Potential Objective-C exception**, not a guaranteed silent failure |
| Path translation/module loading fails | See RootHide report; lease read can fail or loader may fail earlier | Must distinguish silent missing-file UI behavior from PatchLoader assertions/load failures |

An illustrative malformed case is an array at `lease["purpose"]`: if earlier presence/version checks pass, the code sends `isEqualToString:` at `0xc81c` before signature verification (`0xc9e4`). An incompatible receiver can raise an unrecognized-selector exception. Likewise, numeric `build` does not satisfy the reader's string-oriented message at `0xc8c4`. There is no local exception recovery demonstrated around this validation path. These are static exception risks, not reproduced SpringBoard crashes.

The ordinary failure path does not call `assert`, `abort`, `exit`, or `kill`; those APIs are absent from the overlay import inventory. `___stack_chk_fail` is imported and used for compiler stack-canary checks, including the master's epilogue at `0xb724`. It is not a lease rejection assertion. `_Unwind_Resume` landing pads perform cleanup/rethrow and do not establish a safe catch-and-hide policy.

The exported master can populate `NSError` code 498 on failure (`0xb610`–`0xb68c`); that string is not a fatal assertion. The active UI reader returns nil without that error object. The active reader does not itself delete `CapabilityLease.plist` on failure; the separately exported session-removal helper at `0xc10c` does remove session/lease files, but is not called from this reader.

## 6. Corrections to existing workspace claims

Existing documents/scripts were left unchanged as requested. The following claims must be reconciled before implementation:

| Existing claim/artifact | What this build's overlay demonstrates |
|---|---|
| `docs/00_ARCHITECTURE.md`: notification synchronization without polling | `0x4ba8` installs a repeating 1-second UI timer |
| `docs/03...`: master verifier controls all paths / 185 s window | Overlay UI uses `0xc48c`, with a separate 95 s maximum duration; master remains exported without observed internal callers |
| `docs/03...`: binary-plist signature message | `0xa648` serializes JSON with options `2` |
| `docs/03...`: arbitrary UUID session/renewal bindings | Master hashes supplied token strings and compares those hashes |
| `docs/03...` / `docs/06...`: ten-year lease and ISO timestamp examples | UI requires numeric epoch fields and a duration <=95 s, plus a same-boot `received_uptime` envelope field |
| `docs/06...`: capability boolean dictionary | UI requires an `NSArray` containing exact capability identifiers such as `camera.controls` and `camera.color-sync` |
| `scripts/lease_generator.py` local verification | Signs/verifies binary-plist bytes against its own implementation; missing envelope fields and incompatible containers/times mean this is not native-overlay validation |
| Generator hashes fixed FAT range | Overlay's bundled digest helper parses section bounds and hashes selected executable `__text`; a hardcoded whole-slice range is a different algorithm |
| `docs/04...` / `postinst` comments: markers imply boot-time header patch/re-sign | See source-grounded RootHide report; runtime path instrumentation and package conversion/signing are distinct |

In particular, disabling a refresher and providing a long-lived static lease is **not supported as a working design by this overlay audit**. A key replacement that preserves instruction bytes also does not, by itself, establish compatible serialization, duration, entitlement, path translation, or PAC behavior.

## 7. Remaining device validation and task coverage

| Requested question | Status |
|---|---|
| Internal callers of arm64 `0xb0f8` | Answered within static bounds: zero IDA xrefs and zero direct branches in both architectures/copies |
| Floating button initialization | Answered: constructor -> activation/main-thread initialization -> refresh -> manager -> button creation |
| Timer versus notification validation | Answered: both; active reader differs from exported master |
| Secondary self-integrity hashes | Answered with bounded negative result and all imported SHA call sites; executable-text helper documented |
| Missing/invalid lease failure modes | Answered statically, with malformed-type exception risk distinguished from ordinary rejection |
| Zero crashes/regressions on A11/A12+ | **Unverified:** physical runtime evidence absent |

For deployment evidence, capture the exact iOS build, hardware identifier, active slice, jailbreak/bootstrap build, installed PatchLoader/AutoPatches versions, code signatures, mapped image paths, and crash logs. Check fresh install and upgrade, SpringBoard/daemon restart, lock/unlock, scene/orientation changes, expiry/removal/invalid signatures, typed malformed fields in an isolated test environment, and delayed/missing Darwin notifications. On each supported environment, confirm the app/overlay/camera/daemons resolve the same IPC and lease paths under their own identities. Camera/mediaserverd hook stability and private selectors require their own device observations; this overlay-only static audit cannot certify them.
