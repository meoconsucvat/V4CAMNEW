# VCNext build 37: A12–A16 / arm64e compatibility and regression audit

Audit date: 2026-10-20, Asia/Saigon. Scope: the supplied customized package, current workspace server and installer source, independent disassembly, and pinned upstream platform sources.

**Verdict: the suspected arm64-versus-arm64e lease-digest incompatibility is not present in the inspected build. The package preserves the original arm64e code and authentication metadata. These findings support controlled A12+ testing, but do not establish universal crash-free deployment. The historic A13 crash cause is unresolved, and the local server source has separate authentication and multi-device defects.**

The successful A11/iOS 16 installation is user-reported physical-device evidence. This audit did not connect to that device or the VPS, execute an iOS binary, alter a product binary, deploy server changes, or rebuild a package. All proposed source changes below remain review artifacts. The desired scope also needs correction: iPhone 15/15 Plus shipped with iOS 17; iPhone 15 Pro/Pro Max use A17 Pro and shipped with iOS 17. They are outside an A12–A16, iOS 15/16, Dopamine **2** certification. [Apple iPhone 15](https://www.apple.com/newsroom/2023/09/apple-debuts-iphone-15-and-iphone-15-plus/), [Apple iPhone 15 Pro](https://www.apple.com/newsroom/2023/09/apple-unveils-iphone-15-pro-and-iphone-15-pro-max/).

## 1. Artifact identity and what was actually verified

The independent audit reads both Debian archives, extracts only known executables into the evidence directory, parses each Mach-O slice, compares the original and customized text, and recomputes all CodeDirectory code-page hashes. It does not import the production server or read its private key/customer database.

| Check | Observed result |
| --- | --- |
| Original package SHA-256 | `7018a14aa4f82b36158af76cba2942c513a35d622a1e6e3015dc363e917fa88a` |
| Customized package SHA-256 | `0a09a9561eb4e6c181d5d52fdb46846e63da1082d4d123a3f95b92ee8ca8b9b6` |
| Executables / slices / CodeDirectories | **10 / 14 / 21** |
| Code-page mismatches | **0** |
| All original/custom `__TEXT,__text` comparisons | **Byte-identical** |
| Headers/load commands and dyld fixup/binding data | **Unchanged** |
| Sections whose names contain `auth` | **Unchanged** |
| Current `extracted/data` executables versus custom package | **All match** |

The main Camera FAT file currently hashes to `901319d0cf57ff00749fbb4e3ac4095923c5cce2d428475486fd5f386a8a6e6e`; Overlay to `b13d157842de570f3a1799d8aa9c09973b83b2c82c478bebe0ae685a2177f2a7`. These are customized whole-file hashes, not the older original-file identities quoted in previous reports.

| Image | Slice / FAT offset | `__TEXT,__text` SHA-256 |
| --- | --- | --- |
| Camera | arm64 / `0x4000` | `d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943` |
| Camera | arm64e / `0x34000` | `60e7f7328417c91f4dd21bf27077d5196b11d8aa698ce7f0c6f78217736a6bba` |
| Overlay | arm64 / `0x4000` | `dd79aca37347e0f26ad06986845bfdc9893d6d71ccbe633efb605c13f8f820ce` |
| Overlay | arm64e / `0x2c000` | `f0c96a42eea5ca08854b4dec39a5319fdd3a4ad64de09c2557d8a68087d3f90a` |
| App | thin arm64 | `4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2` |
| NetworkDaemon | thin arm64 | `d3a8bf7ff5b061c8bfc975c93713b5adfbdd441bbe64e982e587976e82d8951f` |
| StreamDaemon | thin arm64 | `527ef2086c47e61fc9b2a51a5130ce869f2abda44041a5ebeb6de186a62b2611` |

Camera/Overlay arm64e subtype is `0x80000002`, including the arm64e ABI feature bit. App and both daemons are `CPU_TYPE_ARM64=0x0100000c`, subtype `0`. Their package-manager architecture label is not a claim that every executable is compiled arm64e.

Evidence: [artifact manifest](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/artifact_manifest.json), [reproducible archive/ABI/page-hash audit](/C:/Users/Admin/Desktop/vcnextnew/scripts/audit_arm64e_artifacts.py), [PAC inventory](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_static_inventory.json). Clean code-page hashes establish this static invariant; AMFI admission, loaded-image selection, runtime rewriting and PAC correctness remain separate checks.

### Address convention

Dylib addresses below are unslid virtual addresses within the named slice, image base zero. Their FAT offsets are listed above; do not add a FAT offset to a runtime PC. App/daemon addresses include their image base `0x100000000`. Opcode bytes are shown in file order. A decompiler's assignment marker may follow a `BL`; the raw instruction listing determines the call address.

## 2. Vector 1: the lease digest is not a Camera architecture selector

### 2.1 Camera and Overlay active readers

**Neither active reader reads or compares `lease["binary_digest"]`, in either architecture.** The corresponding exported lease masters also omit that comparison. This conclusion comes from full function reconstruction and literal/branch/fixup cross-references, rather than an absent import or a string search alone.

| Image / architecture | Active local reader | Capability wrapper | Exported lease master | RSA JSON verifier |
| --- | --- | --- | --- | --- |
| Camera arm64 | `0x121b0` | `0x120fc` | `0x10e1c` | `0x1036c` |
| Camera arm64e | `0x1287c` | `0x127c4` | `0x11428` | `0x10964` |
| Overlay arm64 | `0xc48c` | `0xc3d8` | `0xb0f8` | `0xa648` |
| Overlay arm64e | `0xcba8` | `0xcaf0` | `0xb754` | `0xac90` |

The active contract reconstructed for both images and architectures is:

```text
lease     = envelope["lease"]              // NSDictionary
signature = envelope["signature"]          // nonempty NSString
received  = envelope["received_uptime"]      // NSNumber
issued    = lease["issued_at"]              // NSNumber
expires   = lease["expires_at"]             // NSNumber
require version.integerValue == 2
require purpose == "capability.lease"
require issuer == "vcnext-main", audience == "vcnext-ios", build == "37"
require lease.device_id == envelope.device_id
require lease.device_key_thumbprint == envelope.device_key_thumbprint
require capabilities is NSArray
ttl = expires.doubleValue - issued.doubleValue
require 0 < ttl <= 95.0
require 0 <= systemUptime - received.doubleValue < ttl
require wallClockNow < expires.doubleValue
require RSA_PKCS1_SHA256_Verify(sortedJSON(entire lease), signature, Tag3)
return lease; otherwise return nil
```

The wall-clock test is essential: matching the awake-time clock alone does not preserve a lease through an arbitrarily long sleep. The positive cache lasts less than 0.5 seconds and also respects both expiry clocks.

Selected exact arm64e instructions:

| Operation | Camera | Overlay |
| --- | --- | --- |
| `fcmp d11,#0`, bytes `6821601e` | `0x12d84` | `0xd0b0` |
| Construct 95.0: `0900d8d2`, `e90ae8f2` | `0x12d8c`, `0x12d90` | `0xd0b8`, `0xd0bc` |
| `fcmp d11,d0`, `6021601e` | `0x12d98` | `0xd0c4` |
| `fsub d0,d8,d10`, `00396a1e` | `0x12dac` | `0xd0d8` |
| Reject negative age | `0x12db4: 6b090054` | `0xd0e0: 6b090054` |
| `fcmp d0,d11`, `00206b1e` | `0x12db8` | `0xd0e4` |
| Reject age >= TTL | `0x12dbc: 25090054` | `0xd0e8: 25090054` |
| Compare expiry to wall clock, `0020691e` | `0x12dc8` | `0xd0f4` |
| Reject expired wall time, `ad080054` | `0x12dcc` | `0xd0f8` |
| `BL` RSA verifier, `e3f6ff97` | `0x12dd8 -> 0x10964` | `0xd104 -> 0xac90` |

The version/string fields do not all receive independent class checks before `integerValue`/`isEqualToString:`. The valid server schema must remain typed correctly; these functions do not prove that every malformed local plist fails without an Objective-C exception. The reader checks an NSArray, not every element or all five capabilities simultaneously. Feature wrappers check membership of their specific string.

### 2.2 Master verifier reachability and the separate challenge check

The lease master checks the full RSA signature, schema, identity, build, capabilities array, and hashes of the access token, renewal token and next nonce. Its wall-clock helper allows duration up to **185.0 seconds**; the active local readers separately impose **95.0 seconds**. The master does **not** compare `binary_digest`.

No immediate branch/call, decoded data/chained-fixup relocation, or reconstructed ADR(P)+ADD address formation targets the Camera/Overlay masters in any of their four text slices. Direct IDA arm64e code/data xref sets are also empty. Their observed render/overlay paths call the local reader, for example Camera arm64e `0xab68/0xab7c/0xab8c/0xabe0 -> 0x127c4 -> 0x1287c`, and Overlay `0x4724/0x47f4/0x4e6c -> 0xcaf0 -> 0xcba8`. They are exported symbols; another image could resolve them dynamically. Internal non-use is not global unreachability, but even their reconstructed master predicate contains no lease-digest equality.

There **is** a digest comparison in the separate `auth.challenge` verifier:

| Image / slice | Challenge verifier | Instruction forming the `binary_digest` key |
| --- | --- | --- |
| Camera arm64 | `0x1072c` | `0x10a38: 21e00091` |
| Camera arm64e | `0x10d2c` | `0x1103c: 21e00091` |
| Overlay arm64 | `0xaa08` | `0xad14: 21e00591` |
| Overlay arm64e | `0xb058` | `0xb368: 21e00591` |

These are the only recovered code references to that CFString in the respective slices. Do not transfer a challenge predicate to the lease reader. Likewise, a digest getter reading `NSBundle.mainBundle.executablePath` is not automatically a comparison against the injected dylib's own section.

The RSA serializer covers the **entire** dictionary. An ignored semantic member remains signed: changing a digest value without regenerating the signature still fails authentication.

Evidence: [complete reader findings and instruction tables](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/readers_findings.md), [branch/fixup/CFString results](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/readers_static_checks.json), [Camera arm64e reader](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/readers_camera_e_1287c.json), [Camera arm64e master](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/readers_camera_e_11428.json), [Overlay arm64e reader](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/readers_overlay_e_cba8.json), [Overlay arm64e master](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/readers_overlay_e_b754.json).

### 2.3 NetworkDaemon and StreamDaemon: newly traced consumers

The daemon audit closes a gap left by merely looking at their shared exported verifier names:

| Binary | Relevant path | Digest result |
| --- | --- | --- |
| NetworkDaemon | HTTP response callback `0x100005344`; `0x100005718: 49080094 BL 0x10000783c` calls the lease master | Actual active response master does not compare lease `binary_digest` |
| NetworkDaemon | Local reader `0x100008bd0`; `0x100009128: 19f7ff97 BL 0x100006d8c` verifies RSA | Same 95-second/identity/two-clock local contract; no lease-digest comparison |
| StreamDaemon | Link gate `0x100004c08`; `0x100004c20: 650e0094` and `0x100004c30: 610e0094` call capability wrapper `0x1000085b4` for `camera.fake-frame` and `camera.obs` | Uses local capability reader, not an architecture digest equality |
| StreamDaemon | `0x1000085d8: 24000094 BL 0x100008668`; reader calls RSA at `0x100008bc0: 19f7ff97 -> 0x100006824` | Same local 95-second contract; no lease-digest comparison |
| StreamDaemon | Exported lease master `0x1000072d4` | No internal xrefs found; full master also omits digest comparison |

StreamDaemon's sole `binary_digest` CFString code xref is in its **challenge** verifier `0x100006be4`, through the ADRP at `0x100006eec`; that exported challenge verifier has no observed internal callers. NetworkDaemon additionally reads `AuthSession["binary_digest"]` to build outbound proofs and `X-App-Digest`; this is the app/session digest, not a lease-Camera comparison.

NetworkDaemon's successful callback selects returned tokens/nonce/lease/`lease_signature`, verifies token bindings, performs a session freshness guard, writes AuthSession, then calls capability publication at **`0x100005870: 220c0094 BL 0x1000088f8`**. Its main timer is already **30 seconds**, first fire after 10 seconds, leeway 3 seconds (`0x100004238`, interval `0x6fc23ac00` ns), with session-change notifications as additional triggers. An extra 45-second renewal writer is not required to solve CPU compatibility and would introduce another writer to coordinate.

Evidence: [Network master](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/network_master.json), [Network response callback](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/network_0x100005344.json), [Network request constructor](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/network_0x1000042e4.json), [Network local reader](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/network_active_reader.json), [Network timer](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/network_0x100004138.json), [Stream gate](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/stream_0x100004c08.json), [Stream reader](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/stream_0x100008668.json), [Stream xrefs](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/stream_xrefs.json).

**Answers 1.1–1.3:** a valid signed lease carrying the existing `d8e4...` member is not rejected by the inspected arm64e Camera/Overlay or StreamDaemon because Camera arm64e hashes to `60e7...`. No digest-switch binary patch is needed. Keep the correct **app** digest in signed login challenges. Incorrect signatures, schema, identity, capability membership, clock values or renewal can still disable features independently.

## 3. Vector 2: compiled PAC support and hook stability

### 3.1 The arm64e build actually uses authenticated pointers

| Instruction family in text | Camera arm64e | Overlay arm64e |
| --- | ---: | ---: |
| `pacibsp` | 157 | 150 |
| `autibsp` | 70 | 101 |
| `retab` | 89 | 63 |
| `pacda` / `pacia` | 9 / 9 | 13 / 13 |
| `paciza` | 7 | 1 |
| `blraaz` / `blraa` | 2 / 2 | 1 / 1 |
| `braa` in authenticated import stubs, counted separately | 163 | 74 |

The arm64 text slices contain none of these PAC-family instructions. No `autiza` or `xpaci` was observed in the inspected executable text/stub sections. Representative Camera arm64e bytes:

```text
0x4000  7f2303d5  pacibsp
0x4214  1001c1da  pacia x16,x8       // delayed block invoke pointer
0x4258  ff0f5fd6  retab
0x59c8  f023c1da  paciza x16        // render replacement pointer
0x6840  bf0a3fd6  blraaz x21        // saved original render IMP
0x803c  1f093fd6  blraaz x8         // saved original output IMP
0x8180  28093fd7  blraa x9,x8       // authenticated block invoke
```

These establish compiled arm64e behavior. They do not establish that every external hook backend returns a pointer signed for the authentication convention expected by the caller.

### 3.2 Correct initializer and hook API

The supplied `sub_6694` is **not** the arm64e initializer. The actual chain is:

```text
arm64e __init_offsets -> 0x4000 constructor
  -> getprogname: only mediaserverd or cameracaptured proceeds
  -> signed delayed block 0x42a0
  -> 0x42c0: d6000094 BL VCNInstallCameraHooks(0x4618)
  -> dispatch_once block 0x46a0
  -> config/model/ABI-dependent class scanning and MSHookMessageEx
```

Arm64 `0x6694` is the render wrapper, corresponding to arm64e `0x66e0`. Arm64e `0x6694` is `08008052 MOV W8,#0` inside method-ABI checker `0x6480`. Reusing the same numeric offset between architectures would inspect or patch the wrong instruction.

Camera calls external **`MSHookMessageEx`**, through its authenticated Substrate import stub `0x13540`, at:

| arm64e call site | Bytes | Role |
| --- | --- | --- |
| `0x5dd0` | `dc350094` | Preview subclass hooks |
| `0x61b4` | `e3340094` | Named render/photo method hooks |
| `0x7930` | `042f0094` | BWNodeOutput/output subclass hooks |

Helper `0x6058` obtains the original implementation at BL `0x6190`, stores it at `0x619c`, requests a hook at `0x61b4`, and accepts a returned original/trampoline only when non-null and different from the replacement, storing it at `0x61c8`. The original is later invoked with `BLRAAZ`. There is no explicit strip-and-resign repair loop at these save/call sites. The installed provider behind the Substrate compatibility API must honor the arm64e IMP ABI.

The code checks private method argument counts and encodings, skips incompatible methods, tracks duplicate class/selector registrations, bounds subclass hook tables at 32 entries, and rescans when classes change. Named `renderSampleBuffer:forInput:` requires four arguments with void/object/selector/CMSampleBuffer-pointer/object types; output `emitSampleBuffer:` has its own three-argument check. These guards reduce specific ABI risks but do not prove private frame ownership, timing or every OS-specific pipeline implementation safe. No embedded Dobby hook API was identified in Camera/Overlay; Camera's observed Objective-C hooks use Substrate.

Evidence: [full PAC/hook analysis](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_findings.md), [authenticated stubs](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_stubs_inventory.json), [hook helper](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_decompile_6058.json), [method ABI checker](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_decompile_6480.json), [output hook helper](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_decompile_75b8.json).

### 3.3 AutoPatches is a separate runtime patcher

The public AutoPatches source builds arm64 and arm64e and links Dobby. Its path translation code uses `DobbyInstrument`, `DobbyCodePatch`, import replacement and near-branch trampolines. These are separate from Camera's `MSHookMessageEx` calls. [AutoPatches Makefile](https://github.com/roothide/DynamicPatches/blob/9142c7d1d9f578df86e891065c8d2e9f581eabe6/Makefile), [Patches.cpp](https://github.com/roothide/DynamicPatches/blob/9142c7d1d9f578df86e891065c8d2e9f581eabe6/Patches.cpp).

PatchLoader resolves an image's `.roothidepatch` marker, checks the runtime JIT gate, loads the marker target, and calls `InitPatches(path, header, slide)`. The reviewed Dopamine 2 systemhook exports `PLRequiredJIT()` returning zero. Neither fact proves arbitrary runtime trampolines PAC-safe or establishes a general JIT permission grant. The reviewed loader does not re-sign VCNext at boot. [PatchLoader dispatch](https://github.com/roothide/PatchLoader/blob/76dba6571d25e28f2b6dbdfb88a7e8459b1a5684/PatchLoader.c#L43-L73), [Dopamine 2 gate](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/BaseBin/systemhook/src/roothider_main.c#L20-L23).

The public compatibility source identifies version 0.6, while this package requires `rootless-compat >=0.9`; its Dobby archive is a symlink rather than a self-contained pinned source implementation. No installed backend/AutoPatches binary or target loaded-image inventory was supplied. Therefore **correct attachment and PAC behavior of the installed versions remain runtime requirements**, not a static sign-off. Keeping the original text and fixups avoids introducing a new compiled PAC regression; runtime modifications can still differ.

### 3.4 A13: what is established, and what is not

The installer explicitly selects `mediaserverd` only for `iPhone12,*`; the default Camera filter lists both `cameracaptured` and `mediaserverd`. Comments referring to an earlier PAC trap are history claims, not crash evidence. One comment even refers to **mediaserverd** crashing; it does not establish the faulting instruction in **cameracaptured**.

There is independent binary evidence of deliberate model-specific policy:

| Product prefix / profile | Preview hooks | Photo/node/output subclass hooks | In-place delivery |
| --- | --- | --- | --- |
| `iPhone11,*` / `classic-a12-legacy`, profile `0x20750` | Enabled | Enabled | Disabled |
| `iPhone12,*` / `mid-a13-safe-terminal-replacement`, `0x20780` | Disabled | Enabled | Disabled |
| `iPhone13,*` / `mid-a14-terminal-in-place`, `0x20798` | Disabled | Enabled | Enabled |
| `iPhone14,*` / `modern-a15-terminal-in-place`, `0x207b0` | Disabled | Enabled | Enabled |
| `iPhone15,*` / `modern-a16-terminal-in-place`, `0x207c8` | Disabled | Enabled | Enabled |

For A13 mediaserverd, `0x4770–0x47a8` sets an additional fresh-configuration gate. Before first activation, the scanner requires `CameraConfig.mtime + 0.001 >= constructor wall time`; rejection is **`0x5938: 24110054 B.MI 0x5b5c`**. Function `0x5578` also consults `A13CameraCanary`. The app creates/removes that canary in its A13 settings path (`0x1000231c0` / `0x1000231d8`). A valid lease alone therefore does not activate every A13 path; a fresh app configuration can be necessary after the host restarts.

The profile parser `0x43b0` recognizes the full `iPhone<major>,<minor>` string; `0x4400–0x4404` rejects non-iPhone prefixes and leaves a fallback profile. There is no explicit M1/M2 iPad profile established by this selector. Platform eligibility on an M-series iPad is not equivalent to its camera pipeline being covered.

**Answer 2.1:** the exact historical crash cause cannot be determined from these binaries/comments alone. No crash log, exception subtype, PC/LR, faulting instruction, target method encoding, installed backend version or reproduction was provided. A PAC failure, private ABI mismatch and frame lifetime/race fault cannot be distinguished without that evidence. A user-process PAC fault is not automatically a kernel panic. [Apple PAC guidance](https://developer.apple.com/documentation/security/preparing-your-app-to-work-with-pointer-authentication).

**Answer 2.3:** there is no evidence supporting a blanket mediaserverd-only filter for every arm64e device, nor enough evidence to certify cameracaptured safe on A14/A15. The binary already distinguishes these profiles. Removing cameracaptured prevents the entire Camera hook/render path from running in that process; it can lose any consumers/modes whose buffers travel there. Static analysis cannot enumerate those consumers on every target OS. Preserve the existing A13 mitigation while testing the other process paths on exact device/build pairs.

Evidence: [model parser](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_decompile_43b0.json), [decoded profile data](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_device_policy_data.json), [initialization policy](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_decompile_46a0.json), [hook scanner](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_decompile_568c.json), [existing app canary analysis](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/navigation_findings.md).

### 3.5 `uname -m`: the A13 branch is not inherently dead

**Answer 2.2:** physical iOS can return `iPhone12,*` from `uname -m`. Apple's libc `uname()` fills `machine` using `CTL_HW/HW_MACHINE`; its shell utility queries the same field. XNU's physical iOS implementation obtains the platform product name. Dopamine's own exploit selector and this Camera dylib use `uname().machine` to select device models. The expectation of a universal `arm64` result confuses different Darwin environments/utilities. [Apple libc](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/gen/uname.c#L81-L84), [Apple uname utility](https://github.com/apple-oss-distributions/shell_cmds/blob/298787009e5432c5e4c378a077f98267077e3495/uname/uname.c#L362-L363), [iOS XNU product field](https://github.com/apple-oss-distributions/xnu/blob/xnu-8796.121.2/bsd/kern/kern_mib.c#L521-L560), [Dopamine selector](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/Application/Dopamine/Jailbreak/DOExploit.m#L67-L75).

`sysctl -n hw.machine` makes the intended query explicit and avoids a utility-specific `UNAME_MACHINE` override. It is useful hardening, **not a proven fix for a dead branch or PAC crash**. Identify the installed command/environment when collecting device evidence. The proposal below prefers the native sysctl and falls back to uname, retaining the exact existing A13 policy.

## 4. Vector 3: thin arm64 processes and RootHide paths

Apple's iOS 16-era XNU binary grader explicitly accepts `CPU_SUBTYPE_ARM64_ALL` on an arm64e host with nonzero grade 9. Therefore these thin arm64 daemons and the thin app execute natively on eligible A12+ hardware; CPU emulation or an arm64e rebuild is not required merely because the kernel/device supports PAC. Executable admission, entitlements and dependencies must still succeed. [XNU grading](https://github.com/apple-oss-distributions/xnu/blob/xnu-8796.121.2/bsd/dev/arm/kern_machdep.c#L84-L104).

The library ABI must match the **process**, rather than the kernel's marketing architecture. A thin arm64 daemon needs the arm64 compatible library path; injecting Camera into an arm64e Apple host uses its arm64e slice. The public AutoPatches build supplies both architectures. That supports the design but does not prove the installed library is present, selected, trusted and functioning on every device. CodeDirectory page rehashing alone supplies no such proof.

RootHide path translation is not a new A12-specific issue. As established in the ecosystem report:

- `libroot`/`jbroot()` are explicit path APIs; merely linking libroot does not prove POSIX calls are interposed.
- The reviewed RootHide root uses randomized `.jbroot-*` trees, not a universally fixed `/var/jb` or the generic preboot example.
- Converted legacy `/var/jb/...` paths depend on the compatibility symlinks, patch markers, AutoPatches and installed virtual-root environment. Preserve their packaging and mirror paths.
- Both root NetworkDaemon and mobile StreamDaemon/injected hosts must resolve the **same** AuthSession/CapabilityLease/config files. UID, sandbox access and file ownership are separate from translation.
- The current installer makes the state tree mobile-owned and removes group/other access, and explicitly deletes stale CameraConfig/CameraStatus/CapabilityLease. Expected post-install disarming is not itself a PAC or license-digest defect.

Do not prepend a second jbroot to an already converted path, persist yesterday's randomized absolute prefix, or replace genuine `.roothidepatch` symlinks with Windows `.symlink` text files. Source and installation details are in the [ecosystem report](/C:/Users/Admin/Desktop/vcnextnew/docs/05_ROOTHIDE_ECOSYSTEM_COMPATIBILITY.md), with the [RootHide developer path contract](https://github.com/roothide/Developer/blob/c53cc199f1bab7d7ea2fd70f0a14e215b1f3461b/interface.md#L14-L58) and [separate virtual-root libraries](https://github.com/roothide/libroothide/blob/7764c54759009272b4f2f23c18c62b21794fe6dd/Makefile#L14-L51).

## 5. Vector 4: app/server parity and multi-device behavior

### 5.1 Exact client fields and digest ownership

| Request | Constructed JSON members | Evidence |
| --- | --- | --- |
| App challenge | `protocol_version`, `request_id`, `username`, `device_id`, `device_public_key`, `client_build`, `binary_digest` | Constructor `0x100006808`; key array `0x100006914–0x1000069f0`; dictionary count 7 |
| App login | `username`, `password`, `device_id`, `device_name`, `client_build`, `binary_digest`, `challenge_nonce`, `challenge_id`, `device_signature` | Block `0x1000072a8`; key array `0x100007330–0x10000744c`; dictionary count 9 |
| Heartbeat/renew | `request_id`, `nonce`, `device_id`, `client_build`, `binary_digest`, `issued_at`, `device_signature` | App shared proof/transport; independently confirmed in NetworkDaemon `0x100004c7c–0x100004ce8`, count 7 |

The login `device_name` is `UIDevice.currentDevice.name` (`0x100007380`, `0x10000738c`), with fallback `"iPhone"`; it is not `hw.machine`. No CPU architecture/product identifier field is constructed in these request dictionaries. App uname usage for A13 local settings/canary is separate from the request parser.

The thin app's request/challenge digest is **`4c10...` on both A11 and A12+**. NetworkDaemon reads `client_build` and `binary_digest` from AuthSession at `0x10000453c` / `0x10000459c`, constructs the proof from those values, and sends `X-Client-Build` / `X-App-Digest` at `0x100004880` / `0x1000048b8`. It does not substitute its own thin-daemon text hash or the Camera hash.

The active app challenge verifier compares the signed challenge digest with the app text getter: BL `0x1000208cc`, comparison helper BL `0x1000208ec`. It signs accepted challenges with a device **P-256 ECDSA** key, distinct from the server RSA authority. App response `0x100007730` subsequently reads `lease_signature` and token/nonce bindings; it does not require lease `binary_digest` to equal the app/Camera hash. Original app text is identical to the current customized app, so those prior instruction findings remain applicable.

Evidence: [challenge request constructor](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/decompile_100006808.json), [login constructor](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/decompile_1000072a8.json), [app signed challenge contract](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/lease_verify_challenge_findings.md), [app lease verifier](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/lease_verify_findings.md), [fresh Network request reconstruction](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/network_0x1000042e4.json).

### 5.2 Architecture strategy

Use one measured build-37 **app artifact profile** for the current challenge/proof contract. Keep the existing signed lease compatibility member for both Camera architectures. There is no reason to guess the loaded Camera slice from a user-editable device name, a UUID, the app digest or the fact that the request came from a thin arm64 process.

If a future verified consumer introduces a real per-slice equality, this client protocol cannot automatically distinguish Camera arm64 from arm64e. That would require a versioned, authenticated client report of the actual measured component/architecture, or trusted enrollment metadata and an explicitly supported schema. Reflecting an untrusted `arch` parameter into a signed lease would not establish hardware identity. No such extension is required by the current inspected readers.

Retain typed strings/numbers, all five capabilities, 90-second signed leases, `lease_signature` on the wire, token/nonce hash bindings, and locally generated received uptime. A correct signature also requires the same JSON bytes as Foundation. The present payload strings are predominantly ASCII; arbitrary Unicode usernames and alternative escaping/number formatting need canonicalization vectors before being advertised as supported. This audit did not run a new Foundation-versus-Python serialization experiment.

### 5.3 Commercial blockers in the supplied server source

The current local implementation is `ThreadingHTTPServer`, not the previously proposed FastAPI service. Source SHA-256 is `408890bf5b491dcb26c2dc506c8afcbae92b2187781c9dfa3df4353ebd5e25c6`. Reading that source establishes these limitations; the deployed VPS's current code/configuration was not inspected:

1. The combined login/renew/heartbeat branch issues new tokens and signed leases without checking a password, Authorization token, device ECDSA proof, or current request nonce. Login does not enforce challenge expiry, device ownership or one-time consumption. The client producing a signature does not mean the server verifies it.
2. A challenge ID is used to retrieve only a thumbprint; missing sessions/challenges can fall back to a fixed thumbprint. Missing device IDs default to a shared constant. These paths are unsuitable as independent device enrollment/authentication.
3. Renew/heartbeat bodies omit username, but the branch defaults username to `admin` rather than restoring it from the authenticated session. `active_devices` and `max_devices` are hardcoded to 1. There is no evidenced account/device-limit policy, despite the table containing multiple device rows.
4. Every accepted request replaces the session's tokens/nonce. The app and NetworkDaemon can send requests concurrently. Adding strict token/nonce verification later requires transactional request consumption and a defined race/idempotency policy; client-side freshness guards alone cannot guarantee that the server and saved session choose the same winning rotation.
5. Logout deletes by device ID without token/proof validation. JSON primitives currently can reach dictionary operations and raise exceptions; the proposal below rejects those inputs before doing so.

The proposed compatibility patch is **not** an authentication implementation and does not close items 1–4. App-digest allowlisting identifies an artifact claim and is not a substitute for credentials or device proof. These are independent reasons to withhold a commercial licensing-authority sign-off, even if frame injection works on an A11 device.

## 6. RootHide compatibility matrix

This table describes eligibility of pinned upstream platforms, not demonstrated VCNext operation on each row. Source identities and exact build exceptions are recorded in [platform evidence](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/platforms.md).

| Platform/device family | Relevant published/source eligibility | VCNext conclusion |
| --- | --- | --- |
| Dopamine 2 RootHide, A12/A13/A14/M1 | Stable iOS/iPadOS 15.0–16.5.1, intersected with firmware available for the device; selected beta builds are separately enumerated | Candidate for controlled system-injection testing; no A12+ runtime pass supplied |
| Dopamine 2 RootHide, A15/A16/M2 | Stable releases through 16.5; manifest excludes 16.5.1 build `20F75` for A15/A16; M2 maps to A15 | Candidate only on supported exact builds; no blanket iOS 16 support |
| A16 iPhone 14 Pro/Pro Max | Shipped iOS 16; eligible versions must satisfy the preceding gate | In scope for testing, not certified |
| iPhone 15/15 Plus | A16 but shipped iOS 17 | Outside Dopamine 2 iOS 15/16 scope |
| iPhone 15 Pro/Pro Max | A17 Pro, shipped iOS 17 | Outside both this chip range and Dopamine 2 scope |
| RootHide Bootstrap alone | Project advertises iOS 15.0–17.0, A8–A17 Pro/M1/M2, and per-app enablement | That alone does not establish this package's SpringBoard/camera-host injection or system launchd jobs. Exact system-injection environment must be validated |
| Relaxin audit snapshot | arm64e, OS 16.5.1–17.3.1, recognized CPU family **and exact target/manifest match** | Separate untested environment; no A11/iOS 15 support. A CPU-family entry alone does not establish VCNext or every device/build support |
| M1/M2 iPads | Platform eligibility as above, where firmware exists | Camera selector has no explicit iPad model profile in the inspected parser; camera/overlay behavior needs separate validation |

Dopamine reference is **2.x commit `44d398aea2a2ea2c6dbece1c0db84ddd5f70388b`**, not its moving 3.x default branch. Relevant primary sources: [support gates](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/Application/Dopamine/Jailbreak/DOEnvironmentManager.m#L627-L644), [PPL build manifest](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/Application/Dopamine/Exploits/dmaFail/Info.plist#L11-L45), [CPU mapping](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/Application/Dopamine/Jailbreak/DOExploit.m#L77-L166).

Bootstrap reference is `053072440b88c9533c43df8cdcceb693d7a78ba4`; its AppEnabler also contains an optional launchd-exploit path. Do not replace the insufficient system-pipeline evidence with an absolute claim that every Bootstrap version lacks all system capabilities. [Bootstrap README](https://github.com/roothide/Bootstrap/blob/053072440b88c9533c43df8cdcceb693d7a78ba4/README.md), [AppEnabler](https://github.com/roothide/Bootstrap/blob/053072440b88c9533c43df8cdcceb693d7a78ba4/Bootstrap/AppEnabler.m).

Relaxin reference is `xz1c/relaxin@871826c6d7f6e905143a55398219a13bb977bc1d`; it is presented as a public audit snapshot. Its arm64e and exact-target preflight gates do not certify a commercial hook stack. [Preflight ABI gate](https://github.com/xz1c/relaxin/blob/871826c6d7f6e905143a55398219a13bb977bc1d/RelaxinEngine/Stages/Preflight/RLXTargetConfirmationTask.m#L37-L45), [target/version gates](https://github.com/xz1c/relaxin/blob/871826c6d7f6e905143a55398219a13bb977bc1d/RelaxinEngine/Stages/Preflight/RLXTargetConfirmationTask.m#L115-L191).

## 7. Exact source proposals and their limits

The complete, applicable unified diff is [compatibility.patch](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/proposals/compatibility.patch). Candidate files are stored only under [proposals](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/proposals/). The product server and installer remain byte-identical to their starting values.

### 7.1 Server proposal

The server diff preserves the existing lease digest value under the clearer name `LEASE_COMPAT_DIGEST`, introduces a build/app-digest profile shared by all device architectures, rejects non-object JSON, and rejects unsupported/mismatched app artifact fields on the four genuine authentication routes. Decoy routes remain outside the artifact gate because their digest/device fields are intentionally randomized. No `hw.machine` inference is added.

```diff
@@
 APP_TEXT_DIGEST = "4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2"
-CAMERA_TEXT_DIGEST = "d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943"
+# Build 37 lease readers do not compare this signed compatibility marker.
+# Preserve its existing value on both arm64 and arm64e clients.
+LEASE_COMPAT_DIGEST = "d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943"
+CLIENT_BUILD = "37"
+SUPPORTED_APP_DIGESTS = {CLIENT_BUILD: frozenset({APP_TEXT_DIGEST})}
+
+def supported_client_artifact(body, headers):
+    if not isinstance(body, dict):
+        return False
+    build = body.get("client_build")
+    digest = body.get("binary_digest")
+    if not isinstance(build, str) or not isinstance(digest, str):
+        return False
+    if digest not in SUPPORTED_APP_DIGESTS.get(build, ()):
+        return False
+    return all(headers.get(name) in (None, expected) for name, expected in (
+        ("X-Client-Build", build), ("X-App-Digest", digest)))
@@
-        except Exception:
-            body = {}
+        except (ValueError, UnicodeDecodeError):
+            return self._send_json(400, {"error": "INVALID_JSON"})
+        if not isinstance(body, dict):
+            return self._send_json(400, {"error": "INVALID_JSON_OBJECT"})
@@ after the decoy-route return, before issuing challenges/leases
+        if path in ("/api/v2/auth/challenge", "/api/v2/auth/login",
+                    "/api/v2/auth/renew", "/api/v2/auth/heartbeat"):
+            if not supported_client_artifact(body, self.headers):
+                return self._send_json(426, {"error": "UNSUPPORTED_CLIENT",
+                                             "message": "Unsupported app build or digest"})
@@ in challenge_payload and lease_payload
-                "build": "37",
+                "build": CLIENT_BUILD,
@@ in lease_payload
-                "binary_digest": CAMERA_TEXT_DIGEST,
+                "binary_digest": LEASE_COMPAT_DIGEST,
```

The excerpt above explains the changes; the linked `.patch` contains exact line-numbered hunks for application. The candidate deliberately rejects Camera hashes as **app request** digests while continuing to emit the legacy signed lease member. Matching values on A11/A12+ are already established by the current thin app and NetworkDaemon constructor. Unknown future app artifacts need a measured profile and protocol review before allowlisting. This is a compatibility proposal, not approval to deploy an otherwise unauthenticated authority.

### 7.2 Installer proposal

Replace the existing historical assertion/comment and `machine=...` line, leaving its `case` body and existing host policy intact:

```diff
@@
-# A13 (iPhone 11/SE2): always keep the camera dylib AND overlay (float control +
-# color sync), force a mediaserverd-only camera filter. The old A13_CANARY_PACKAGE_FLAG
-# gate deleted the dylib because the PAC trap made mediaserverd crash; with the
-# macOS/Xcode SDK build the ptrauth is correct, so the dylib + overlay are safe to
-# keep. The .roothidepatch markers MUST stay so RootHide's PatchLoader can finish
-# patching + re-signing the dylibs at boot.
-machine="$(uname -m 2>/dev/null || true)"
+# Query the product model explicitly. Physical iOS uname -m can also return
+# iPhone12,*; that original branch is not inherently dead code.
+get_hardware_model() {
+    model="$(/usr/sbin/sysctl -n hw.machine 2>/dev/null || true)"
+    case "$model" in
+        iPhone*|iPad*|iPod*) printf '%s\n' "$model"; return ;;
+    esac
+    uname -m 2>/dev/null || true
+}
+
+# Preserve the existing A13 mediaserverd-only policy until crash logs and
+# exact-device tests justify a change. This does not certify PAC safety.
+# Keep the RootHide patch markers; they enable path compatibility patches.
+machine="$(get_hardware_model)"
 case "$machine" in
     iPhone12,*)
```

This is an explicit model-query/fallback change and a correction of unsupported comments. It is **not** a universal cameracaptured crash fix. `preinst` also has an A13 branch; if this proposal is adopted, use the same probe there and remove the equivalent unconditional PAC-safety claim. Do not broaden either model filter to every arm64e device without measured host coverage.

The remaining installer actions deserve device observation: errors from ownership changes and `launchctl load` are suppressed, and `killall mediaserverd` deliberately restarts the host. A script exit status of zero does not prove the service loaded or the state paths/permissions resolved correctly. This audit did not change the established RootHide `/var/jb` compatibility handling or run the installer.

### 7.3 Verification performed on the proposals

The [proposal helper](/C:/Users/Admin/Desktop/vcnextnew/scripts/prepare_arm64e_audit_proposals.py) generates candidates without importing the server, runs Python syntax parsing and an isolated pure artifact-profile helper, checks installer shell syntax, exercises only a mocked model-probe function, and runs `git apply --check --ignore-space-change` against the current source. **22 checks passed.** They include the same thin app on both architectures, daemon header/body parity, rejecting both Camera hashes as app hashes, unknown/numeric/missing build/digest values, mismatched headers, retained lease metadata and A13 policy, sysctl/uname fallback cases, and byte-identical product files afterward. These are source/proposal checks, not simulated PAC or device tests. [Verification record](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/proposals/verification.json).

## 8. Release decision and exact-target evidence still needed

| Decision | Status |
| --- | --- |
| Change lease `binary_digest` to Camera arm64e hash to enable A12+ | **Unnecessary for inspected consumers** |
| Patch the 95-second clock checks or remove PAC instructions | **No evidence justifies this** |
| Keep existing original compiled arm64e code/fixups | **Static preservation verified** |
| Run thin arm64 app/daemons on eligible A12+ | **Supported execution architecture; runtime admission still required** |
| Declare A13 historic crash root cause solved | **Unproven** |
| Change all A12–A16 Camera filters to mediaserverd-only | **Unsupported; possible functional loss** |
| Certify iPhone 15 Pro under Dopamine 2/iOS 15–16 | **Outside platform scope** |
| Approve unrestricted commercial multi-device deployment | **Withheld pending target tests and server authentication/session-policy work** |

For each proposed supported device/OS/build and jailbreak/backend version, capture: actual product/build and loaded slices; installed compatibility/Substrate provider versions; successful daemon launch and exit status; loaded AutoPatches/Camera/Overlay images; actual resolved state paths/ownership; and crash logs with PC/LR/backtraces. Then exercise app challenge/login/restore/logout, repeated 90-second lease renewal, app/daemon concurrent renewal, network loss and recovery, wall-clock/sleep-wake expiry, host restart with A13 configuration reactivation, front/rear preview and still/video capture, third-party camera consumers, stream/media replacement and floating/color-sync controls. Compare output and failure recovery with the working A11 baseline.

A controlled matrix can establish tested support for named device/build combinations. Static opcode preservation, a functioning A11 install and a generic PAC label cannot establish zero process crashes, zero kernel panics or full private-camera coverage across every A12–A17/M-series environment.
