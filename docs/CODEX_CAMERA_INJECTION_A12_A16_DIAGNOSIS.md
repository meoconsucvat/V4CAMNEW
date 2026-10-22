# VCNext Direct Media failure on iPhone 12 and iPhone 14 Pro

**Date:** 2026-10-21, Asia/Saigon. **Verdict:** two concrete failure mechanisms are established in the shipped code: a cross-process file-access barrier and deliberately reduced preview/output hook coverage. Neither has yet been observed inside the affected phones, so an exact runtime root cause and a verified permanent fix cannot honestly be certified from the supplied symptoms alone. Reversible permission tests and separately staged preview-test binaries are delivered below.

## 1. Reported reproduction and investigation boundary

| Device | User-confirmed environment | Reported result |
| --- | --- | --- |
| iPhone 8 Plus / A11 | iOS 16, Dopamine 2 RootHide | Direct Media replaces the stock Camera feed |
| iPhone 12 / A14 / `iPhone13,2` | iOS 16.5, build 20F66, Dopamine 2 RootHide v2.x | Login succeeds; Use as Camera becomes Stop Camera; physical feed remains |
| iPhone 14 Pro / A16 / `iPhone15,2` | iOS 16.5, build 20F66, Dopamine 2 RootHide v2.x | Same failure |

The user already performed a userspace reboot and manually restarted both `mediaserverd` and `cameracaptured`. Repeating a generic restart is therefore not the primary recommendation. The exact jailbreak/ElleKit package revisions, live process credentials, filesystem modes, loaded images and frame counters remain unmeasured.

This investigation inspected the current package, main/mirror binaries, load commands, profile bytes, retained disassembly and fresh decompilation/Capstone decoding, plus pinned official RootHide/ElleKit source. No phone, server, licensing database or production binary was modified. The existing `.deb` remains unchanged. Experimental binaries exist only in a separate staging directory.

### Artifact identity

| Artifact | SHA-256 |
| --- | --- |
| `VCNext-custom-roothide.deb`, 496,292 bytes | `4d1f8bf580e1c7699865fbafec4302ad28ab9df9a155b8bc13d68330ef51675b` |
| Main Camera dylib, 403,888 bytes | `901319d0cf57ff00749fbb4e3ac4095923c5cce2d428475486fd5f386a8a6e6e` |
| pkgmirror Camera dylib, 405,056 bytes | `c244b61a0247bdbd88eac5a7127a9c5f4df30907b8270b66ebfca1d908e2b32a` |
| Camera arm64 `__TEXT,__text` | `d8e4627720972adb6751d0719616a6798fca1a8b61b348b3c4895c04948ed943` |
| Camera arm64e `__TEXT,__text` | `60e7f7328417c91f4dd21bf27077d5196b11d8aa698ce7f0c6f78217736a6bba` |

The FAT slice bases are arm64 `0x4000` and arm64e `0x34000`. Addresses below are **unslid arm64e virtual addresses** unless explicitly called FAT offsets. [Fresh verification](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/verification.json) confirms the main/mirror source bytes match the current package members, the installer matches its package copy, and all five packaged AutoPatches markers are genuine symlinks.

REA opened the byte-identical arm64e thin slice. Its IDA adapter decompilation failed because its upstream schema rejected `offset`/`max_lines`; those error records are retained and are not treated as successful analysis. Direct upstream IDA decompilation then recovered the missing renderer helpers with address markers. [Fresh independent instruction decoding](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/renderer_arm64e_fresh.asm) anchors their relevant instructions to current bytes. The analysis session was closed; no target execution occurred.

## 2. Confirmed activation flow: the UI button is upstream of injection

Arm64e `sub_568C` does this before selecting hooks:

```c
cfg = readDictionary(CameraConfig);             // 0x56f0
link = cfg.linkEnabled && cfg.linkMode < 2;
path = normalizeAndValidate(cfg.selectedMediaPath);
direct = cfg.directMediaEnabled &&
         (cfg.selectedMediaKind == 1 || cfg.selectedMediaKind == 2) &&
         attributes(path).fileSize != 0;
if (!(link || direct)) {
    active = 0; clearDedupCache(); return;        // 0x58a0 -> 0x5b7c
}
active = 1;
installHooksAllowedByProfile();
```

This is explanatory pseudocode. Config fields/path/type/attributes are read at `0x5708`–`0x5890`. A nil dictionary produces false/zero through Objective-C nil messaging. If Direct Media is the only active source, inability to read CameraConfig or stat its selected file prevents activation **before every preview/photo/output path**. Missing files, invalid paths and disabled config can cause the same branch; nil does not uniquely identify EACCES. [Exact initializer](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_decompile_568c.json).

The renderer separately reloads CameraConfig at `0xaa20`, checks `camera.fake-frame`, `camera.obs` and `media.import` at `0xab6c`–`0xab90`, and reads media attributes at `0xafd0`/`0xaff4`. An active app-side lease does not establish the injected process's ability to read/validate that lease or source file. [Fresh renderer configuration](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/ida_arm64e_a968.json).

Consequently the red Stop Camera button establishes app intent/config state, not successful dylib loading, daemon-side activation, installed hooks or delivered frames.

## 3. Vector 1: preview is disabled, but the whole replacement pipeline is not

### Exact profile gates

At `0x59a4`, bytes `08254039` decode as `ldrb w8,[x8,#9]`; `0x59a8` compares with 1; `0x59ac` (`c1040054`, `b.ne 0x5a44`) skips the named preview branch when the byte is zero.

| Profile family | Profile VA | +9 named preview | +10 photo | +11 output | +12 output subclasses | +13 preview subclasses | +15 connected output | +16 in-place |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| iPhone10,* / A11 | `0x20738` | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| iPhone11,* / A12 | `0x20750` | 1 | 1 | 1 | 1 | 1 | 0 | 0 |
| iPhone12,* / A13 | `0x20780` | 0 | 1 | 1 | 1 | 0 | 0 | 0 |
| iPhone13,* / A14 | `0x20798` | 0 | 1 | 1 | 1 | 0 | 0 | 1 |
| iPhone14,* / A15 | `0x207b0` | 0 | 1 | 1 | 1 | 0 | 1 | 1 |
| iPhone15,* / A16 | `0x207c8` | 0 | 1 | 1 | 1 | 0 | 0 | 1 |

These field names are inferred from actual consumers, not recovered source declarations. All 28 inspected profile records across original/current, main/mirror and both architectures agree: the authority customization did **not** disable preview. [Raw policy inventory](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/policy_offset_inventory.json), [control-flow analysis](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/policy_findings.md).

With `+9=0`, `BWImageQueueSinkNode` and `BWRemoteQueueSinkNode` `renderSampleBuffer:forInput:` hooks at `0x59d0`/`0x59f4` are not attempted. Preview subclass enumeration is also skipped. However, photo hooks for `BWPhotoEncoderNode` and `BWStillImageSampleBufferSinkNode` (`0x5a78`, `0x5a9c`) and `BWNodeOutput` output/subclass hooks (`0x5ac8`, `0x5b54`) remain outside that branch and enabled.

**Answer:** named viewfinder/sink coverage is disabled on the reported profiles. It does not follow that stock preview cannot be replaced through an enabled output route, or that still photos, recording and every third-party app necessarily fail. Their actual private frame routes must be measured. Neither “photo must work” nor “broken everywhere” is established by a flag table.

### A +9-only edit has limited scope

Dynamic preview-subclass discovery also requires `byte_25DD8`. Initialization reads profile `+13` at `0x4804`, combines `+14` with the OS-major condition at `0x4808`–`0x4818`, and stores the flag at `0x482c`. A14/A16 have `+13=0`, so changing only `+9` attempts the two named hooks but **does not enable preview subclass enumeration** at `0x5a04`.

The named-hook helper checks whether each runtime class/method exists and passes its ABI validator before `MSHookMessageEx` at `0x61b4`. A flag change cannot create a missing method or guarantee traversal. The author’s reason for these policies—pipeline change, known crash, performance or another tradeoff—is **unknown** without source history or corresponding runtime evidence. A real-camera picture is not a PAC crash report. Do not disable ABI checks or copy the entire A11 policy onto A14/A16.

### The enabled A14/A16 output path has additional gates

`sub_7CE0` probes output `connection` and `consumer` at `0x7dfc`/`0x7e28`. When both are present, replacement requires profile `+15` or its special A13 observation condition (`0x7e78`–`0x7e90`). **Both reported A14/A16 profiles have `+15=0`**, while A15 has 1. Ineligible calls increment `rejectedNodeOutputFrames` and preserve the original sample. Missing connection/consumer has separate terminal-eligibility checks; not every missing object automatically qualifies.

Eligible A14/A16 routes take the serialized in-place block at `0x8140`. It requests a replacement via `sub_6894` (`0x837c`), then copies into the original CVPixelBuffer at `0x83fc`; success increments `inPlaceFrames`. The outer wrapper has a real fallback:

```c
if (inPlaceCopySucceeded || alreadyDeduplicated)
    forward(original);      // Original buffer contains virtual pixels.
else if (replacement && replacementPixelFormat == originalPixelFormat)
    forward(replacement);   // Compatible-format fallback.
else
    forward(original);      // No usable virtual replacement.
```

Format comparison occurs at `0x7f0c`–`0x7f1c`; mismatch counting at `0x7f7c`; final sample selection at `0x8020`–`0x8028`. Thus a failed in-place copy alone is insufficient to diagnose failure: **copy failure plus different pixel formats**, or no prepared replacement, preserves the real feed. [Output wrapper](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/arm64e/pac_camera_decompile_7ce0.json), [fresh in-place block](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/ida_arm64e_8244.json).

### Pixel-format failure is a concrete alternative to preview coverage

The A14/A16 `+18=1` selects preparation purpose 2. Renderer `0x8fd8` maps compressed formats to renderable equivalents, including `&8f0`/`-8f0` to `420f`, `&8v0`/`-8v0` to `420v`, `&BGA`/`-BGA` to `BGRA`, and `&xv0`/`-xv0` to `x420`. This can make replacement and original formats differ.

The in-place method at `0x996c` first attempts VideoToolbox transfer through `sub_9E7C` (`0x9ee8`). If transfer fails, its raw-copy fallback checks matching geometry/format and refuses the compressed formats at `0x9b50`–`0x9be4`; it does not blindly memcpy compressed planes. The outer different-format fallback then preserves the physical buffer. These are observed failure paths, **not proof of the actual formats/status codes on these phones**. [Preparation](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/ida_arm64e_8fd8.json), [copy method](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/ida_arm64e_996c.json), [transfer block](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/ida_arm64e_9e7c.json).

Apple documents compressed capture formats, including the FourCC mappings above, and warns that available formats depend on the active capture format. VideoToolbox transfer can return an unsupported-transfer error. Neither source identifies stock Camera's active private format here. [Apple TN3121](https://developer.apple.com/documentation/technotes/tn3121-selecting-a-pixel-format-for-an-avcapturevideodataoutput), [transfer API](https://developer.apple.com/documentation/VideoToolbox/VTPixelTransferSessionTransferImage%28_%3Afrom%3Ato%3A%29?language=objc).

The renderer also rejects unsuitable geometry: normal/output purpose exceeds 4096 per dimension or `0x870000` pixels; photo purpose exceeds 5000 per dimension or `0xc65d40` pixels (`0x9078`–`0x90cc`). Include a normal-resolution still test rather than assuming every high-resolution capture mode is covered.

## 4. Vector 2: filesystem permissions can disable activation before hooks

Current [postinst](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/postinst:11) recursively assigns the mixed shared tree to mobile and removes group/other access:

```sh
chown -R mobile:mobile "$SHARED_DIR"
chmod -R u+rwX,go-rwx "$SHARED_DIR"
```

This is owner-only access, commonly 0700 directories/0600 files, although owner execute bits can be preserved. It is followed by removal of stale config/status/lease files. A newly written 0644 file still cannot be opened through an inaccessible ancestor. Different unprivileged daemon credentials need directory search permission plus file read permission, unless ACLs or another applicable privilege supply access. The claimed UID 24/26 identities are **not verified**; collect actual effective credentials. Root reading successfully is not an equivalent test. [Apple open(2), EACCES conditions](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/open.2.html).

The app config writer creates the parent with nil attributes at `0x100022ac0`, writes CameraConfig atomically at `0x100022f74`, then sets a file-protection attribute at `0x100022fe4`. It contains no chmod/chown that deliberately reopens the existing shared directory. The app's text hash still matches the retained writer evidence. New file modes after atomic publication require inspection rather than assumption. [App writer](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/ui_tag1/navigation_decompile_100022a24.json).

**Answer:** if a host cannot traverse/read these paths, opening the relevant directories and config/media files resolves that DAC barrier. It does not repair sandbox denial, a bad normalized path, lease rejection, missing hooks or transfer failure. The same installer policy exists on A11, so a hardware-specific explanation additionally needs actual process credential/path differences; the artifact alone does not establish them.

Do **not** recursively chmod the entire VCNext tree 0755/0644. AuthSession can contain tokens/private device-key material. The provided narrow test uses shared root **0711** (search without listing), CameraConfig **0644**, selected Media ancestors **0755**, selected file **0644**, and leaves AuthSession, CapabilityLease, Streams and unselected media untouched. All earlier ancestors must also be traversable.

A read-only fix deliberately does not grant CameraStatus write access. Its atomic writer at `0x54e0` requires directory write/rename permission; a missing status/Injected marker can therefore coexist with successful image loading. Do not grant world-write access to the mixed security-state directory just to obtain diagnostics. [Filesystem findings and tools](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/filesystem_findings.md).

## 5. Vector 3: process filters and PAC

The packaged filter targets both `cameracaptured` and `mediaserverd`. The historical mediaserverd-only rewrite applies to `iPhone12,*` (A13), not either reported model. ElleKit matches executable names and loads eligible images with `dlopen`; safe mode and admission/load errors can still prevent injection. A matching plist is eligibility evidence only. [RootHide ElleKit injector](https://github.com/roothide/ellekit/blob/0199db7dbd4aab7e4e38e1b5041ec7265e0939a4/injector/injector.c#L280-L504).

Pinned Dopamine 2 systemhook source does not universally exclude either camera host and conditionally loads TweakLoader. Its A14/A16 platform gate includes the reported 16.5/20F66 combination; this is not the A16 16.5.1/20F75 exclusion. It does not identify the installed jailbreak revision. [Admission/loading](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/BaseBin/systemhook/src/main.c#L195-L249), [platform manifest](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/Application/Dopamine/Exploits/dmaFail/Info.plist#L11-L45).

Camera imports `MSHookMessageEx`; RootHide ElleKit's compatibility implementation delegates to its Objective-C hook and callable/signing helpers. This supports an arm64e-aware mechanism, but cannot prove private Apple ABI compatibility or a particular installed image's behavior. There is **no supplied evidence of a cameracaptured crash, PAC fault or kernel panic**. [Hook API](https://github.com/roothide/ellekit/blob/0199db7dbd4aab7e4e38e1b5041ec7265e0939a4/ellekit/API/MobileSubstrate.swift#L74-L77), [Objective-C hook](https://github.com/roothide/ellekit/blob/0199db7dbd4aab7e4e38e1b5041ec7265e0939a4/ellekit/Languages/Objective-C.swift#L10-L30).

**Recommendation:** retain both hosts as the diagnostic baseline. Do not globally restrict arm64e to mediaserverd, add arbitrary application names, or disable ABI/PAC checks. The Camera constructor itself schedules work only in the two supported hosts. Isolate one host only if measured crashes or duplicate processing justify that specific A/B test. [Detailed source audit and diagnostics](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/injection_findings.md).

## 6. Delivered fixes and experiments

### A. Reversible permission test — first

[Read-only diagnostic](/C:/Users/Admin/Desktop/vcnextnew/scripts/camera_diagnostics/diagnose_camera.sh) and [permission repair](/C:/Users/Admin/Desktop/vcnextnew/scripts/camera_diagnostics/repair_camera_read_access.sh) are POSIX shell scripts for the owned phone, not this Windows host. The repair requires root, an actual mobile-owned shared directory, an existing config and selected file inside its Media directory. It refuses noncanonical/symlink leaves and out-of-scope media. It records original modes and inode identity in a private manifest for rollback.

These helpers passed **nine offline checks** for syntax, host guards, scoped changes, unchanged credential/stream modes, rollback, replaced-inode handling and invalid paths. The shell-control tests use mocked Darwin metadata; no real iOS DAC/sandbox result is claimed. [Results](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/camera_diagnosis/helper_tests.json).

If that test restores output, the lasting fix is a consistent cross-process publication policy: preserve private session modes, ensure traversable camera-data ancestors, and apply readable modes on every new config/media inode before publishing/notifying. A one-time chmod or a postinst-only change cannot guarantee permissions after future atomic rewrites/imports. No broad installer change is silently applied here.

### B. Preview-only binary experiment — after access and loading pass

[prepare_camera_preview_experiment.py](/C:/Users/Admin/Desktop/vcnextnew/scripts/prepare_camera_preview_experiment.py) defaults to a dry run and writes only to an explicitly new output directory. It verifies exact source hashes and profile bytes, then changes **only arm64e profile +9** for A14/A15/A16. Existing staged main/mirror candidates and their [manifest](/C:/Users/Admin/Desktop/vcnextnew/dist/camera-preview-experiment/manifest.json) are in [dist/camera-preview-experiment](/C:/Users/Admin/Desktop/vcnextnew/dist/camera-preview-experiment).

| Family | Thin preview byte | FAT arm64e byte | Change |
| --- | --- | --- | --- |
| iPhone13,* / A14 | `0x207a1` | `0x547a1` | `00 → 01` |
| iPhone14,* / A15 | `0x207b9` | `0x547b9` | `00 → 01` |
| iPhone15,* / A16 | `0x207d1` | `0x547d1` | `00 → 01` |

The profile is in **`__DATA_CONST,__const`**, not the licensing `__TEXT,__const` slots. Pointer/fixup words and all other policy flags remain unchanged. `+13` remains zero, so this is a **named-preview experiment**, not full preview-subclass coverage. `+15` terminal eligibility and `+16` in-place behavior remain unchanged so the result is attributable to +9.

Verification confirms unchanged file lengths, the entire arm64 slice byte-identical, both text/PAC instruction streams unchanged, and modifications confined to the three flag bytes plus CodeDirectory page-32 hash arrays. All **six** CodeDirectories across these two universal candidates have zero code-page mismatches; special slots, entitlements, requirements and CMS bytes are preserved. Main candidate SHA-256 is `321f3ddf407966f8cb0d2a21c84bb00c6070043bafee578997dd41d4cd7547e5`; mirror is `ad3095736c632e37d06bdae3d9e2be28b2c117377597a3343211fc8641197ff3`.

**Trust boundary:** preserving CMS bytes is not re-signing them. The inspected CodeDirectory flags are `0x0`; do not label these candidates valid ad-hoc signatures merely because page hashes match. Their cdhash values change. Complete the normal target-compatible signing/trust installation workflow and confirm actual dyld admission before interpreting a negative camera result. A text digest remaining valid does not prove AMFI acceptance. The staged files are **not a validated drop-in production release**, and no modified `.deb` was built or deployed.

Do not change +13, +15 or +16 simultaneously with this test. If +9-only does not produce a reached named hook, the next patch must follow runtime class/ABI/frame evidence rather than a wider blind flag edit.

## 7. Physical-device test procedure

Run the following separately on **each** affected phone, keeping a known-good recovery path. Use the actual resolved RootHide paths. If `/var/jb` is not a usable shell alias, obtain the real installed prefix from the phone's package/file tooling; do not guess a randomized directory. Neither script discovers secrets or contacts a server.

1. **Record the baseline.** Save exact jailbreak/ElleKit/rootless-compat versions, `hw.machine`, `kern.osversion`, PID/UID/GID for both camera hosts, current package/dylib hashes and installed filter. Use a conspicuous test image. Keep its name/path private if necessary. The user-reported reboot/restart has already been completed.

   ```sh
   /usr/sbin/sysctl -n hw.machine
   /usr/sbin/sysctl -n kern.osversion
   ps -A -o pid,ppid,uid,gid,user,comm
   dpkg-query -W | grep -E 'vcnext|ellekit|substrate|rootless-compat|patchloader'
   ```

2. **Check the whole read path before changing binaries.** Select Use as Camera, then run the diagnostic with the actual shared directory and selected media path. If the shell alias exists, `cd /var/jb/var/mobile/Library/VCNext && pwd -P` can reveal that resolved directory. Otherwise supply the installed path explicitly.

   ```sh
   SHARED='/actual/resolved/var/mobile/Library/VCNext'
   MEDIA='/actual/resolved/var/mobile/Library/VCNext/Media/test-image.jpg'
   sh diagnose_camera.sh "$SHARED" "$MEDIA" > camera-before.txt 2>&1
   ```

   Inspect all ancestor modes and actual file owners. Where sudo is available, the script attempts read probes with measured UID/GID. Those probes use a fresh shell and do not reproduce the daemon sandbox. Confirm an actual in-process file read/sandbox denial through logs/debugger if the shell succeeds but activation remains false. Do not share AuthSession, private keys or full lease/session contents.

3. **Run the narrow DAC A/B test if access is blocked.** After selection, avoid further app changes during the test; close/background VCNext while ensuring normal lease renewal remains active. Apply once and retain the printed root-owned rollback manifest.

   ```sh
   sh repair_camera_read_access.sh --apply "$SHARED" "$MEDIA"
   sh diagnose_camera.sh "$SHARED" "$MEDIA" > camera-after-permissions.txt 2>&1
   # Later, restore using the exact printed manifest path:
   # sh repair_camera_read_access.sh --restore /var/tmp/vcnext-camera-modes.XXXXXX/modes.tsv
   ```

   Test Camera immediately, then after another app config/import operation and after 90 seconds with verified renewal. Recheck modes/inodes after any new write. Do not conclude “permissions fixed permanently” from one successful frame. No daemon restart is performed by these scripts; if reinitialization is necessary, restart each known host once in the test window and record its new PID.

4. **Prove image admission and hook installation.** Collect per-process loaded images with an already available debugger/vmmap workflow; confirm current VCNextCamera, hook provider and RootHide patch loader. Fresh `Injected/<process>` markers support constructor execution, but missing markers are ambiguous because creation also requires write access. With existing tooling, `image list -f` and `image lookup -n MSHookMessageEx` identify loaded files/provider. Debugger attachment can pause a camera host, so use a controlled test window.

   ```sh
   log stream --style compact --info --debug --predicate \
     'subsystem == "com.vcnext.camera" OR process == "mediaserverd" OR process == "cameracaptured"'
   ```

   The tweak logger is `com.vcnext.camera` / `hook` (`0x4868`). Look for ABI-compatible installed hooks, incompatible-method skips, dyld/AMFI errors and sandbox denials. Record unavailable tooling honestly. Constructor scheduling normally waits 3 seconds in cameracaptured or 8 in mediaserverd for a supported profile. Do not mistake an immediate observation for a completed hook scan.

5. **Classify the failure by counters, not the UI button.** Sample public CameraStatus fields repeatedly and corroborate with logs. Both processes share the same file, so its `process` field identifies only the last writer; lack of a fresh file may be a write-access problem.

   | Observation | Next investigation |
   | --- | --- |
   | Image absent / load failure / repeated crash | Injection admission, marker, dependency, trust or crash backtrace |
   | Config/media read fails; activation stays off | DAC, sandbox, normalized path or source validity |
   | `hookedClassCount=0` with readable active config | Runtime classes/methods and ABI admission |
   | `nodeOutputFrames` rises; `eligibleNodeOutputFrames=0`, rejected count rises | Terminal/connected-output policy and actual graph |
   | Eligible frames rise; `renderedFrames=0`, replacement misses rise | Renderer preparation, source read, capabilities and geometry |
   | In-place failures plus format mismatches rise | Original/replacement FourCC and VideoToolbox transfer result |
   | `inPlaceFrames`/`deliveredVirtualFrames` rises but display remains physical | Whether this host/route feeds the tested consumer; another unmodified route |

6. **Only then test the staged +9 variant.** Preserve the exact installed main/mirror images and filter, complete signing/trust handling, install only the intended candidates through the package's normal workflow, restart the affected hosts once, and verify their loaded images. Keep permissions, filter, media and camera settings identical to the passing baseline. Check the two named preview hooks are now installed **and called**. Roll back immediately on repeated camera-host crashes; retain the relevant `.ips` UUIDs, exception/termination reason, PC/LR and backtrace. A PAC fault must be established by that evidence, not inferred from arm64e hardware.

7. **Run the regression matrix.** For original versus permission-only versus preview-only, record rear/front stock preview, normal-resolution still photo, 1080p recording, app background/foreground, source-image change, >90-second renewal and each third-party app/mode separately. Then test higher-resolution/HDR modes as separate format cases. Verify resulting photos/videos and the remote recipient's third-party frames, not just local preview. Retest A11 with the unchanged arm64 slice before any commercial package release.

## 8. Final diagnosis and decision

**Confirmed:** A14/A16 omit the named preview hooks; their output path remains enabled but deliberately gates connected consumers and uses in-place conversion. The installer removes cross-UID access, and the app config writer does not deliberately reopen that directory. These are independent, instruction/source-backed mechanisms capable of producing the reported real-feed symptom.

**Not yet confirmed:** which of those mechanisms fires on either supplied phone; actual daemon UID/sandbox access, selected pixel format, reached node class, loaded-image/trust state, or an author-documented reason for disabling preview. No observation proves a cameracaptured/PAC crash, and no evidence justifies a universal mediaserverd-only filter.

**Delivered:** read-only diagnosis and reversible permission repair scripts; a guarded preview-only patch generator plus separately staged main/mirror candidates; exact offsets, fresh renderer pseudocode/instructions, package/profile invariants and physical test steps. The existing binaries, installer/filter and production `.deb` remain unchanged. Approve a permanent fix only after a single-variable on-device test identifies the failing stage and the regression matrix passes.
