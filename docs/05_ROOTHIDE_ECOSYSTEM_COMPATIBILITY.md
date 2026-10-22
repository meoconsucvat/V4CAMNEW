# VCNext 0.16.73 (build 37): RootHide ecosystem compatibility audit

Audit date: 2026-10-19 (Asia/Saigon). Scope: read-only package inspection and pinned upstream source review. No target processes were launched, no binaries were changed, and no licensing endpoint was contacted. This report establishes mechanisms and deployment preconditions; it cannot establish zero crashes or zero functional regressions on devices that were not tested.

## 1. Findings that affect deployment

1. **`libroot` is an explicit path API, not a global `open`/`stat`/`access` hook.** RootHide's `libroothide` supplies `jbroot()`; its separate `libvroot`/`libvrootapi` targets provide virtual-root wrappers. A converted legacy package can additionally use AutoPatches. These mechanisms must not be conflated.
2. **The package relies on a compatibility layer.** Its control file has `Pre-Depends: rootless-compat(>= 0.9)`, and all five main binaries have `.roothidepatch` symlinks targeting AutoPatches. Native `jbroot()` usage is preferable in a future source build, but the current observational audit does not justify wrapping or rewriting already-converted binaries.
3. **The observed RootHide root is `.jbroot-<16 hex digits>` under `/var/containers/Bundle/Application`, with a paired writable tree under `/var/mobile/Containers/Shared/AppGroup`.** The `/private/preboot/<UUID>/...` example in the request describes a different rootless layout and is not the path implemented by the reviewed RootHide sources.
4. **PatchLoader dispatches patch modules when images load.** AutoPatches, rather than PatchLoader, parses load commands and changes selected code/string objects in memory. The reviewed code does not re-sign the VCNext files or rewrite their Mach-O headers at boot.
5. **A11 and A13 require different ABI execution paths.** A11 needs the arm64 slice; A13 system processes use arm64e/PAC. The package has an A13-specific install filter, but that is an explicit mitigation, not evidence that every PAC issue is solved.
6. **Bootstrap, Dopamine RootHide, and Relaxin are different execution environments.** Successful app injection in Bootstrap does not establish injection into SpringBoard/mediaserverd or the availability of the package's launchd daemons. The reviewed Relaxin engine explicitly requires arm64e, so it is not an A11 deployment option.

## 2. Source identity and reproducibility

Sources were retrieved from the upstream repositories, not executed. Local copies are under [`evidence/roothide/`](evidence/roothide/); `source-revisions.json` records the initial default-branch queries. Additional branch-specific revisions below are deliberately separate. Files retain upstream line numbering. Source hashes are recorded in [`source-files.sha256.json`](evidence/roothide/source-files.sha256.json).

| Upstream | Revision used | Purpose |
|---|---|---|
| [roothide/Developer](https://github.com/roothide/Developer/tree/c53cc199f1bab7d7ea2fd70f0a14e215b1f3461b) | `c53cc199f1bab7d7ea2fd70f0a14e215b1f3461b` | Public developer contract, entitlements, rootfs/jbroot distinctions |
| [opa334/libroot](https://github.com/opa334/libroot/tree/102348f5e9360ad1f509ae4958bd3ca686347ee8) | `102348f5e9360ad1f509ae4958bd3ca686347ee8` | Standardized explicit path API and fallback implementation |
| [roothide/libroothide](https://github.com/roothide/libroothide/tree/7764c54759009272b4f2f23c18c62b21794fe6dd) | `7764c54759009272b4f2f23c18c62b21794fe6dd` | `jbroot()`, root naming, separate vroot libraries |
| [roothide/PatchLoader](https://github.com/roothide/PatchLoader/tree/76dba6571d25e28f2b6dbdfb88a7e8459b1a5684) | `76dba6571d25e28f2b6dbdfb88a7e8459b1a5684` | Actual image-load dispatcher |
| [roothide/DynamicPatches, AutoPatches branch](https://github.com/roothide/DynamicPatches/tree/9142c7d1d9f578df86e891065c8d2e9f581eabe6) | `9142c7d1d9f578df86e891065c8d2e9f581eabe6` | Generic legacy `/var/jb` patch mechanism |
| [roothide/Dopamine-roothide, 2.x branch](https://github.com/roothide/Dopamine-roothide/tree/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b) | `44d398aea2a2ea2c6dbece1c0db84ddd5f70388b` | Requested Dopamine 2 environment |
| [roothide/Dopamine-roothide, default 3.x branch](https://github.com/roothide/Dopamine-roothide/tree/dc647c56b33431b36baae130c78d9ad54266a54c) | `dc647c56b33431b36baae130c78d9ad54266a54c` | Identity check only; not substituted for 2.x |
| [roothide/Bootstrap](https://github.com/roothide/Bootstrap/tree/053072440b88c9533c43df8cdcceb693d7a78ba4) | `053072440b88c9533c43df8cdcceb693d7a78ba4` | App-enabling/bootstrap behavior and root rerandomization |
| [xz1c/relaxin](https://github.com/xz1c/relaxin/tree/871826c6d7f6e905143a55398219a13bb977bc1d) | `871826c6d7f6e905143a55398219a13bb977bc1d` | Public audit snapshot, target validation and RootHide root layout |

**Version boundary:** the public AutoPatches branch's `control` identifies version **0.6**, whereas this package requires **>=0.9**. It proves the published design, not byte-for-byte behavior of an unknown installed 0.9/1.x/2.x compatibility library. Neither the installed PatchLoader/AutoPatches binaries nor a device package inventory was supplied. Runtime conclusions about their exact coverage remain unresolved. The queried `roothide/AutoPatches` repository does not exist; the actual source is the `AutoPatches` branch of `DynamicPatches`.

The formerly separate `Dopamine2-roothide` GitHub API URL currently resolves to `roothide/Dopamine-roothide`, whose default branch is 3.x. Its current README is a merge-in-progress notice. The 2.x commit above is the relevant pin for this audit; search-engine snapshots of old 1.x pages must not be treated as the current repository identity.

## 3. Path translation: which component does what?

### 3.1 Explicit API versus virtual-root wrapper

The standard `libroot` header exposes `JBROOT_PATH[_CSTRING/_NSSTRING]` and `ROOTFS_PATH` macros calling `libroot_dyn_jbrootpath`/`libroot_dyn_rootfspath`. Its `dyn.c` discovers a jailbreak provider with `dlopen("@rpath/libroot.dylib")` and `dlsym`, then explicitly concatenates prefixes in its fallback converters. There is no registration of POSIX interposition in these reviewed files. See [libroot.h, lines 9-25 and 45-75](https://github.com/opa334/libroot/blob/102348f5e9360ad1f509ae4958bd3ca686347ee8/src/libroot.h#L9-L75) and [dyn.c, lines 82-145](https://github.com/opa334/libroot/blob/102348f5e9360ad1f509ae4958bd3ca686347ee8/src/dyn.c#L82-L145).

RootHide's own `jbroot()` API is implemented in `libroothide`. The Makefile deliberately builds three distinct libraries: `libroothide.dylib` from `jbroot.*`; `libvroot.dylib` from `vroot*`; and `libvrootapi.dylib` from `vrootapi.c`. The last exports API-name trampolines into `vroot_*`. The wrappers include `open`, `access`, `stat`, `fopen`, and spawn functions, but linking/loading `libroot` or `libroothide` alone is not proof that the caller's POSIX imports use those wrappers. See [Makefile, lines 14-51](https://github.com/roothide/libroothide/blob/7764c54759009272b4f2f23c18c62b21794fe6dd/Makefile#L14-L51), [vrootapi.c](https://github.com/roothide/libroothide/blob/7764c54759009272b4f2f23c18c62b21794fe6dd/vrootapi.c), and [vroot.h, lines 60-78 and 178-187](https://github.com/roothide/libroothide/blob/7764c54759009272b4f2f23c18c62b21794fe6dd/vroot.h#L60-L78).

The public developer contract explicitly converts a jailbreak-relative path before passing it to the OS API. For a future native RootHide source build, a VCNext file should conceptually be opened as:

```c
// A path inside the jailbreak tree, expressed relative to that tree.
open(jbroot("/var/mobile/Library/VCNext/CapabilityLease.plist"), O_RDONLY);
```

Do not pass an already expanded runtime root through this operation again. Do not add the legacy `/var/jb` segment to a native logical path just because old rootless strings had it. That segment survives in converted legacy packages through compatibility symlinks and AutoPatches. The core implementation prepends `JBROOT` to an absolute logical path, with special handling for `/rootfs`; it does not generally strip a leading `/var/jb`. See [Developer/interface.md, lines 14-58](https://github.com/roothide/Developer/blob/c53cc199f1bab7d7ea2fd70f0a14e215b1f3461b/interface.md#L14-L58), [jbroot.c, lines 155-200](https://github.com/roothide/libroothide/blob/7764c54759009272b4f2f23c18c62b21794fe6dd/jbroot.c#L155-L200).

### 3.2 Actual randomized root and the `/var/jb` compatibility link

`common.h` defines `JB_ROOT_PARENT` as `/var/containers/Bundle/Application` and `JB_ROOT_PREFIX` as `.jbroot-`. `roothideinit` obtains the current root from its own loaded-library path and validates its random brand. The paired writable location is visible in the Dopamine 2 sandbox-extension code. See [common.h, lines 4-8](https://github.com/roothide/libroothide/blob/7764c54759009272b4f2f23c18c62b21794fe6dd/common.h#L4-L8), [init.c, lines 20-57](https://github.com/roothide/libroothide/blob/7764c54759009272b4f2f23c18c62b21794fe6dd/init.c#L20-L57), and [Dopamine common.m, lines 419-428](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/BaseBin/libjailbreak/src/roothider/common.m#L419-L428).

PatchLoader's packaging creates `jbroot:/var/jb -> /` and a pkgmirror-local `/var/jb` compatibility link. Absolute symlink semantics belong to RootHide's bootstrap/installation path processing; do not reproduce these links literally on an ordinary rootfs. Native processes use an expanded rootfs path, while bootstrap CLI tools normally consume logical jailbreak-root paths through the virtual-root layer. See [PatchLoader/Makefile, lines 20-31](https://github.com/roothide/PatchLoader/blob/76dba6571d25e28f2b6dbdfb88a7e8459b1a5684/Makefile#L20-L31) and [Developer/roothide.md, lines 30-63](https://github.com/roothide/Developer/blob/c53cc199f1bab7d7ea2fd70f0a14e215b1f3461b/roothide.md#L30-L63).

For example, the compatibility path produced from the legacy string can include:

```text
<current-jbroot>/var/jb/var/mobile/Library/VCNext/CapabilityLease.plist
```

The installed compatibility symlink is needed for this to resolve to the intended jailbreak-tree state. The stable source-level representation is `/var/mobile/Library/VCNext/...`, converted when used. Store a logical path or convert with `rootfs()` before persisting a runtime absolute path; a path containing yesterday's randomized root can become stale. Bootstrap's rerandomization explicitly moves both trees ([bootstrap.m, lines 301-333](https://github.com/roothide/Bootstrap/blob/053072440b88c9533c43df8cdcceb693d7a78ba4/Bootstrap/bootstrap.m#L301-L333)).

### 3.3 Root daemon and mobile injection are not separate path-translation rules

The reviewed `jbroot()` conversion does not branch on UID. Both root daemons and mobile/SpringBoard clients must name the same expanded file. Privilege/sandbox checks happen separately; root UID alone is not evidence of all necessary sandbox access. RootHide's developer entitlements document recommends `platform-application`, `no-sandbox`, AppBundles and AppDataContainers access for standalone binaries, and places shared tweak state in `jbroot:/var/` ([entitlements.md, lines 1-24](https://github.com/roothide/Developer/blob/c53cc199f1bab7d7ea2fd70f0a14e215b1f3461b/entitlements.md#L1-L24)).

Locally, `postinst` creates the state tree as `mobile:mobile` and removes group/other access (lines 10-12); the stream daemon runs as `mobile`, network daemon as `root`, and injected libraries inherit their host's security context. Correct translation therefore does not prove all writers can read/write each other's files. The `postinst` cleanup also intentionally deletes the prior capability lease (lines 15-19): an absent lease immediately after install is expected state, not evidence that path translation failed.

## 4. `.roothidepatch` markers, PatchLoader, and AutoPatches

### 4.1 What is actually in the VCNext package?

[`overlay/artifact_preservation.json`](evidence/overlay/artifact_preservation.json) records the original Debian archive members. The archive contains genuine symbolic links named:

```text
Applications/VCNext.app/VCNext.roothidepatch
Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib.roothidepatch
Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib.roothidepatch
usr/libexec/VCNNetworkDaemon.roothidepatch
usr/libexec/VCNStreamDaemon.roothidepatch
    -> /usr/lib/DynamicPatches/AutoPatches.dylib
```

The visible `*.roothidepatch.symlink` files are this Windows extraction's text representation of those symlinks. **`.symlink` is not the runtime marker suffix.** A repackage that accidentally installs only these text files would not satisfy the loader's `<image>.roothidepatch` lookup. No such repackaging was done in this phase. The same evidence verifies all ten main/mirror Mach-O files remain byte-identical to the supplied `.deb`.

### 4.2 Exact PatchLoader control flow

At commit `76dba657...`, the implementation is:

```c
// Simplified, faithful to PatchLoader.c; errors omitted below, described next.
constructor() {
    PLRequiredJIT = dlsym(RTLD_DEFAULT, "PLRequiredJIT");
    if (!PLRequiredJIT) PLRequiredJIT = dlsym(RTLD_DEFAULT, "jbdswDebugMe");
    register_add_image_callback();
    // The callback is suppressed while enumerating existing images.
    for (each already loaded image outside the dyld shared cache)
        image_load_handler(path, header, slide);
    load_init = true;
}
image_load_handler(path, header, slide) {
    patcher = path + ".roothidepatch";
    if (lstat(patcher) != 0) return;
    check_legacy_var_jb_compatibility_symlink();
    assert(PLRequiredJIT() == 0);
    handle = dlopen(patcher, RTLD_NOW);
    InitPatches = dlsym(handle, "InitPatches");
    assert(InitPatches != NULL);
    InitPatches(path, header, slide);
}
```

The callback similarly skips shared-cache images and invokes this handler for later images. See [PatchLoader.c, lines 43-73](https://github.com/roothide/PatchLoader/blob/76dba6571d25e28f2b6dbdfb88a7e8459b1a5684/PatchLoader.c#L43-L73) and [lines 86-136](https://github.com/roothide/PatchLoader/blob/76dba6571d25e28f2b6dbdfb88a7e8459b1a5684/PatchLoader.c#L86-L136). Dopamine 2's systemhook exports `PLRequiredJIT()` and loads `roothidepatch.dylib` ([roothider_main.c, lines 20-23 and 523](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/BaseBin/systemhook/src/roothider_main.c#L20-L23)). This is image loading/injection time, which can occur at daemon start, respring, or `dlopen`; it is not a once-per-boot file conversion.

**Loader failure modes are real and distinct from license failure.** Missing JIT helper and failed `dlopen` use `abort_with_payload`; unsuccessful JIT and absent `InitPatches` assert. A broken `jbroot:/var/jb` compatibility link aborts when the main executable is inside an app bundle. These failure paths can prevent startup before VCNext's own lease/UI checks run. They are not evidence that an invalid lease itself causes an assertion.

### 4.3 The module that inspects load commands

The public AutoPatches implementation performs these operations:

| Source location in `Patches.cpp` | Observed operation |
|---|---|
| 59-77 | Scan `__cstring`; retain strings containing `/var/jb` |
| 173-242 | Scan ARM64 `__text` for `ADR` or adjacent matching `ADRP`+`ADD`; recognize the referenced retained string address |
| 197-200, 230-233 | Replace recognized instruction(s) with `NOP` (`0xD503201F`), then install Dobby instrumentation |
| 29-56 | At the instrumentation point, evaluate `jbroot(oldpath)` and replace the selected saved `xN` register value |
| 80-96 | Rewrite matching `__CFString` buffer and length in memory with `DobbyCodePatch` |
| 99-110 | Enumerate ordinary data pointers for logging; **this routine contains no pointer write** |
| 245-324 | Walk `LC_SEGMENT_64` commands and sections, using ASLR slide to find `__text`, `__cstring`, `__cfstring`, `__data` |
| 544-609 | Selected hashed image paths receive import-table replacements; default `autopatch` calls `auto_patch_machO` |

All locations refer to [the pinned AutoPatches source](https://github.com/roothide/DynamicPatches/blob/9142c7d1d9f578df86e891065c8d2e9f581eabe6/Patches.cpp). The source **reads** Mach-O header/load-command metadata to locate sections. It patches code and constant string objects, not the header. No on-disk signing operation appears in this module or PatchLoader. The package script's statement about PatchLoader finishing “patching + re-signing ... at boot” (`postinst` lines 30-31) is broader than the observed implementation supports.

There is also a separate dyld path expansion mechanism: Dopamine 2 recognizes `@loader_path/.jbroot` library paths and substitutes the current root ([dyldhook/src/roothider.c, lines 12-39](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/BaseBin/dyldhook/src/roothider.c#L12-L39)). This resolves dependent libraries; it does not transform arbitrary application file paths passed to `open()`.

### 4.4 What this cannot transparently guarantee

The published scanner recognizes particular compiler instruction patterns and string sections. It is not evidence of complete translation of dynamically constructed paths, arbitrary `openat`/direct syscall callers, nonadjacent instruction sequences, or every Swift representation. Several API wrappers are merely pass-through and import replacements are selected by image-path hash. A hardcoded-path string plus a marker proves an intended compatibility dependency, not successful transformation at every use site.

`my_fopen` (lines 338-381) additionally checks `pkgmirror` and can read a mirror Mach-O instead of the installed file. This explains a possible compatibility strategy for self-digest routines, but the switch in `InitPatches` selects only certain path hashes, and this public 0.6 source cannot prove that any VCNext image receives that hook in the installed >=0.9 layer. Main/mirror files have different whole-file hashes. Never assume an on-disk self hash, an in-memory code hash, and a CodeDirectory signing hash are interchangeable.

## 5. A11 versus A12+/A13: architecture and hook stability

Apple documents arm64e/pointer authentication on A12 and later A-series processors ([Preparing your app to work with pointer authentication](https://developer.apple.com/documentation/security/preparing-your-app-to-work-with-pointer-authentication)). A11 is the non-PAC arm64 case. On an arm64e process, signing/authentication of indirect function pointers and branch targets is part of the ABI; simply re-signing the code signature cannot correct a wrong ABI, wrong function prototype, or incompatible trampoline.

The overlay's supplied FAT binary has arm64 subtype 0 and arm64e subtype `0x80000002` slices. Both main and mirror are inventoried in [`overlay/static_inventory.json`](evidence/overlay/static_inventory.json). This establishes slice presence, not successful dyld selection, trust, relocation, or safe execution inside a particular system process. The Debian `Architecture: iphoneos-arm64e` field is a RootHide packaging label and must not be used as evidence that the payload lacks arm64.

| Device/process case | Supported conclusion from the evidence | Remaining requirement |
|---|---|---|
| iPhone 8 Plus, `iPhone10,2` / `iPhone10,5`, A11 | Use the arm64 code path; no hardware PAC adaptation should be applied to it | Correct exact OS/host ABI, injection backend, trust and runtime validation |
| `iPhone12,*`, A13 (iPhone 11/SE2 family) | PAC-capable case; package has an explicit install-time mitigation described below | Verify arm64e slice ABI and hook backend on exact OS/process |
| Other A12+ | PAC-capable architecture does not make every device/OS equivalent | Verify matching slice, dyld ABI and selected host separately |

The actual `postinst` behavior, lines 25-56, is important: for `iPhone12,*`, if Camera dylib exists, it rewrites `VCNextCamera.plist` to inject **only `mediaserverd`**. The shipped default filter lists **both `cameracaptured` and `mediaserverd`**. `preinst` lines 7-16 clears stale A13 canary state; it keeps the camera/overlay binaries. No corresponding `iPhone10,*` special filter exists in these scripts. The comments claim a previous PAC crash was corrected by a macOS/Xcode SDK build, but a comment is not a crash-log comparison or runtime test. The filter may be deliberate process-selection containment; it does not by itself prove PAC was the cause.

For maintaining hook stability, preserve the supplied architecture slices and filter semantics during this phase. A future source change needs correctly typed hook/original-function pointers and an injection engine supporting the host's arm64e ABI. Do not transplant instruction offsets, pointer representations, or PAC-specific stubs from A13 to A11. The separate overlay report documents its own initialization/retry behavior; that behavior is not the install script's A13 branch.

Dopamine 2 itself distinguishes arm64e with `hw.cpusubtype`, has separate PAC/PPL prerequisites, and gates an iOS 15 arm64e dyld spinlock workaround. These are environment code paths, not VCNext patches: [DOEnvironmentManager.m, lines 203-218 and 612-643](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/Application/Dopamine/Jailbreak/DOEnvironmentManager.m#L203-L218), [spinlock_fix.c, lines 1-24](https://github.com/roothide/Dopamine-roothide/blob/44d398aea2a2ea2c6dbece1c0db84ddd5f70388b/BaseBin/dyldhook/src/spinlock_fix.c#L1-L24). A stability claim should identify the actual environment build, not merely “RootHide.”

## 6. Environment boundaries: Dopamine 2, Bootstrap, Relaxin

| Environment | Evidence-backed scope | Consequence for VCNext |
|---|---|---|
| Dopamine RootHide **2.x pinned source** | Source advertises arm64 iOS 15.0-15.8.6 / 16.0-16.6.1 and arm64e 15.0-16.5.1; actual `isSupported` checks available exploit prerequisites, so these display strings are not a per-device support guarantee | An appropriate environment for testing the full daemon + system-process injection topology, subject to exact device/OS/build support |
| RootHide Bootstrap | README advertises iOS 15.0-17.0, A8-A17 Pro and M1/M2, and app injection enabled through App List; app-enabling code works on app bundles | Installing an app/package and enabling app injection does not prove SpringBoard or mediaserverd injection or system launchd support; full VCNext equivalence is **not established** from Bootstrap alone |
| Relaxin public snapshot | README says iOS/iPadOS 16.5.1-17.3.1; target-confirmation code rejects non-arm64e, validates exact manifest fields, and maps A12/A13/A14-M1/A15-M2/A16/A17 CPU families | **A11 is excluded** by the engine architecture check; A13 is represented by a CPU profile but still requires exact OS/build/kernel and runtime compatibility |

Bootstrap source/documentation: [README, lines 1-35](https://github.com/roothide/Bootstrap/blob/053072440b88c9533c43df8cdcceb693d7a78ba4/README.md#L1-L35), [AppEnabler.m, lines 145-228](https://github.com/roothide/Bootstrap/blob/053072440b88c9533c43df8cdcceb693d7a78ba4/Bootstrap/AppEnabler.m#L145-L228). Older community guides often state that Bootstrap cannot inject SpringBoard; the current source also has optional `launchd_exploit_available()` paths. This audit therefore does not extrapolate that historical blanket statement into every current Bootstrap variant. The exact Bootstrap version and its system-process execution capabilities must be specified before claiming full VCNext support.

Relaxin source: [README](https://github.com/xz1c/relaxin/blob/871826c6d7f6e905143a55398219a13bb977bc1d/README.md), [RLXTargetConfirmationTask.m, lines 36-45, 126-155 and 198-209](https://github.com/xz1c/relaxin/blob/871826c6d7f6e905143a55398219a13bb977bc1d/RelaxinEngine/Stages/Preflight/RLXTargetConfirmationTask.m#L36-L45). This primary-source scope differs from third-party “A15+ only” guides; neither broadens the snapshot into an A11-compatible tool.

Relaxin's root scanner uses the same two `.jbroot-<brand>` parents and rejects roots carrying `.bootstrapped`/`.thebootstrapped` markers rather than adopting a Bootstrap-app installation. A matching RootHide path API therefore does not imply that one installed environment can be reused by another: [RLXBootstrapRootScanner.m, lines 20-61 and 121-169](https://github.com/xz1c/relaxin/blob/871826c6d7f6e905143a55398219a13bb977bc1d/RelaxinEngine/Bootstrap/RLXBootstrapRootScanner.m#L20-L61).

## 7. Verification boundary and outstanding deployment evidence

All three requested mechanisms are answered at source/package level: explicit versus compatibility path conversion; real marker/loader/module responsibilities; and architecture/environment distinctions. Runtime compatibility remains **unvalidated** because no target device, installed dependency inventory, crash logs, or controlled system-process test was part of this phase.

Before a reliability claim, record the exact iPhone model, iOS build, jailbreak build, installed PatchLoader/rootless-compat/ElleKit versions and hashes; verify both root and mobile clients resolve the same state tree after rerandomization; verify actual loaded image slice and marker resolution; then observe SpringBoard and camera host startup/restart behavior with valid, absent, expired and malformed lease state. Confirm the A13 install filter on-device rather than assuming the package script succeeded. Capture crash/termination evidence and frame/IPC continuity on both A11 and a PAC device. This report has not performed or passed those device tests.

The companion [`CODEX_AUDIT_REPORT.md`](CODEX_AUDIT_REPORT.md) contains the overlay's exact instruction offsets, timer/notification call paths, digest search boundary and lease-failure behavior. Its conclusions concern VCNext's own code; PatchLoader's independent early abort/assert paths above remain a separate failure domain.
