# Commercial rebranding and dynamic support messaging verdict

Date: **2026-10-22, Asia/Saigon**. Target: the current VCNext v0.16.73/build 37 package and local server source. This is an observational audit: no production server requests, credential/database reads, notifications, signing, package rebuilding or on-device execution were performed. Product files remain unchanged.

## 1. Decision

**Server-controlled support text is feasible for manual sign-in failures, with two important restrictions: the client uses a two-line UILabel, and two legacy uppercase error identifiers append the original support handle.** It does not open a login UIAlertController. Server-only changes cannot create an unlimited, scrollable, clickable contact panel or replace errors generated before an HTTP JSON response arrives.

**External display-name, loose-icon and Debian metadata changes are the preferred branding path.** Keep executable/package identities and runtime interfaces unchanged. This exact package has no populated Info.plist/resource sealing slots, so changing those external resources does not itself require rewriting the current executable CodeDirectories. A later signer/build may introduce those seals; check the actual candidate rather than assuming the same layout.

| Requirement | Evidence-backed verdict |
| --- | --- |
| Change manual-login failure text/contact without a client update | Supported through a nonempty JSON string `message`, preserving existing status/error codes |
| Show Telegram + Zalo + Facebook + reason in full | Not guaranteed: the login error label is limited to **two rendered lines** |
| Vietnamese, newline, URL and phone-number text | Compatible with JSON/Foundation/NSString; screen fit remains a device test |
| Dynamic support for every failure everywhere | Not supported solely by server text: restore/local validation/TLS/identity-verification paths differ |
| Change SpringBoard name/icons without editing Mach-O | Feasible with the existing loose-resource layout and identity-preserving staging |
| Replace hardcoded navigation titles | Technically possible, but requires constant-string, code-page and trust analysis; unnecessary for dynamic error text |
| Certify 100% runtime stability from this audit | Not established; no physical device was run, and the earlier A14/A16 camera issue is a separate release concern |

### Current artifact binding

| Artifact | SHA-256 |
| --- | --- |
| `VCNext-custom-roothide.deb`, 496,292 bytes | `4d1f8bf580e1c7699865fbafec4302ad28ab9df9a155b8bc13d68330ef51675b` |
| Main `Applications/VCNext.app/VCNext` | `cb09e14b403151b31e81ed5c2eb40fea014ed1357067818cc47ac1c0517cba4f` |
| pkgmirror app executable | `036b228f3fa472275e84f39d1abb50552fb008c695e9db4f6536c579ad8462d3` |
| App `__TEXT,__text`, both copies | `4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2` |

Both application executables are thin arm64. All addresses below are **unslid arm64 VAs** with base `0x100000000`; explicitly labelled file offsets are different. Both copies match their current package members. Main and mirror have different signature layouts and must be checked separately.

The REA target binding succeeded. Its pseudocode adapter rejected incompatible upstream parameters; this failed result is not treated as decompilation evidence. Direct upstream IDA on the owned private copy supplied fresh address-marked decompilation, independently checked against current bytes using Capstone and decoded Objective-C selector stubs. The large `buildInterface` pseudocode preview is truncated; the complete bounded instruction listing supplies the two-line-label evidence. See [analysis record](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/client_analysis_record.json), [fresh instructions](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/client_fresh_arm64.asm), and [client inventory](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/client_inventory.json). The analysis session was closed.

## 2. Exact dynamic error flow

### Transport accepts typed server messages on failed HTTP responses

The generic request method installs completion block `sub_1000064A4`. It parses the body with `NSJSONSerialization` at actual call `0x10000650c`, accepts a dictionary, and distinguishes HTTP **200–299** from other status codes (`0x100006580`–`0x100006594`). With no overriding transport error, 400/401/403/426 follow the same failed-HTTP branch:

1. Read dictionary `message` at `0x1000065a4` and verify NSString at `0x1000065bc`–`0x1000065cc`.
2. Read `error`, also requiring NSString; wrong types use the fallback identifier `HTTP_ERROR`.
3. Call `errorWithCode:message:identifier:` at **`0x1000066a8`**, carrying HTTP status, selected message and identifier.
4. Dispatch the reply onto the main queue at `0x100006724`.

The constructor `-[VCNef09a60940d83a952fa8 errorWithCode:message:identifier:]` starts at `0x100005af4`. It stores the nonempty supplied message under `NSLocalizedDescriptionKey`, stores the identifier under `identifier`, and constructs NSError domain `com.vcnext.account`. A missing, wrong-type or empty message ultimately falls back to `Account request failed`. There is no message substring/character-count cap in these inspected functions. [Transport decompilation](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x1000064a4.json), [NSError constructor](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x100005af4.json).

Apple documents that `localizedDescription` reads that userInfo entry. JSON data supports UTF-8; the current server already emits UTF-8. [NSError documentation](https://developer.apple.com/documentation/foundation/nserror/localizeddescription), [JSON decoding documentation](https://developer.apple.com/documentation/foundation/jsonserialization/jsonobject%28with%3Aoptions%3A%29-8demi?language=objc).

### Challenge and login errors converge on the manual sign-in label

The relevant fresh cross-references are:

| Function/address | Observed role |
| --- | --- |
| `0x100006ba4` | Challenge reply: an existing transport/HTTP error goes to its completion; only successful responses enter signed-challenge verification |
| `0x1000072a8` | After challenge: existing error is forwarded at `0x100007318`; otherwise constructs the login POST |
| `0x100007598` | Login reply: HTTP error bypasses success parsing; completion forwards the error at `0x10000767c` |
| `0x100007730` | Successful-response/session consumer, **not** the failed-HTTP alert implementation |
| `0x10000c100` | `signIn`: supplies UI completion block `sub_10000C388` to `loginWithUsername:password:remember:completion:` |
| `0x10000c48c` | On manual-login failure, calls `displayMessageForError:` |
| `0x10000c4b4` | Calls `errorLabel.setText:` with that returned string |

Fresh decompilations: [challenge](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x100006ba4.json), [post-challenge/login submission](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x1000072a8.json), [login reply](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x100007598.json), [manual UI completion](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x10000c388.json).

The observed reconstruction is:

```objc
// Failed HTTP response, excluding an overriding transport error:
NSString *message = isNSString(json[@"message"]) ? json[@"message"]
                                                    : @"Account request failed";
NSString *identifier = isNSString(json[@"error"]) ? json[@"error"] : @"HTTP_ERROR";
NSError *error = accountError(status, message, identifier);

// Manual sign-in UI failure:
NSString *display = error.localizedDescription ?: @"Sign in failed";
if ([identifier isEqualToString:@"INVALID_CREDENTIALS"] ||
    [identifier isEqualToString:@"DEVICE_LIMIT"])
    display = [display stringByAppendingString:@"\n@toilaluyen"];
self.errorLabel.text = display;
```

This is explanatory pseudocode, not recovered source. The client compares identifiers **case-sensitively** at `0x10000c088`/`0x10000c09c` and appends the legacy suffix at actual call `0x10000c0b0`. [Message selection decompilation](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x10000bf90.json).

Therefore `message` is preserved for normal manual-login errors **except for that conditional suffix and the visual line limit**. It is not unconditionally verbatim on every screen. The app's only direct call through the inspected `alertControllerWithTitle:message:preferredStyle:` stub is `0x100016540`, in `showMediaImportError:`; its title is `Import failed`. That is a different error path. [Media-import alert](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x1000164f0.json).

### The actual display limit is two lines

In login `buildInterface`, `errorLabel` is fetched at `0x10000a50c`. Current bytes then decode as:

```asm
0x10000a51c  42008052  mov w2, #2
0x10000a520  a0760094  bl  0x100027fa0   ; setNumberOfLines:
```

The label has a 12-point font and centered text (`0x10000a4a4`–`0x10000a4fc`). No `setLineBreakMode:` selector is present in this app's inspected bytes. Apple documents the default UILabel line-break mode as tail truncation, and `numberOfLines` limits rendered lines. The containing scroll view does not remove the label's line count. [UILabel layout](https://developer.apple.com/documentation/uikit/uilabel?changes=_8__2), [line-break default](https://developer.apple.com/documentation/uikit/uilabel/linebreakmode?changes=__3).

**There is a real client display limit, but no discovered fixed byte/character truncation threshold in the inspected message pipeline.** A line may wrap before an explicit newline, so even two source lines can exceed two rendered lines. Vietnamese/emoji/URLs use different widths; there is no reliable universal maximum character count. UIKit still receives the full string, while the screen may omit its tail. Plain `setText:` supplies no HTML/Markdown interpretation, URL handler, contact buttons or copyable text view.

### Cases server text cannot fully control

- Empty username/password is rejected locally at `0x10000c310`; no server response exists to decorate.
- DNS, network, TLS/pin rejection and invalid signed challenge/lease responses can yield client-generated text instead of an HTTP `message`. A success-status body containing only an error message is not an alternative: it enters success parsing and fails that contract.
- Stored-session restore has a different UI callback at `0x1000092f8`. Account-domain 401/403 classification (`0x100008d78`) skips its generic error-label assignment; other failures can display the hardcoded `Could not restore the session. Sign in again.` at `0x1000093d0`. That callback does **not** render the server message through `displayMessageForError:`. Do not promise branded text for automatic expiry/restore merely because manual sign-in shows it. [Restore callback](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x1000092f8.json), [classification](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x100008d78.json).

## 3. Recommended dynamic support contract

The current local source catches `store.AuthError` and emits `{"ok":false,"error":...,"message":...}` at [server.py](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:304). Its serializer already uses `ensure_ascii=False`, UTF-8 and an encoded-byte Content-Length at [server.py](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:268). These actual wire codes differ from the proposed uppercase labels:

| Customer condition | Current HTTP / wire error |
| --- | --- |
| Wrong password | 403 / `wrong_password` |
| Unregistered account | 403 / `invalid_credentials` during challenge |
| Expired account | 403 / `account_expired` |
| Device quota exceeded | 403 / `device_limit_reached` |
| Account disabled | 403 / `account_disabled` |
| Unsupported build/artifact | 426 / `unsupported_client` |

`user_not_found` exists in a credential helper that the current HTTP login path does not call. The current lowercase wire identifiers also avoid the two exact uppercase legacy-suffix matches. Preserve these identifiers and statuses; do not normalize them to uppercase as an incidental branding edit. [Source-cited server findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/server_findings.md).

The narrow implementation is a presentation-only message builder at the failed-JSON-response boundary, with trusted owner-controlled contact configuration. It should preserve HTTP status, `error`, auth decisions, device/quota checks, notification classification and all signed success payloads. A server configuration reload/restart can then change displayed contacts without changing the client executable or its signature. No new app build is necessary for the manual-login path described above.

Use a short reason plus **one short support handle or URL**, for example the following placeholder-only body:

```json
{"ok":false,"error":"wrong_password","message":"Sai mật khẩu.\nHỗ trợ: @your_support"}
```

Store actual newline characters in the message value; JSON represents them as `\n`, which decoding restores. Telegram, Zalo and Facebook can all be maintained on a support landing page referenced by a short URL. That URL is still plain label text, not a proven tappable link. Full three-channel details or an interactive support dialog require a separately implemented UI change. Do not put bot tokens, passwords, session/device material or private exception details into public messages.

Retain generic public missing-user text rather than adding account enumeration during a branding change. Test actual challenge failure and actual login failure, not an unused helper. Also test malformed JSON, 426, transport failure, expired automatic restore, long text and small-screen wrapping. A Python Unicode/newline roundtrip passed; it is transport evidence, **not a physical UIKit layout test**.

## 4. External name, icon and metadata rebranding

### Display names and bundle identity

Both [main Info.plist](/C:/Users/Admin/Desktop/vcnextnew/extracted/data/Applications/VCNext.app/Info.plist) and [mirror Info.plist](/C:/Users/Admin/Desktop/vcnextnew/extracted/data/var/mobile/Library/pkgmirror/Applications/VCNext.app/Info.plist) currently declare `CFBundleDisplayName = CFBundleName = V4HCAM Next`. Change only those visible/fallback name strings for this scope. The main plist is XML (1,267 bytes), the mirror is binary (758 bytes); their parsed dictionaries are identical. Preserve valid plist structure and compare dictionaries after editing, rather than requiring raw XML/binary equality. Apple defines the display-name/fallback roles and recommends a short bundle name. [Apple bundle keys](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/CoreFoundationKeys.html).

**Keep `CFBundleIdentifier = com.vcnext.app` for this branding release.** This is a scoped compatibility recommendation, not a claim that iOS universally forbids changing an identifier. Such a change is an application identity/state migration, requiring separate registration, preferences, signing and Keychain validation:

- Actual Keychain query `0x100004ed0` uses fixed service **`com.vcnext.account`**, generic-password class and an account string, with no explicit access-group entry. Main entitlements contain no `application-identifier` or `keychain-access-groups`; mirror has no entitlement blob. Do not invent an observed `com.vcnext.app` Keychain group. Implicit/default Keychain authorization and remembered state still require testing after any identity/signing migration. [Keychain query](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/ida_0x100004ed0.json).
- Shared storage paths are literal `/var/jb/var/mobile/Library/VCNext/...`, independent of the display name. Neither display-name edits nor a bundle-ID edit automatically relocates them.
- RootHide's marker is beside the executable: `VCNext.roothidepatch`. PatchLoader constructs `"%s.roothidepatch"` from the image path; it is not named after the bundle identifier. Preserve the folder, executable and all five marker symlinks. [Pinned PatchLoader source](https://github.com/roothide/PatchLoader/blob/76dba6571d25e28f2b6dbdfb88a7e8459b1a5684/PatchLoader.c#L43-L65).
- Maintainer scripts call uicache for `Applications/VCNext.app`; Debian `Package: com.vcnext.app` matches the pkgmirror control directory. Those names remain integration interfaces. A NetworkDaemon bundle-ID string hit also exists, with its consumer unresolved in this audit; it is not used as proof of a specific dependency.

### Exact loose-icon inventory

Both bundles declare **`CFBundleIconFiles = ["AppIcon"]`**, with no `CFBundleIcons`, `CFBundleIconName`, `Assets.car`, localized Info overrides or app extensions. Existing files are:

| File in each app bundle | Dimensions | Current format |
| --- | --- | --- |
| `AppIcon.png` | 60 × 60 px | Standard PNG, RGBA, 8 bits/channel |
| `AppIcon@2x.png` | 120 × 120 px | Same |
| `AppIcon@3x.png` | 180 × 180 px | Same |
| `BrandLogo.png` | 256 × 256 px | Same; separate in-app logo, not a SpringBoard icon declaration |

All four fully decode, have no CgBI chunk and are non-interlaced. Existing alpha ranges from 220 to 255. For conservative icon replacement, preserve exact filenames/dimensions, use standard sRGB PNG with opaque icon art, and let iOS apply its icon shape. External PNG byte lengths need not match. Replace both main/mirror copies. The login builder calls `imageNamed:@"BrandLogo"`; replacing SpringBoard icons alone will not replace that header image or hardcoded titles. [Measured assets and signing details](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/assets_findings.md), [machine-readable inventory](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/assets_inventory.json).

### Actual resource-seal state: an important exception

Neither current bundle contains `_CodeSignature/CodeResources`. Main app's SHA-256 CodeDirectory has zero/absent Info slot 1 and resource slot 3. Mirror's SHA-1 and SHA-256 directories have zero/absent Info slot 1 and only two special slots, so no resource slot 3. Apple Security's `slotIsPresent` treats zero/out-of-range slots as absent. Neither executable has a CMS entry; all three CodeDirectory flags are `0x0`, so they should not be described as having an explicit `CS_ADHOC` flag. [Pinned Apple implementation](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/codedirectory.cpp#L247-L261).

**Consequently an external-only display-name/icon edit does not invalidate an existing Info/resource seal in these exact copies: those seals are absent.** It also leaves executable bytes, code-page hashes, cdhash and the measured text digest unchanged. No executable page rehash is required solely for those external edits.

For an ordinarily sealed bundle or a later signing pass that introduces seals, Info slot 1 and CodeResources slot 3 must reflect the final resources. Code-page rehash alone cannot repair external resource seals. Complete the supported bundle-signing/trust workflow with preserved entitlements/requirements where applicable; avoid an indiscriminate `ldid -S` pass that replaces entitlement policy. Absence of a seal does not prove a particular RootHide installer/runtime will accept the candidate. [Apple signing-hash model](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes).

### Step-by-step safe staging checklist

1. **Snapshot the current artifact** and work in a new staging tree. Record exact hashes and preserve the existing package for rollback. Actual brand name, artwork and public contacts have not been supplied, so this audit does not invent or publish them.
2. **Change only both visible-name fields** in both app Info dictionaries. Preserve bundle ID, `CFBundleExecutable = VCNext`, folder `VCNext.app`, application version/build 37, platform requirements and usage permissions. Confirm valid plists and equal main/mirror dictionaries.
3. **Replace the three existing icon files** at their measured sizes in both bundles. Optionally replace 256-pixel BrandLogo to update the login header. Fully decode candidate images. Keep existing resource names: the current package builder iterates original archive member names, so a newly named file is not automatically packaged.
4. **Update visible Debian fields** in both [primary control](/C:/Users/Admin/Desktop/vcnextnew/extracted/control/control) and [mirror control](/C:/Users/Admin/Desktop/vcnextnew/extracted/data/var/mobile/Library/pkgmirror/DEBIAN.com.vcnext.app/control): `Name`, `Author`, `Description`, `Section`, and owner-approved `Maintainer`. Preserve valid control-field/continuation syntax. Keep `Package`, architecture, dependencies and pre-dependencies unchanged. For an actual upgrade use an appropriate Debian package revision while retaining the client's app build `37`; recompute Installed-Size if resources materially change.
5. **Preserve archive file types/metadata.** The five markers must remain real symlinks to `/usr/lib/DynamicPatches/AutoPatches.dylib`, not `.symlink` text files. Keep executable/maintainer-script modes and bundle traversal/read permissions. Avoid recursive chmod/chown during cosmetic edits. Current tar metadata differs between main/mirror; use the archive-aware builder rather than Windows file attributes.
6. **Reinspect the final candidate's seals.** Under this exact unsealed external-resource layout, all ten Mach-O files should remain byte-identical for name/icon-only branding. If a signing workflow creates new seals, validate all affected slots/resources and target admission. Do not delete/zero a newly present seal to avoid signing.
7. **Audit the separately built package** before distribution: canonical AR headers, Zstandard tars, correct control and both resource copies, five genuine symlinks, original runtime filters/paths, executable hashes and CodeDirectories. No package was built in this audit.
8. **Test on a controlled phone:** install using the established RootHide workflow, run its existing RootHide-aware uicache registration for the unchanged app path, confirm SpringBoard name/icon, launch, remembered credentials, manual login errors and camera/overlay behavior. Check both scale variants and small-screen text. Do not delete Keychain/session/container state merely to refresh a cached icon. The previous A14/A16 frame failure still requires its separate regression procedure.

## 5. Hardcoded UI-string edits: feasibility and boundaries

The exact title **`V4HCAM Next`** is 11 ASCII/UTF-8 bytes at file **`0x2c16b`**, VA `0x10002c16b`, in `__TEXT,__cstring`. Its NSConstantString object is at file **`0x35758`**, VA `0x100035758`, in **`__DATA_CONST,__cfstring`**. Its explicit length word is at **`0x35770`** and currently equals 11. The pointer is an encoded `DYLD_CHAINED_PTR_64_OFFSET` word with fixup-chain metadata, not a plain pointer to overwrite.

Fresh ADRP+ADD references to the shared object occur at `0x100009d8c`/`0x100009d90`, `0x10000dbf0`/`0x10000dbf4`, and `0x10000eb40`/`0x10000eb44`. The home navigation `setTitle:` call is `0x10000dbfc`. The same object therefore has multiple UI consumers; changing Info.plist does not replace these hardcoded titles. [String analysis](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/strings_findings.md), [fresh string instructions](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/rebranding/strings_fresh_arm64.asm).

| Proposed edit | Actual consequence |
| --- | --- |
| Exactly 11 replacement ASCII bytes, same address/NUL | Preserves addresses and current constant length; still changes signed code pages and every user of the shared literal |
| Shorter text padded with NULs to the old span | **Insufficient alone**: NSConstantString still declares length 11. Inspect/update explicit length and all aliases/consumers; C-string termination rules are not the entire NSString contract |
| Longer in-place text | Overwrites neighboring bytes unless independently verified spare capacity exists; none is approved here |
| Insert/delete file bytes to make room | Shifts mapped content and invalidates references, load-command offsets, fixups and signature layout without a relocation-aware rebuild |
| Vietnamese raw byte substitution | Must account for actual encoding, byte count and constant flags/length semantics; visible character count is insufficient for the existing ASCII constant layout |

A different byte length does **not inherently** corrupt ADRP+ADD if the referenced address stays fixed and all storage/metadata are valid. The danger is overflowing its allocation, shifting targets, or leaving incompatible constant/fixup metadata. Inspect shared/suffix/interior references; do not globally replace brand words. Another `V4HCAM` occurrence is the functional path `/var/mobile/Library/Application Support/V4HCAMNext/Media` at file `0x2cc70`.

For the exact title allocation, the changed signed code-page index is **44** (`0x2c000`–`0x2cfff`). Editing the explicit constant length also affects page **53** (`0x35000`–`0x35fff`). Recompute the relevant code-slot hashes in **all three app CodeDirectories**: main SHA-256 and mirror SHA-1 plus SHA-256, all with 4096-byte pages. Do not alter special slots unless their actual content changes. Page-hash consistency changes the CodeDirectory/cdhash and does not establish target trust. These current app copies have no CMS; if a later candidate has one, modifying its authenticated CodeDirectory requires the corresponding signing treatment.

The measured app digest routine selects **`__TEXT,__text`**, not all of `__TEXT`; fresh parser comparisons are at `0x1000216a0`/`0x1000216b8` and SHA-256 call at `0x100020114`. A cstring/constant-only change preserves that particular `4c10bf4d…` digest. Editing ADRP/ADD, label configuration or other executable instructions changes it and can invalidate the challenge/client-artifact contract. This section-specific observation does not certify every other runtime check.

**Recommendation:** use server messages for dynamic support, external resources for visual branding, and keep executable labels unchanged unless the owner separately requires that work. Changing the two-line UI limit is an executable/UI modification with layout and digest implications, not an automatic benefit of rebranding.

## 6. Hard boundaries and release validation

For this cosmetic scope, do not change protocol keys/error identifiers, lease/challenge fields, Tag 1/2/3 authority configuration, build/digest checks, hardware bindings, PAC/hook instructions, ABI validation, camera profiles, injection filters, Darwin notification names, storage paths, executable/folder/package identities, or RootHide marker names/targets. Do not blindly overwrite chained pointers, clear entitlements/seals, or equate code-page equality with dyld/AMFI acceptance.

The read-only reproducers completed successfully:

```text
python -X utf8 scripts/audit_rebranding_client.py
python -X utf8 scripts/audit_rebranding_assets.py
python -X utf8 scripts/audit_rebranding_strings.py
```

Results bind the UI findings to current bytes, verify loose PNGs/main-mirror metadata, confirm current app code pages have **zero mismatches across all three CodeDirectories**, and preserve the production package hash. These are static/host-side results. No new signing, phone launch, icon-cache result, live support response, commercial deployment or resolution of the A14/A16 camera issue is claimed.

**Formal verdict:** proceed with a separately staged, external-resource branding change and a narrowly scoped server message configuration. Do not sign off on full multi-channel login alerts or universal dynamic error branding with this unchanged client. Obtain actual two-line presentation, registration, authentication and camera/overlay regression results before distributing a branded package.
