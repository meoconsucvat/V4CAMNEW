# VCAMPLUS commercial package and support-message re-audit

Date: **2026-10-22, Asia/Saigon**. Artifact: `dist/VCAMPLUS-roothide.deb`, v0.16.73/build 37 lineage.

## 1. Formal verdict

**The staged package passes archive, title-patch and code-page integrity checks. Production-package isolation is verified directly on the VPS and through its public HTTPS download. The authorized unknown-account test returned the exact branded response, and the owner confirmed its Telegram alert arrived.**

**The claim that every branding/message change is complete is not confirmed.** The packaged mirror Debian control is still unbranded; four refresh/session error variants retain one-line messages; and two newline-separated source lines do not guarantee complete display in the two-line UIKit label. Resolve those commercial conformance gaps and complete target signing/admission/UI tests before general distribution. This audit does not certify the previously reported A14/A16 frame-injection failure as fixed.

| Area | Result |
| --- | --- |
| Exact staged size/hash | PASS: 479,204 bytes; supplied SHA-256 matches |
| AR structure, canonical modes, tar checksums | PASS |
| Five real AutoPatches symlinks | PASS |
| Both app title bytes and NSConstantString length | PASS |
| All 10 binaries / 14 slices / 21 CodeDirectories | PASS: zero code-page mismatches |
| All executable text vs production baseline | PASS: unchanged |
| Both icon sets / Info display names | PASS |
| Both Debian control copies branded | **FAIL: mirror control retains original branding** |
| Six manual-auth errors | PASS in isolated handler tests |
| All equivalent session/refresh errors branded | **FAIL: four unbranded variants remain** |
| Live unknown-account HTTPS error | PASS: 403, exact UTF-8 message and lowercase identifier |
| Live Telegram delivery | PASS for one rejection, confirmed by owner |
| Production original package unchanged | PASS at observed VPS path and public endpoint |
| iOS trust admission, screen fit and camera regressions | NOT TESTED on a physical device |

The audit read package members in memory, inspected current bytes, and ran isolated tests. It did not execute the builder, patch binaries, replace packages, restart production services, modify accounts or download private session/key data. Exactly **one** challenge rejection request was made after explicit user authorization; no login/activation/device enrollment was performed.

## 2. Package identity and archive verification

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Staged commercial `dist/VCAMPLUS-roothide.deb` | 479204 | `ff13f266d898a02173224645ea0d81e47bad508ca965cd5c37e976512d71c558` |
| Local production baseline `VCNext-custom-roothide.deb` | 496292 | `4d1f8bf580e1c7699865fbafec4302ad28ab9df9a155b8bc13d68330ef51675b` |

The AR magic is `!<arch>\n`; member order, lengths, alignment/padding and header terminators validate. Each raw mode field is exactly ASCII **`100644  `**, hex **`3130303634342020`**. `debian-binary` contains `2.0\n`.

| AR member | Stored bytes | SHA-256 |
| --- | ---: | --- |
| `debian-binary` | 4 | `d526eb4e878a23ef26ae190031b4efd2d58ed66789ac049ea3dbaf74c9df7402` |
| `control.tar.zst` | 1845 | `435fe2adc5740c3a21d38f8011ebf20d561a281a8f5581da8837f96c748b748f` |
| `data.tar.zst` | 477166 | `fd5f5bdf7c67a08f1dee683abfa88695386859e30f330ee089a0d161a6ca330c` |

Both Zstandard streams decompress. The independent checker explicitly recalculates each raw 512-byte tar header checksum with its checksum field replaced by spaces. All **5 control + 59 data = 64 headers** match the stored octal sums. Member paths/types, duplicate checks and end markers pass. The uncompressed control tar is 10,240 bytes, SHA-256 `7bc35c3cb2cadaae6c9b6a320bad8d9eaf5718b4839572c1b6b12b7261e8c1d9`; data tar is 3,072,000 bytes, SHA-256 `7be5403b40211daa1f9218fa11eb38d945edc01392fac0f88a03afadfd0f24e1`.

These five members have **raw typeflag `2`**, zero-sized payload and exact link target `/usr/lib/DynamicPatches/AutoPatches.dylib`:

```text
Applications/VCNext.app/VCNext.roothidepatch
Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib.roothidepatch
Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib.roothidepatch
usr/libexec/VCNNetworkDaemon.roothidepatch
usr/libexec/VCNStreamDaemon.roothidepatch
```

No package members were added/removed relative to production. Twelve data members changed: four PNGs, Info.plist and the app executable in each app copy. Only outer `control` changed in the control tar. Owner/group/mode/link metadata is preserved. Primary `preinst`, `postinst`, `prerm` remain byte-identical to baseline and pass shell syntax checks; the main/mirror `prerm` difference already existed. Main/mirror `preinst` and `postinst` are identical. No installer body was executed.

See [raw archive/resources evidence](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/archive_resources.json) and [archive findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/archive_findings.md).

## 3. Option 2 Mach-O verification

Both packaged application executables have:

```text
file offset 0x2c16b, 12 bytes:
56 43 41 4d 50 4c 55 53 00 00 00 00   VCAMPLUS + four NULs

file offset 0x35770, little-endian uint64:
08 00 00 00 00 00 00 00               NSConstantString length = 8

__TEXT,__text SHA-256:
4c10bf4d3a643ad2cacff54575dbbfaa970b775c6048df9ae2461d6b719fbab2
```

This correctly handles the earlier shorter-string concern: it changes both the backing bytes and the explicit length. The NSConstantString object starts at `0x35758`; its first 24 bytes, including flags and encoded pointer/fixup words, are unchanged. All **2,929 inspected chained pointer words per app**, the chained-fixup payload and relevant instruction references are preserved. No additional constant-string object points into the modified slot in the inspected constant table.

The shared title object's fresh ADRP+ADD references remain at `0x100009d8c/0x100009d90`, `0x10000dbf0/0x10000dbf4`, and `0x10000eb40/0x10000eb44`; home `setTitle:` remains at `0x10000dbfc`. These are unslid arm64 VAs, unlike the file offsets above. [Fresh title instructions](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/macho_title_xrefs.asm).

| Main package path; mirror shown separately | Slices | CodeDirectories | Page mismatches | Staged file SHA-256 |
| --- | ---: | ---: | ---: | --- |
| `Applications/VCNext.app/VCNext` | 1 | 1 | 0 | `9aa6bb7cd1e7c4623ee1fd6c0a58f339d7efdcb760490edae634d99e4c9c08d3` |
| `Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib` | 2 | 2 | 0 | `901319d0cf57ff00749fbb4e3ac4095923c5cce2d428475486fd5f386a8a6e6e` |
| `Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib` | 2 | 2 | 0 | `b13d157842de570f3a1799d8aa9c09973b83b2c82c478bebe0ae685a2177f2a7` |
| `usr/libexec/VCNNetworkDaemon` | 1 | 1 | 0 | `71653dbdec06fab84e54142dcdc63ad5db621b5f3204cd71914a64e8aad2167b` |
| `usr/libexec/VCNStreamDaemon` | 1 | 1 | 0 | `97767570df5baa577deb02a6fd1c11759ded204dc4038eee3c677b2b90dc1a53` |
| `pkgmirror/Applications/VCNext.app/VCNext` | 1 | 2 | 0 | `a805a65895d259b0ae18f5d4b0c58771dfc8fd55d9e894e9cb07257d38607376` |
| `pkgmirror/Library/MobileSubstrate/DynamicLibraries/VCNextCamera.dylib` | 2 | 4 | 0 | `c244b61a0247bdbd88eac5a7127a9c5f4df30907b8270b66ebfca1d908e2b32a` |
| `pkgmirror/Library/MobileSubstrate/DynamicLibraries/VCNextOverlay.dylib` | 2 | 4 | 0 | `8c3ca529c959b2fb86f97f7af7b67590634f72c8bf53c54384a0e392c54d5412` |
| `pkgmirror/usr/libexec/VCNNetworkDaemon` | 1 | 2 | 0 | `0e407e3684be4a9ff479a0c2d87b7af18bcd7e7074b2243311d6f91b97919898` |
| `pkgmirror/usr/libexec/VCNStreamDaemon` | 1 | 2 | 0 | `e489221f3dab220e747f5d6f4d0a5b8ce18b4399b19c69ce6ca2d090d3a6a965` |
| **Total** | **14** | **21** | **0** | |

`pkgmirror/` abbreviates `var/mobile/Library/pkgmirror/` in that table. The eight non-app files are completely byte-identical to production baseline. Both apps have unchanged file lengths; their differences are strictly confined to the title slot, length word and code-slot hashes for 4096-byte page indexes **44** (`0x2c000`) and **53** (`0x35000`). There are 74 changed bytes in main and 114 in mirror, including the three CodeDirectories' hash-array changes.

All observed special-slot bytes and embedded requirements/entitlements are preserved; nonzero embedded special-slot hashes validate. Info.plist/resource slots are zero or absent, and no CodeResources file is packaged. There is no CMS signature blob; CodeDirectory flags remain `0x0`, not an explicit `CS_ADHOC=2` flag.

**Signing assessment:** Option 2 is internally consistent and preserves the measured application text contract. It changes app cdhash values. Valid page hashes alone do not prove target dyld/AMFI admission, registration, entitlement availability or installation behavior. Use the established target-compatible signing/trust installation workflow and test the final installed images. Do not add a generic signing pass that drops required entitlements, or infer a PAC/runtime guarantee from unchanged instructions.

The title edit also does not replace every other brand literal: existing logout/wireless-data text and the legacy support suffix remain elsewhere. Those were outside the selected centered-title patch. [Full Mach-O evidence](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/macho_integrity.json), [findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/macho_findings.md).

## 4. Icons, Info.plist and Debian metadata

Both copies of each PNG are identical. All chunks' CRCs validate; each image fully decodes as standard non-interlaced **RGBA8 PNG**, alpha 255 throughout, without CgBI. Pixels exactly match the present 640×640 JPEG converted to RGBA and resized with Lanczos. The source JPEG SHA-256 is `8fc6f2666fe0fdf58ac4c30e6c1182efd4c6b87831c2507aa1aea702defdebcb`.

| Filename | Dimensions | Bytes | SHA-256, same in main/mirror |
| --- | --- | ---: | --- |
| `AppIcon.png` | 60×60 | 9280 | `84d1357e4858dfb2c3abd6daff03dfda7146cae14fc039da44dc87af2f4bc34d` |
| `AppIcon@2x.png` | 120×120 | 33883 | `65f22cadca28349ec3d19ae4c1ad562cae4a9be06dd55233403d265eb7b35514` |
| `AppIcon@3x.png` | 180×180 | 71769 | `27e4d5944622211df284df767c3c927fe5252a26650091a38f1fc72970bae58d` |
| `BrandLogo.png` | 256×256 | 135538 | `895541d287cae299260b9e5f1697d3135ac75656810d2165c912940190f73c6b` |

Main Info is valid XML; mirror Info is valid binary plist. Both parsed dictionaries retain `com.vcnext.app`, executable `VCNext`, icon declaration `[AppIcon]`, build `37` and app version `0.16.73`. Only `CFBundleDisplayName`/`CFBundleName` change to `VCAMPLUS`. There is no Assets.car.

The outer Debian control correctly contains the requested VCAMPLUS name/author/description/section. **The packaged `var/mobile/Library/pkgmirror/DEBIAN.com.vcnext.app/control` does not:**

| Field | Outer control | Packaged mirror control |
| --- | --- | --- |
| Name | `VCAMPLUS` | `V4HCAM Next` |
| Author | `VCAMPLUS Team <@vcamplus>` | `V4HCAM` |
| Maintainer | `VCAMPLUS <@vcamplus>` | `V4HCAM` |
| Description | Requested Vietnamese description | Original English description |
| Section | `Tweaks` | `Applications` |

**Required before branding sign-off:** apply the visible-field update to that data member in [build_commercial_deb.py](/C:/Users/Admin/Desktop/vcnextnew/scripts/build_commercial_deb.py), then rebuild and audit the newly identified artifact. Do not copy the entire outer control: the mirror deliberately retains baseline `Architecture: iphoneos-arm64` and no outer rootless pre-dependency; the outer control is `iphoneos-arm64e` with `rootless-compat` pre-dependency. Preserve those runtime/package-conversion distinctions unless separately investigated.

Other distribution-quality recommendations:

- `Maintainer: VCAMPLUS <@vcamplus>` uses a Telegram handle where Debian policy specifies an email address. Supply an actual owner-approved email and keep Telegram as a separate public support link. This is a metadata conformance issue, not evidence of a malformed tar or Mach-O. [Debian Maintainer specification](https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-maintainer).
- Debian `Version` remains `0.16.73`, the same as production. An automatic package-manager upgrade should not be assumed; choose an appropriate package revision for release while retaining client app build `37`.
- The inherited `Installed-Size: 1528` understates even the 3,024,405 bytes (2954 KiB rounded up) of regular payload; recompute installed-size metadata with the final packaging workflow. This was inherited, not introduced by the title patch.

These audit findings were recorded without changing the builder or package.

## 5. Error-message and Telegram verification

### Six manual-auth rejection paths

An isolated test compiles selected source definitions without production module initialization/key loads, uses a temporary SQLite fixture, and substitutes fake Telegram transport. It executes the actual message/handler logic. **62 assertions pass**, including lowercase identifiers, exact UTF-8/newline/Content-Length, six rejection cases, notification dispatch, HTML escaping, fixed-owner routing and branded fake delivery. Passing assertions also reproduce the known gaps; they do not mean every branding requirement passed.

| Wire error | Message first line | Second line | Isolated result |
| --- | --- | --- | --- |
| `wrong_password` | `Sai mật khẩu đăng nhập!` | `Liên Hệ Telegram: @vcamplus` | PASS |
| `invalid_credentials` | `Tài khoản chưa được đăng ký!` | Same | PASS |
| `account_expired` | `Tài khoản đã hết hạn sử dụng!` | Same | PASS |
| `device_limit_reached` | `Đã đủ số thiết bị đăng ký!` | Same | PASS |
| `account_disabled` | `Tài khoản đang bị tạm khóa!` | Same | PASS |
| `device_bound_to_other_user` | `Thiết bị đã gắn với tài khoản khác!` | Same | PASS |

All six actual handler bodies use HTTP 403 and lowercase codes. `user_not_found` is a helper return code, not the unknown-account HTTP response in the current challenge/login flow. All inspected literal AuthError codes are lowercase and do not equal the client's exact uppercase `INVALID_CREDENTIALS` or `DEVICE_LIMIT` comparisons at `0x10000c088`/`0x10000c09c`. Thus these current responses avoid the original handle append. **The branch still exists in the client; this is not permanent removal or a guarantee about future/proxy errors.**

### Remaining server-message coverage gap

Four same-category errors in [server.py](/C:/Users/Admin/Desktop/vcnextnew/server/server.py:123) retain the previous one-line text. They were reproduced in isolated calls:

| Source line | Path/condition | Wire code | Current unbranded message |
| --- | --- | --- | --- |
| 123 | Response construction finds expiry | `account_expired` | `Tài khoản đã hết hạn!` |
| 158 | Session device owner differs | `device_bound_to_other_user` | `Thiết bị đã được gắn với tài khoản khác!` |
| 162 | Session account disabled | `account_disabled` | `Tài khoản đang bị khóa!` |
| 164 | Session/license expired | `account_expired` | `Tài khoản đã hết hạn!` |

The deployed `server.py` hash equals the inspected source, so this is not merely stale local code. A small central mapping at the failed-JSON-response boundary can normalize these public messages while preserving status, machine error, auth decisions and signed successful dictionaries. Alternatively update all corresponding emitters. Cover both challenge/login and heartbeat/renew tests; do not decorate signed lease/challenge payloads or change identifier case.

### Live HTTPS result and owner-confirmed Telegram delivery

At **2026-10-22 14:27:07 ICT** (07:27:07 UTC), one explicitly authorized synthetic unknown-account `/api/v2/auth/challenge` request used a newly generated in-memory P-256 public key and supported build/digest. It supplied no password and did not proceed to login. The unknown-user branch rejects before challenge insertion/enrollment; no account was created or device bound.

Observed response:

```http
HTTP 403
Content-Type: application/json; charset=utf-8
Content-Length: 126
```

```json
{"ok":false,"error":"invalid_credentials","message":"Tài khoản chưa được đăng ký!\nLiên Hệ Telegram: @vcamplus"}
```

TLS certificate verification was enabled; redirects/retries were not used for this one-shot POST. The body has exactly two source lines, the exact requested contact, and no legacy handle. [Captured response](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/live_error_response.json).

The owner then answered **“Yes, alert arrived”** for the unique synthetic account. This confirms actual delivery for that rejection, beyond a local mock. A narrow journal check found no notifier error classes in the test window. It does not prove delivery of successful-login alerts or every future message. The production notifier remains a bounded, in-memory best-effort queue, not a durable exactly-once outbox. [Owner confirmation](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/telegram_owner_confirmation.json), [journal observation](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/live_notification_observation.json).

One presentation issue remains in the bot: `notify.ERROR_LABELS` lacks `invalid_credentials`, so unknown-account notifications fall back to the generic `Đăng nhập không hợp lệ` reason. Add an owner-appropriate mapping if the alert must explicitly say the account is unregistered. Receipt was confirmed; exact alert artwork/wording was not inspected in the chat.

No live wrong-password, expired-account, quota or migration login was performed; those cases have isolated execution plus deployed-source hash parity. Creating/mutating production fixtures was unnecessary for this audit. [Isolated message findings](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/messages_findings.md), [62-check evidence](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/messages_verification.json).

### Two source lines are not a screen-fit guarantee

The patched apps preserve executable text, including login `setNumberOfLines:2` at `0x10000a520` with argument 2 at `0x10000a51c`. A long first line can wrap, consuming both rendered lines and truncating the contact. The longer device-ownership reason needs particular small-screen testing. Manual login uses `displayMessageForError:` into a UILabel, not a scrollable alert or selectable contact view. Stored-session restoration/local validation/transport failures follow different paths and cannot all be branded by these server messages. See the [prior exact client-flow report](/C:/Users/Admin/Desktop/vcnextnew/docs/CODEX_COMMERCIAL_REBRANDING_VERDICT.md).

## 6. Production isolation verified

Read-only SSH using the existing project credential and previously known host key checked the exact requested path, hashes and service states. At **14:26:29 ICT**, `/opt/vcnext_server/VCNext-custom-roothide.deb` was **496292 bytes**, mode **0644**, owner/group `ubuntu:ubuntu`, SHA-256 **`4d1f8bf580e1c7699865fbafec4302ad28ab9df9a155b8bc13d68330ef51675b`**. Both `vcnext.service` and `vcnext-bot.service` reported active. No remote files or service configuration were changed. [VPS observation](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/live_vps.json).

The public GET of [the existing production download](https://vc.huxa.xyz/VCNext-custom-roothide.deb) independently returned HTTP 200, 496292 bytes and that same hash. It did **not** serve the 479204-byte commercial candidate. The local commercial artifact remained under `dist/`, re-read unchanged after auditing. These observations prove current identity at the tested path/endpoint, not a historical assertion that nobody ever replaced/restored a file. [Download observation](/C:/Users/Admin/Desktop/vcnextnew/docs/evidence/vcamplus/live_download.json).

The four deployed Python source hashes match the local test inputs:

| File | SHA-256, identical local/deployed |
| --- | --- |
| `server.py` | `354e1d550373e1dcd0ed16ffb9d4e4cda67902b512bc32deec7c4a7d33145b96` |
| `store.py` | `9c874f27d89fa5966d753778a067656d5bf6b4ffbf848e99c544ba71e0ae7264` |
| `notify.py` | `a4558aa67d5e53c2cfe054e273a3757080894ed4315e24be91115a6125f4dd72` |
| `telegram_bot.py` | `5d52b22c134f2da6fa63bb937947145554969cb418a2957ed96dbf6c8006d2af` |

The bot's commercial invoice still points to `/download`, whose current backend serves `VCNext-custom-roothide.deb`. That is consistent with the requested isolation. Do not treat the invoice's VCAMPLUS label as evidence the commercial binary package is deployed.

## 7. Target testing and release recommendation

Approve **controlled device testing** of the staged artifact; withhold a blanket commercial/runtime sign-off until the following evidence exists:

1. Correct the mirrored branding and same-category session error text in a new candidate, recording its new hash; use a real maintainer contact and intended Debian revision. Repeat the three read-only audits below.
2. Keep the known-good original package and recovery access. Install using the exact target RootHide/signing/trust workflow. Verify installed main/mirror executable hashes or any documented signing transformations, cdhash admission and actual app launch. Do not assume unchanged text means the new app cdhash is already trusted.
3. Check SpringBoard icon/name after the normal RootHide-aware registration/cache refresh, login/header/home title, logout text expectations, and remembered-state continuity. Preserve bundle ID, paths, notifications and device bindings.
4. On A11 and a physical arm64e device, exercise all six manual errors using designated test accounts, small screen/font settings, long names and landscape restrictions. Verify the whole support line remains visible and the legacy handle is absent. Separately exercise automatic restore, expiry during renewal and offline/TLS failure; their UI behavior differs.
5. Confirm valid login and sustained renewal over several 90-second windows, plus an owner-received success alert. Confirm rejection alerts separately. Avoid treating a queue enqueue result as delivery proof.
6. Regress floating overlay, Direct Media, source changes, front/rear preview, still photo, recording and third-party consumers. For the reported iPhone 12/iPhone 14 Pro failure, follow [the camera diagnostic report](/C:/Users/Admin/Desktop/vcnextnew/docs/CODEX_CAMERA_INJECTION_A12_A16_DIAGNOSIS.md). The commercial package keeps those camera binaries, profiles, installer permissions and filters byte-identical; cosmetic rebranding does not resolve their existing failure mechanisms.

Reproducers, all read-only with respect to product artifacts and production:

```text
python -X utf8 scripts/audit_vcamplus_archive.py
python -X utf8 scripts/audit_vcamplus_macho.py
python -X utf8 scripts/audit_vcamplus_messages.py
```

Each exited 0. Archive/Mach-O checks establish the stated integrity properties; the message suite also deliberately verifies the remaining inconsistent paths. No package/server remediation was silently applied during this requested audit.
