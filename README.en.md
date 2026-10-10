# Shellsmith — Android and iOS App Hardening

[简体中文](README.md) | English

[![Latest Release](https://img.shields.io/github/v/release/kairowan/Shellsmith?style=flat-square&label=release&color=6366f1)](https://github.com/kairowan/Shellsmith/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/kairowan/Shellsmith/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/kairowan/Shellsmith/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green?style=flat-square)](#license)

Protect Android APK/AAB outputs and iOS source projects, and verify the resulting artifacts, entirely on your own machine. APKs and signing materials never leave it.

- **Android:** DEX encryption and runtime protection, then repackaging, alignment, and optional signing.
- **iOS:** selected Swift literal protection and freeRASP runtime checks, combined with Apple's native archive, export, and signature verification.

Both pipelines raise the cost of static analysis, tampering, and unauthorized re-signing. They do not guarantee that an app cannot be unpacked or reverse engineered.

The recommended desktop GUI supports Windows, macOS, Linux, and Chinese/English interfaces. A source-built CLI is available for automation and development.

> Use only with applications you own or are authorized to protect. Do not bypass third-party protections or use this tool for unauthorized purposes.

## Core Capabilities

- **DEX and runtime protection:** encrypt application DEX files, bind them to the original certificate, and apply baseline anti-debugging or optional strict environment checks.
- **iOS source protection:** modify an isolated working copy with Swift Confidential and freeRASP, then archive, export, and verify it with `xcodebuild`.
- **Integrated signing:** import, create, and manage certificates; automatically sign protected output or sign an APK independently.
- **Preflight checks and failure diagnostics:** inspect signatures, existing protection, system requirements, and ABIs; on failure, show a sanitized diagnostic summary that can be previewed and submitted as an error report.
- **Reusable settings:** remember protection options and the protection page's certificate choice, customize output directory and filename, and freeze each running task's configuration.
- **Installation compatibility:** handle APK ZIP alignment and common native-library cases, with separate standard and Android 4.4 industrial modes.

## Download and Quick Start

Download a stable desktop installer from [GitHub Releases](https://github.com/kairowan/Shellsmith/releases/latest).

| Platform | Package |
|---|---|
| Windows | `Shellsmith_x.y.z_windows_x64_setup.exe` |
| macOS | `Shellsmith_x.y.z_macos_universal.dmg` |
| Linux | `Shellsmith_x.y.z_linux_amd64.AppImage` or `.deb` |

### Requirements

- A **full JDK 8 or later**, with `java` and `keytool` available; PVM2 requires Java 17+.
- Desktop release users do not need to install the Android SDK. apktool, apksigner, bundletool, and aapt2 for APK/AAB work are bundled.
- iOS hardening requires macOS with full Xcode; Windows and Linux cannot archive or export an IPA.

Signing status depends on how the package was produced:

- Local source builds are ad-hoc signed.
- External macOS releases are signed and notarized only when Developer ID and a notary profile are configured, and their artifact name carries the `_notarized` suffix. Run packages without that suffix only from a trusted source.

### Android Quick Start

1. In **Certificates**, import the original APK's signing certificate. For a new project, you may create one, but the input APK must also be signed with it first.
2. In **Protect**, select an already signed APK, or switch to **AAB · Google Play** and select a signed AAB, then review the preflight results.
3. Choose the target system and protection policy. Normally use Android 5.0+ and the recommended standard protection; use industrial mode only when Android 4.4 is required.
4. Review the output directory, filename, automatic signing certificate, and per-app sharing choice, then start protection.
5. Test the signed output on target devices: installation, launch, core functionality, and upgrade installation.

### iOS Quick Start

Install full Xcode on macOS, open **Protect → iOS**, select an `.xcodeproj` or `.xcworkspace`, enter the scheme, Team ID, and Bundle ID, run the check, and choose a separate empty output directory. `confidential.yml`, the freeRASP watcher email, and the App Attest server endpoint are all optional. Strict client hardening works without an endpoint, but it does not include a server-side device-attestation loop. The source project is left unchanged.

### Output and Signing

Output defaults to the input APK's directory with a suggested filename; both can be changed before execution. Without automatic signing, sign the output with the original certificate.

**Re-signing protected output with another certificate prevents startup.**

<details>
<summary>macOS reports that the developer cannot be verified</summary>

After verifying the download source and moving the application to `/Applications`, you can run:

```bash
xattr -rd com.apple.quarantine /Applications/Shellsmith.app
```

This removes quarantine; it does not mean the application is notarized by Apple. Open it again. See the [usage guide](docs/usage.md) for more help.

</details>

## Preview

![Shellsmith protection page illustration](docs/assets/screenshots/readme-protect-main.png)

The screenshot illustrates the layout; available options depend on the current version. More screens and instructions are in the [usage guide](docs/usage.md).

## Compatibility and Limitations

### Scope

| Mode | Scope |
|---|---|
| Android 5.0 and later | API 21+; `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`. An APK does not need all four ABIs |
| Android 4.4 industrial | API 19+; inputs must have no native libraries or only `armeabi-v7a` libraries. Physical-device coverage is an Android 4.4.2 `armeabi-v7a`/NEON industrial device |
| iOS source project | iOS 13+ SwiftUI/UIKit application targets; archive, export, and signing require macOS with full Xcode |

### Not Supported

- Protected APKs/AABs cannot be protected again.
- iOS requires source and legitimate signing access. Shellsmith does not inject into arbitrary IPAs, bypass signatures, or repackage third-party apps.
- Compatibility mode does not lower the application's `minSdkVersion`.
- Missing business libraries are not generated.
- The GUI processes one APK or AAB at a time; no batch queue is provided.
- Swift Confidential only processes Swift source. Objective-C projects can use RASP but get no literal protection, so do not supply `confidential.yml` for them.

### Requires Your Own Validation

- Vendor systems and hardware still need testing; a successful build does not establish compatibility with every environment.
- The Android GUI and CLI support APK/AAB, but Google Play App Signing, dynamic features, Asset Packs, and dynamic delivery still require validation in the target app's internal test track.
- Unneeded legacy ABIs can be excluded with per-task confirmation, but prefer filtering them in the original project.
- 16 KB ZIP alignment does not establish ELF page-size compatibility for every third-party library or guarantee Google Play acceptance.

### Known Issues

- Linux startup applies a WebKitGTK DMABUF compatibility setting for Fedora AppImage issue [#121](https://github.com/kairowan/Shellsmith/issues/121); the reporter's release environment still requires validation.

See the [usage guide](docs/usage.md) for detailed boundaries.

## How It Works and Security Scope

### Android pipeline

Protection reads the original certificate, compresses and encrypts DEX files, injects the stub, then rebuilds, aligns, and optionally signs the APK. At runtime, the stub checks the environment, validates or decrypts the DEX cache, loads code, and starts the original application.

DEXB payload encryption **does not provide confidentiality against static analysis**: both inputs of the envelope key (the signing certificate fingerprint and the build ID) are stored in cleartext in the package header, so the key can be recovered from the APK file alone, and with it the derived keys for every business DEX, the PVM2 images, encrypted assets and business `.text`. What it does provide is refusal to run after re-signing, plus a higher cost for automated scanning and reverse engineering. Real payload confidentiality would require an out-of-package secret (a non-exportable device key or a server-issued key), which is not implemented today; see the confidentiality boundary section in [docs/design/internals.md](docs/design/internals.md).

Production uses a decrypted DEX cache in the application's private directory. It is **not a fully in-memory DEX loader or method-code extraction scheme**. Root access, process control, or other elevated privileges may allow runtime code extraction. Standard protection does not block startup solely because of root signals; strict protection blocks some risky environments but cannot guarantee detection of hidden root or prevent bypasses.

### iOS pipeline

The iOS pipeline edits only a working copy, resolves exact upstream Swift Package versions, generates a stable threat-event wrapper, uses Apple's native Archive/Export flow, and verifies signatures, Team ID, Bundle ID, entitlements, arm64, privacy manifests, dSYMs, and selected sensitive literals. Closed-source freeRASP behavior and the known RootHide gap remain upstream residual risks.

Hardening does not replace server-side authorization, key management, or application security design. See [runtime security](docs/design/runtime-security.md), [technical internals](docs/design/internals.md), and [iOS hardening](docs/design/ios-hardening.md).

## Privacy

APKs, certificates, keystores, and signing passwords are processed locally and not uploaded. The desktop tool has the following independent data channels:

| Channel | Data and controls |
|---|---|
| Safe error reports | Preview and confirm each report; no raw logs, APKs, paths, package names, certificates, or passwords. Independent of the other channels |
| Per-app usage sharing | Controlled on protection/signing pages, selected by default for new package names. Opt-outs persist across pages and restarts. Successful operations send app name, package name, version code, tool version, operation, flow, success date, and protocol/deduplication metadata; no device identifier |

App sharing is maintainer-only and retained for 180 days. Opting out stops future sharing for that package but does not delete received records. **These reporting features are not injected into protected APKs.** See [data and privacy documentation](docs/ops/telemetry.md) for scope, retention, and deletion details.

In-app problem feedback never reports automatically: the feedback text (for bug reports, together with the automatically attached version, OS, Java, and tool-status diagnostics) is sent to a public GitHub issue only after the user fills in the form, previews it, and confirms sending. If the service is unavailable, the app offers to open a prefilled issue page in the browser instead.

The iOS balanced and strict profiles integrate freeRASP directly into the target app. Its `watcherMail`, security events, and network behavior are governed by Talsec's terms and privacy policy and require app-owner disclosure before release. Shellsmith does not host the freeRASP binary.

## Feedback and Community

- Read the [support guide](docs/process/support.md), then open a [GitHub issue](https://github.com/kairowan/Shellsmith/issues); you can also submit directly from the **Problem feedback** section on the Settings page.
- For feature requests, choose **Feature request** in the **Problem feedback** section on the Settings page, or use the [feature request form](https://github.com/kairowan/Shellsmith/issues/new?template=feature_request.yml); upvote an existing matching request instead of filing a duplicate.
- Report vulnerabilities privately following [SECURITY.md](SECURITY.md). Do not publish exploits, business APKs, certificates, or passwords.

## Documentation and Development

| Topic | Documentation |
|---|---|
| GUI, certificates, configuration locations, and CLI | [Usage guide](docs/usage.md) |
| Installation and runtime problems | [Troubleshooting](docs/ops/troubleshooting.md) |
| Source builds | [Build guide](docs/ops/build.md), [environment requirements](docs/ops/environment.md) |
| Architecture and internals | [Documentation index](docs/README.md) |
| iOS integration, configuration, and security scope | [iOS hardening](docs/design/ios-hardening.md) |
| Future work | [Roadmap](docs/process/roadmap.md) |

The CLI is source-built; Releases contain desktop GUI packages only. Build `make build-stub` first, then `make build-cli` or `make build-gui`. Refer to the build guide for dependencies and platform-specific steps.

### CI/CD and Cross-Platform Releases

GitHub Actions live under `.github/workflows/`:

- Every push to `main` and every pull request runs Rust, Python, iOS-core, and frontend checks.
- After every successful CI run on `main`, the Release workflow automatically computes a `<current version>-build.<CI run number>` version, builds native Linux, macOS, and Windows installers, and creates a GitHub Release. You can still run `Release` manually for a specified version.
- The release job uploads Linux `.AppImage`/`.deb`, macOS `.dmg`, Windows `.exe`, Android runtime resources, and SHA-256 checksum files, and includes an automatic summary of the triggering commit.
- macOS builds use ad-hoc signing by default. Set `MACOS_RELEASE_MODE=developer-id`, a Developer ID identity, and a notarytool profile to produce a distributable notarized package.

The same scripts can be used locally, reading the version from `package.json` so it cannot drift from the released version:

```bash
VERSION=$(node -p "require('./apps/shield-gui/package.json').version")
VERSION="$VERSION" ./scripts/release-linux.sh
VERSION="$VERSION" ./scripts/release-macos.sh "$VERSION" universal
```

On Windows, run this from an elevated PowerShell:

```powershell
$version = (Get-Content apps/shield-gui/package.json | ConvertFrom-Json).version
.\scripts\release-windows.ps1 -Version $version
```

All three builds include the stub, PVM2 packer, Android resources, and signing tools; install and verify each package on its target OS before publishing.

## Acknowledgements

Shellsmith's hardening capabilities build on the upstream projects and tools below. They define the capability boundary, or take part directly in hardening at build time or runtime. Licenses and third-party notices for redistributed components ship in `tools/licenses/`.

### Origin project

| Project | License | Notes |
|---|---|---|
| [Mocika Shield](https://github.com/mocikadev/mocika-shield) | MIT OR Apache-2.0 | The origin of this project. DEX encryption, stub loading, signature binding, baseline runtime protection, and certificate/signing management all evolved from it; Shellsmith extends it with iOS hardening, AAB handling, Native VMP, and in-app updates. |

### Code protection

| Project | License | Use |
|---|---|---|
| [XopProtector](https://github.com/xopJack/XopProtector) | Apache-2.0 | PVM2 and True-VMP code protection; the runtime and packer sources are redistributed in `third_party/xopprotector/`, and `xop-pvm2-packer.jar` ships with releases, with its license and third-party notices in `tools/licenses/` |
| [LLVM](https://llvm.org/) | Apache-2.0 WITH LLVM-exception | Native VMP is implemented as an LLVM 21 pass plugin for the app's native build (`native-vmp/`; standalone component, not yet wired into the hardening flow) |

### iOS runtime protection

| Project | License | Use |
|---|---|---|
| [freeRASP](https://github.com/talsec/Free-RASP-iOS) 7.1.4 | MIT, subject to Talsec's fair usage policy | iOS runtime threat detection; resolved on the user's machine, no binary redistribution |
| [Swift Confidential](https://github.com/securevale/swift-confidential) 0.5.2 | Apache-2.0 | Swift sensitive literal protection (optional) |

### Packaging, signing, and build tools

| Project | License | Use |
|---|---|---|
| [Apktool](https://apktool.org/) 3.0.1 | Apache-2.0 | APK decoding and rebuilding; redistributed with releases |
| [apksigner](https://developer.android.com/tools/apksigner) (Android SDK Build-Tools) | Apache-2.0 | APK signing and signature verification; redistributed with releases |
| [bundletool](https://github.com/google/bundletool) · [aapt2](https://developer.android.com/tools) | Apache-2.0 | AAB module handling and resource compilation |
| [Android NDK](https://developer.android.com/ndk) | Apache-2.0 | Compiling the stub native libraries and Android 4.4 compatibility libraries |

Desktop frameworks, frontend packages, and general-purpose Rust libraries are not enumerated here; exact versions and licenses can be reproduced from `Cargo.lock`, `apps/shield-gui/package-lock.json`, and `shield-stub/gradle/libs.versions.toml`.

If a credit is wrong, a license is mislabeled, or a project is missing, please open an issue or pull request and we will correct it.

## License

Dual-licensed under **MIT OR Apache-2.0**, at your choice: [MIT](LICENSE-MIT) · [Apache-2.0](LICENSE-APACHE).
