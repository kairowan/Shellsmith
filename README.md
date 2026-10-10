# Shellsmith — Android 与 iOS 应用加固工具

简体中文 | [English](README.en.md)

[![最新版本](https://img.shields.io/github/v/release/kairowan/Shellsmith?style=flat-square&label=最新版本&color=6366f1)](https://github.com/kairowan/Shellsmith/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/kairowan/Shellsmith/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/kairowan/Shellsmith/actions/workflows/ci.yml)
[![许可证](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green?style=flat-square)](#许可证)

在本机完成 Android APK/AAB 与 iOS 源码工程的加固、签名和产物验证，加固与签名材料始终不出本机。

- **Android**：DEX 加密与运行时保护，重新打包、对齐并按需签名。
- **iOS**：选择性 Swift 字符串保护、freeRASP 运行时检测，配合 Apple 原生 Archive、导出与签名验证。

两条链路都用于提高静态分析、篡改和非法重签的成本，不承诺无法脱壳或逆向。

推荐使用 Windows、macOS、Linux 桌面 GUI，支持中英文界面；CLI 可从源码构建，用于自动化和本地开发。

> 仅用于保护你拥有合法权利的 Android 与 iOS 应用，请勿用于绕过第三方保护或其他未授权场景。

## 核心能力

- **DEX 加固与运行时保护**：加密业务 DEX，绑定原签名证书；提供基础反调试和可选的严格保护。
- **iOS 源码保护**：在独立工作副本中接入 Swift Confidential 与 freeRASP，再用 `xcodebuild` 完成 Archive、导出和签名验证。
- **加固签名一体化**：证书导入、新建与管理，加固后自动签名，也支持独立签名。
- **加固前风险检查与失败诊断**：检查签名、已有加固、系统要求、ABI 等兼容信号；失败时给出脱敏诊断摘要，可预览并确认发送错误报告。
- **省去重复配置**：记住常用加固选项和加固页证书选择，可调整输出目录与文件名，任务开始后固定本次配置。
- **安装与系统兼容**：处理 APK ZIP 对齐及常见 Native 库兼容问题；标准模式与 Android 4.4 工控模式分开选择。

## 下载与快速开始

从 [GitHub Releases](https://github.com/kairowan/Shellsmith/releases/latest) 下载正式桌面安装包：

| 平台 | 安装包 |
|---|---|
| Windows | `Shellsmith_x.y.z_windows_x64_setup.exe` |
| macOS | `Shellsmith_x.y.z_macos_universal.dmg` |
| Linux | `Shellsmith_x.y.z_linux_amd64.AppImage` 或 `.deb` |

### 环境要求

- 完整 JDK 8 或更高版本，确保 `java`、`keytool` 可用；使用 PVM2 需要 Java 17+。
- 使用桌面发布包无需自行安装 Android SDK；AAB 与 APK 所需的 apktool、apksigner、bundletool、aapt2 已随包提供。
- 仅 iOS 加固需要 macOS 并安装完整 Xcode，Windows 与 Linux 无法 Archive 或导出 IPA。

签名状态随构建方式不同，下载后请按需确认：

- 本地源码构建产出的是 adhoc 签名包。
- 对外 macOS 产物只有在配置 Developer ID 与 notary profile 后才会签名、公证，并带上 `_notarized` 后缀；未带该后缀的包仅应从可信位置使用。

### Android 快速流程

1. 在 **证书** 页面导入原 APK 使用的签名证书。新项目可创建证书，但输入 APK 也必须先用该证书签名。
2. 在 **加固** 页面选择已签名 APK，或切换到 **AAB · Google Play** 选择已签名 AAB，查看预检结果。
3. 选择目标系统和保护策略。一般使用“Android 5.0 及以上”与“标准保护（推荐）”；目标确有 Android 4.4 时再选择工控模式。
4. 确认输出目录、文件名和自动签名证书，按需调整当前应用的分享选择，再开始加固。
5. 使用签名后的产物，在目标设备验证安装、启动、主要业务功能和覆盖升级。

### iOS 快速流程

在 macOS 安装完整 Xcode，在 **加固 → iOS** 选择 `.xcodeproj` 或 `.xcworkspace`，填写 scheme、Team ID、Bundle ID，先运行检查，再选择独立空目录执行保护。`confidential.yml`、freeRASP 邮箱和 App Attest 服务端地址均为可选项；没有后台地址时仍可执行严格客户端加固，但不包含服务端设备证明闭环。原工程不会被修改。

### 输出与签名

输出默认位于原 APK 同目录，并自动建议文件名，执行前可修改。不启用自动签名时，产物仍需使用原证书签名才能安装运行。

**加固产物与原证书绑定，换证书重签会导致应用无法启动。**

<details>
<summary>macOS 首次打开提示无法验证开发者</summary>

确认安装包来源可信，并将应用移到“应用程序”目录后，可执行：

```bash
xattr -rd com.apple.quarantine /Applications/Shellsmith.app
```

该命令移除隔离标记，不代表应用已获 Apple 公证。随后重新打开；其他问题见[使用指南](docs/usage.md)。

</details>

## 界面预览

![Shellsmith 加固页示意](docs/assets/screenshots/readme-protect-main.png)

截图用于展示页面布局，具体选项以当前版本为准。更多页面与操作说明见[使用指南](docs/usage.md)。

## 兼容性与限制

### 适用范围

| 模式 | 适用范围 |
|---|---|
| Android 5.0 及以上 | API 21+，支持 `armeabi-v7a`、`arm64-v8a`、`x86`、`x86_64`；不要求每个 APK 都包含四种架构 |
| Android 4.4 工控兼容 | API 19+；只接受无 Native 库或 Native 库仅含 `armeabi-v7a` 的 APK；真机验证范围为 Android 4.4.2、`armeabi-v7a`/NEON 工控设备 |
| iOS 源码工程 | iOS 13+；SwiftUI/UIKit 应用 target；Archive、导出与签名仅支持安装完整 Xcode 的 macOS |

### 不支持与不会做的事

- 已加固 APK/AAB 不支持重复加固。
- iOS 需要源码和合法签名权限，不对任意 IPA 注入、绕过签名或重打包。
- 兼容模式不会降低原应用的 `minSdkVersion`。
- 不会为缺失架构生成业务库。
- GUI 一次处理一个 APK 或 AAB，暂不提供批量队列。
- Swift Confidential 仅处理 Swift 源码；Objective-C 工程可接入 RASP，但不做字符串保护，请勿提供 `confidential.yml`。

### 需要自行验证

- 不同厂商系统和硬件仍需实测，构建通过不代表所有环境可用。
- Android GUI 和 CLI 都支持 APK/AAB，但 AAB 的 Google Play App Signing、dynamic-feature、Asset Pack 和动态交付仍需在目标应用内测轨道验证。
- 混合旧 ABI 可逐次确认排除，但优先建议从原工程过滤业务不需要的架构。
- 16 KB ZIP 对齐不等于所有第三方 `.so` 都满足 ELF 页大小要求，也不等于通过 Google Play 审核。

### 已知问题

- Linux 启动时会应用 WebKitGTK DMABUF 兼容设置以规避 Fedora AppImage 空白窗口 [#121](https://github.com/kairowan/Shellsmith/issues/121)；仍需在反馈环境完成发布包回归。

详细边界见[使用指南](docs/usage.md)。

## 工作原理与安全边界

### Android 链路

加固时读取原签名证书，压缩并加密 DEX，注入壳资源，再重新打包、对齐并按需签名。运行时由壳执行安全检查、校验或解密 DEX 缓存，加载业务代码并启动原应用。

当前正式方案会在应用私有目录使用解密后的 DEX 缓存，**不是完整内存 DEX 或方法代码抽取方案**。Root、进程控制或其他高权限环境下，攻击者仍可能提取运行时代码。标准保护不因 Root 信号拒绝启动；严格保护可阻断部分风险环境，但无法保证识别隐藏 Root 或抵御绕过。

### iOS 链路

iOS 流水线只改工作副本：接入精确版本的上游 Swift Package，生成统一威胁事件封装，调用 Apple 原生 Archive/Export，再核验签名、Team ID、Bundle ID、Entitlements、arm64、隐私清单、dSYM 和选定敏感字符串。freeRASP 的闭源检测能力和已知 RootHide 漏检仍属于上游残余风险。

加固不能替代服务端鉴权、密钥管理和应用自身的安全设计。技术细节见[运行时安全](docs/design/runtime-security.md)、[技术内参](docs/design/internals.md)与 [iOS 加固实现](docs/design/ios-hardening.md)。

## 隐私说明

APK、证书、密钥库和签名密码只在本机处理，不上传业务文件。桌面工具有以下独立数据通道：

| 通道 | 数据与控制方式 |
|---|---|
| 安全错误报告 | 每份报告先预览、再确认发送；不上传原始日志、APK、路径、包名、证书或密码，独立于其他数据通道 |
| 应用使用分享 | 加固/签名页控制，新包名默认选中，同包名取消后跨页及重启保持；成功时发送应用名称、包名、版本码、工具版本、操作、流程、成功日期及协议/去重信息，不带设备标识 |

应用分享仅维护者可见，明细保留 180 天；取消停止同包名后续分享，不删除已接收记录。**加固后的 APK 不包含这些分享上报。** 数据范围、保留与删除说明见[数据与隐私说明](docs/ops/telemetry.md)。

软件内“问题反馈”不会自动上报：只有在设置页主动填写表单、预览并确认提交后，反馈正文（Bug 反馈还会附带版本、系统、Java 与工具状态等诊断信息）才会发送到 GitHub 公开 issue；服务端不可用时，软件会提供在浏览器打开预填 issue 页面的入口。

iOS balanced/strict 会让目标应用直接集成 freeRASP；其 `watcherMail`、安全事件和网络行为受 Talsec 条款与隐私政策约束，发布前需由应用方完成披露。Shellsmith 不托管 freeRASP 二进制。

## 反馈与交流

- 使用问题请先阅读[反馈指南](docs/process/support.md)，再提交 [GitHub Issue](https://github.com/kairowan/Shellsmith/issues)；也可直接在设置页的“问题反馈”区块提交。
- 功能建议可在设置页的“问题反馈”中选择“需求建议”提交，也可使用[需求表单](https://github.com/kairowan/Shellsmith/issues/new?template=feature_request.yml)；已有相同需求可在原 issue 点赞。
- 安全漏洞请按 [SECURITY.md](SECURITY.md) 私下报告，不公开可利用细节、业务 APK、证书或密码。

## 文档与开发者入口

| 需要了解 | 文档 |
|---|---|
| GUI 操作、签名证书、配置位置、CLI 用法 | [使用指南](docs/usage.md) |
| 安装与运行问题 | [本地排障](docs/ops/troubleshooting.md) |
| 从源码编译 | [构建指南](docs/ops/build.md)、[环境要求](docs/ops/environment.md) |
| 模块结构、原理与设计 | [文档导航](docs/README.md) |
| iOS 接入、配置与安全边界 | [iOS 加固实现](docs/design/ios-hardening.md) |
| 后续规划 | [路线图](docs/process/roadmap.md) |

CLI 仅供源码构建和自动化使用，Release 不单独提供 CLI 包。构建顺序为先 `make build-stub`，再 `make build-cli` 或 `make build-gui`；完整依赖与平台步骤以构建指南为准。

### CI/CD 与跨平台发布

GitHub Actions 位于 `.github/workflows/`：

- 每次推送到 `main` 或创建 Pull Request 时运行 Rust、Python、iOS 核心和前端检查。
- `main` 每次通过 CI 后，Release 工作流会自动计算 `<当前版本>-build.<CI运行号>` 版本，在 Linux、macOS 和 Windows 原生 runner 上构建安装包，并创建 GitHub Release；也可以手动运行 `Release` 发布指定版本。
- 发布流程会上传 Linux `.AppImage`/`.deb`、macOS `.dmg`、Windows `.exe`、Android runtime 资源包及 SHA-256 校验文件，并自动生成本次提交的变更摘要。
- macOS 默认生成 adhoc 签名包；配置 `MACOS_RELEASE_MODE=developer-id`、Developer ID 身份和 notarytool profile 后，才生成可分发的公证包。

本地也可以复用同一套脚本，版本号直接从 `package.json` 读取，避免与当前发布版本脱节：

```bash
VERSION=$(node -p "require('./apps/shield-gui/package.json').version")
VERSION="$VERSION" ./scripts/release-linux.sh
VERSION="$VERSION" ./scripts/release-macos.sh "$VERSION" universal
```

Windows 使用管理员 PowerShell：

```powershell
$version = (Get-Content apps/shield-gui/package.json | ConvertFrom-Json).version
.\scripts\release-windows.ps1 -Version $version
```

三平台构建都包含 Stub、PVM2 Packer、Android 资源和签名工具，发布前仍应在目标系统安装并验证。

## 致谢

Shellsmith 的加固能力建立在这些上游项目与工具之上：它们定义了本工具的能力边界，或在构建期、运行期直接参与加固。随发布包分发的组件，其许可证与第三方声明见 `tools/licenses/`。

### 上游来源工程

| 项目 | 许可证 | 说明 |
|---|---|---|
| [Mocika Shield](https://github.com/mocikadev/mocika-shield) | MIT OR Apache-2.0 | 本项目的来源工程。DEX 加密、壳加载、签名绑定、基础运行时保护与证书/签名管理流程均由此演化而来；Shellsmith 在其基础上扩展了 iOS 加固、AAB 处理、Native VMP 与应用内更新。 |

### 代码保护

| 项目 | 许可证 | 用途 |
|---|---|---|
| [XopProtector](https://github.com/xopJack/XopProtector) | Apache-2.0 | PVM2 与 True-VMP 代码保护；壳运行时源码与打包器源码随本仓库分发（`third_party/xopprotector/`），`xop-pvm2-packer.jar` 随发布包分发，许可证与第三方声明见 `tools/licenses/` |
| [LLVM](https://llvm.org/) | Apache-2.0 WITH LLVM-exception | Native VMP 以 LLVM 21 Pass 插件形式接入业务 Native 构建（`native-vmp/`） |

### iOS 运行时保护

| 项目 | 许可证 | 用途 |
|---|---|---|
| [freeRASP](https://github.com/talsec/Free-RASP-iOS) 7.1.4 | MIT，另受 Talsec 公平使用政策约束 | iOS 运行时威胁检测；由用户本机解析，发布包不重新分发其二进制 |
| [Swift Confidential](https://github.com/securevale/swift-confidential) 0.5.2 | Apache-2.0 | Swift 敏感字面量保护（可选） |

### 打解包、签名与构建工具

| 项目 | 许可证 | 用途 |
|---|---|---|
| [Apktool](https://apktool.org/) 3.0.1 | Apache-2.0 | APK 反编译与重打包，随发布包分发 |
| [apksigner](https://developer.android.com/tools/apksigner)（Android SDK Build-Tools） | Apache-2.0 | APK 签名与签名校验，随发布包分发 |
| [bundletool](https://github.com/google/bundletool) · [aapt2](https://developer.android.com/tools) | Apache-2.0 | AAB 模块处理与资源编译 |
| [Android NDK](https://developer.android.com/ndk) | Apache-2.0 | 壳 Native 库与 Android 4.4 兼容库的编译 |

桌面框架、前端与 Rust 通用库依赖不在本节逐一列出；完整版本与许可证可从 `Cargo.lock`、`apps/shield-gui/package-lock.json` 与 `shield-stub/gradle/libs.versions.toml` 复现。

如果这里署名有误、许可证标注不准或遗漏了应当致谢的项目，欢迎提交 issue 或 PR，我们会尽快更正。

## 许可证

采用 **MIT OR Apache-2.0** 双协议，可选择其中任意一种：[MIT](LICENSE-MIT) · [Apache-2.0](LICENSE-APACHE)。
