<div align="center">
  <img src="docs/assets/brand/shellsmith-icon.png" width="96" alt="Shellsmith logo">
  <h1>Shellsmith</h1>
  <p><strong>Android 与 iOS 应用加固工具</strong></p>
  <p>离线 / 在线双密钥 · Android 与 iOS 加固 · 签名一体化</p>
  <p>简体中文 | <a href="README.en.md">English</a></p>
  <p>
    <a href="https://github.com/kairowan/Shellsmith/releases/latest"><img src="https://img.shields.io/github/v/release/kairowan/Shellsmith?style=flat-square&label=%E6%9C%80%E6%96%B0%E7%89%88%E6%9C%AC&color=6366f1" alt="最新版本"></a>
    <a href="https://github.com/kairowan/Shellsmith/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/kairowan/Shellsmith/ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
    <a href="#许可证"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green?style=flat-square" alt="许可证"></a>
  </p>
</div>

Shellsmith 是一款面向 Android 与 iOS 的桌面应用加固工具，支持**本地离线密钥**与**自建服务端在线密钥**两种交付方式。离线模式下，密钥派生、加固、签名与产物验证均在本机完成，无需网络或密钥服务；在线模式（BYOS）将产物 IKM 托管到你自建的 HTTPS 服务，APK 只携带服务地址和 token，应用启动时经设备批准或 Google Play Integrity 授权取回。

Android 侧提供 APK/AAB 的 DEX 加密、证书绑定、PVM2 方法虚拟化、基础反调试与可选的严格保护，并完成重打包、ZIP 对齐和自动签名；iOS 侧在独立工作副本中接入 Swift Confidential 与 freeRASP，完成 Archive、导出和签名验证。除在线密钥模式向你的服务端注册和取钥外，APK、证书、签名材料与密码不会上传，也不会发送给 Shellsmith 维护者。

提供 Windows、macOS、Linux 桌面 GUI（中英文界面），CLI 可从源码构建用于自动化和本地开发。

> 仅用于保护你拥有合法权利的 Android 与 iOS 应用，请勿用于绕过第三方保护或其他未授权场景。

**快速导航** · [核心能力](#核心能力) · [快速开始](#快速开始) · [兼容性](#兼容性与限制) · [在线密钥（BYOS）](#byos-包外密钥) · [安全边界](#工作原理与安全边界) · [文档](#文档与开发)

## 核心能力

- **双密钥交付**：**离线密钥**由本机派生并封装进产物，无需网络和密钥服务；**在线密钥（BYOS）**把 IKM 托管到自建 HTTPS 服务，产物只携带服务地址和 token，启动时经设备批准或 Play Integrity 授权取回。详见 [BYOS 包外密钥](#byos-包外密钥)。
- **Android 代码保护**：加密业务 DEX 并绑定原签名证书；支持 PVM2 方法虚拟化、基础反调试和可选的严格保护；重新打包、对齐并按需签名。
- **iOS 源码保护**：在独立工作副本中接入 Swift Confidential 与 freeRASP，再用 `xcodebuild` 完成 Archive、导出和签名验证，原工程不被修改。
- **加固签名一体化**：导入、新建和管理证书；加固后自动签名，也可独立签名。
- **加固前检查与失败诊断**：检查签名、已有加固、系统要求、ABI 等兼容信号；失败时给出脱敏诊断摘要，可预览后确认发送。
- **少重复配置**：记住常用加固选项和证书选择，支持自定义输出目录与文件名，任务开始后固定本次配置。
- **安装兼容**：处理 APK ZIP 对齐及常见 Native 库问题；标准模式与 Android 4.4 工控模式分开选择。

两条链路都用于提高静态分析、篡改和非法重签的成本，不承诺无法脱壳或逆向。

## 快速开始

### 下载

从 [GitHub Releases](https://github.com/kairowan/Shellsmith/releases/latest) 下载正式桌面安装包：

| 平台 | 安装包 |
|---|---|
| Windows | `Shellsmith_x.y.z_windows_x64_setup.exe` |
| macOS | `Shellsmith_x.y.z_macos_universal.dmg` |
| Linux | `Shellsmith_x.y.z_linux_amd64.AppImage` 或 `.deb` |

### 环境要求

- 完整 JDK 8 或更高版本，确保 `java`、`keytool` 可用；使用 PVM2 需要 Java 17+。
- 桌面发布包无需自行安装 Android SDK；apktool、apksigner、bundletool、aapt2 已随包提供。
- iOS 加固需要 macOS 和完整 Xcode；Windows 与 Linux 无法 Archive 或导出 IPA。

签名状态随构建方式不同：

- 本地源码构建产出 adhoc 签名包。
- 对外 macOS 产物只有在配置 Developer ID 与 notary profile 后才会签名、公证，并带上 `_notarized` 后缀；未带该后缀的包仅应从可信位置使用。

### Android 加固流程

1. 在 **证书** 页面导入原 APK 使用的签名证书。新项目可创建证书，但输入 APK 也必须先用该证书签名。
2. 在 **加固** 页面选择已签名 APK，或切换到 **AAB · Google Play** 选择已签名 AAB，查看预检结果。
3. 选择目标系统和保护策略。一般使用“Android 5.0 及以上”与“标准保护（推荐）”；目标确有 Android 4.4 时再选择工控模式。
4. 确认输出目录、文件名和自动签名证书，按需调整当前应用的分享选择，再开始加固。
5. 在目标设备验证安装、启动、主要业务功能和覆盖升级。

### iOS 加固流程

在 macOS 安装完整 Xcode，在 **加固 → iOS** 选择 `.xcodeproj` 或 `.xcworkspace`，填写 scheme、Team ID、Bundle ID，先运行检查，再选择独立空目录执行保护。`confidential.yml`、freeRASP 邮箱和 App Attest 服务端地址均为可选项；没有后台地址时仍可执行严格客户端加固，但不包含服务端设备证明闭环。

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

<p align="center">
  <img src="docs/assets/screenshots/readme-protect-main.png" width="860" alt="Shellsmith 加固页示意">
</p>

截图用于展示页面布局，具体选项以当前版本为准。更多页面与操作说明见[使用指南](docs/usage.md)。

## 兼容性与限制

### 适用范围

| 模式 | 适用范围 |
|---|---|
| Android 5.0 及以上 | API 21+，支持 `armeabi-v7a`、`arm64-v8a`、`x86`、`x86_64`；不要求每个 APK 都包含四种架构 |
| Android 4.4 工控兼容 | API 19+；只接受无 Native 库或 Native 库仅含 `armeabi-v7a` 的 APK；真机验证范围为 Android 4.4.2、`armeabi-v7a`/NEON 工控设备 |
| iOS 源码工程 | iOS 13+；SwiftUI/UIKit 应用 target；Archive、导出与签名仅支持安装完整 Xcode 的 macOS |
| 在线密钥（BYOS） | 仅 Android APK；`device_approval` 要求 `minSdk 24+`，`play_integrity` 要求 `minSdk 29+`；需要可用的自建 HTTPS 服务和网络；AAB、iOS、Android 4.4 兼容模式不支持 |

### 不支持与不会做的事

- 已加固 APK/AAB 不支持重复加固。
- iOS 需要源码和合法签名权限，不对任意 IPA 注入、绕过签名或重打包。
- 兼容模式不会降低原应用的 `minSdkVersion`。
- 不会为缺失架构生成业务库。
- GUI 一次处理一个 APK 或 AAB，暂不提供批量队列。
- Swift Confidential 仅处理 Swift 源码；Objective-C 工程可接入 RASP，但不做字符串保护，请勿提供 `confidential.yml`。
- 在线密钥（BYOS）只支持 Android APK；没有自建 HTTPS 服务和可用网络时，BYOS 产物无法启动，也不会回退到离线加载。

### 需要自行验证

- 不同厂商系统和硬件仍需实测，构建通过不代表所有环境可用。
- AAB 的 Google Play App Signing、dynamic-feature、Asset Pack 和动态交付仍需在目标应用内测轨道验证。
- 混合旧 ABI 可逐次确认排除，但优先建议从原工程过滤业务不需要的架构。
- 16 KB ZIP 对齐不等于所有第三方 `.so` 都满足 ELF 页大小要求，也不等于通过 Google Play 审核。

### 已知问题

- Linux 启动时会应用 WebKitGTK DMABUF 兼容设置以规避 Fedora AppImage 空白窗口 [#121](https://github.com/kairowan/Shellsmith/issues/121)；仍需在反馈环境完成发布包回归。

详细边界见[使用指南](docs/usage.md)。

## BYOS 包外密钥

Shellsmith 提供两种密钥交付方式：

| 模式 | 密钥位置 | 运行时要求 | 适用场景 |
|---|---|---|---|
| 本地离线密钥 | 加固时在本机派生并封装进 APK | 无需网络或密钥服务 | 完全离线交付、没有后台服务 |
| 在线密钥（BYOS） | 你自建的 HTTPS 服务端 | 每次启动联网授权取回 | 需要设备批准、Play Integrity、设备/产物撤销 |

默认使用本地离线密钥；需要把 IKM 移出 APK 时，在“密钥交付”中选择 BYOS 服务。两种模式按加固任务选择，在线模式授权失败不会回退到离线密钥。下文介绍在线密钥模式。

BYOS（Bring Your Own Server）把产物 IKM 从 APK 中移出，适合需要自行保管密钥、控制设备授权和撤销发布权限的应用。

加固时 Shellsmith 为每个产物生成独立 32 字节 IKM，调用自建服务端的注册接口换取 `token_id`。APK 只携带服务地址和 token。应用启动时，客户端生成一次性 RSA 密钥对，带上 token、设备证明或 Play Integrity 证明请求 IKM；服务端验证授权、防重放和设备/Play 状态后，用本次请求的 RSA 公钥加密 `digest[32] || IKM[32]` 返回。客户端解密并校验摘要后才加载业务代码。

### 授权方式

| 方式 | 适用场景 | 要求 |
|---|---|---|
| `device_approval` | 国内、侧载、自有分发 | 设备 EC P-256 公钥登记，管理员批准；Android 7.0+（`minSdk 24`） |
| `play_integrity` | Google Play 分发 | Play Console 与 Google Cloud 服务账号；Android 10+（`minSdk 29`） |

两种方式都不会在失败时回退到离线加载。未知设备只登记为待批准并拒绝；Play 证明失败也不会切换到设备授权。

### 使用流程

1. 按协议部署自建 HTTPS 服务端，创建应用策略和构建 API key。源码构建需分别生成设备授权和 Play 资源：`make build-byos`、`make build-byos-play`；正式发布包已包含对应资源。
2. 在 Shellsmith 的“密钥交付 → 新增服务”中填写 HTTPS 基础地址、构建 API key、授权方式和最终证书 SHA-256。
3. 测试连接，加固并签名 APK。每个产物注册后获得新的 `token_id`。
4. 设备模式首次启动会被拒绝，管理员批准设备后重新启动；Play 模式使用 Play 测试轨道 APK 验证。
5. 撤销设备或产物后，后续取钥失败；已经进入进程的 IKM 和明文代码无法远程收回。

### 安全边界

- BYOS 让 APK 本身不含 IKM，降低仅凭 APK 离线恢复业务密钥的风险；它不等于 DRM，不能阻止已授权进程的内存提取、Hook 或二次打包分析。
- 服务端是信任根。服务端、KMS 或 HSM 被攻破后，攻击者可以解封 IKM；必须按服务端文档保护数据库、主密钥、KMS/HSM 权限和备份。
- 每次启动仍需取钥，DEX 缓存启动也不例外；没有网络或服务端不可用时不会回退到离线加载。撤销只影响后续取钥。
- 构建 API key 只用于加固注册，不进入 APK，也不具备运行时授权能力。
- AAB、iOS 和 Android 4.4 兼容模式不支持 BYOS。

Shellsmith 不托管 BYOS 服务端。仓库提供一份可独立部署的 Go/PostgreSQL 参考实现，包含设备批准、Play Integrity、防重放、审计、主密钥轮换和 `migrate-backend`，支持本机 `local_aead`、AWS KMS、GCP KMS（含 Cloud HSM）和 PKCS#11 HSM。

- [BYOS HTTPS 密钥服务接入协议](docs/design/byos-key-server.md)
- [服务端参考实现与部署](docs/design/byos-key-server-reference.md)
- [BYOS 本地验证与排障记录](docs/process/byos-local-validation.md)
- [技术内参中的 DEXB 边界](docs/design/internals.md)

## 工作原理与安全边界

```mermaid
flowchart TB
    subgraph Android[Android]
        A1[APK / AAB] --> A2[预检]
        A2 --> A3[DEX 加固]
        A3 --> A4[重打包 / 对齐]
        A4 --> A5[签名]
    end
    subgraph iOS[iOS]
        I1[Xcode 工程] --> I2[检查]
        I2 --> I3[源码保护]
        I3 --> I4[Archive / Export]
        I4 --> I5[签名验证]
    end
```

### Android

加固时读取原签名证书，压缩并加密 DEX，注入壳资源，再重新打包、对齐并按需签名。运行时由壳执行安全检查、校验或解密 DEX 缓存，加载业务代码并启动原应用。

本地离线密钥链路的 DEXB v6 载荷加密**不提供针对静态分析的机密性**：包裹密钥的两个输入（签名证书指纹与 build_id）都写在包内头部，仅凭 APK 文件本身即可还原密钥，并进一步解出全部业务 DEX 与 PVM2、加密 assets、业务 `.text` 的派生密钥。该层提供的是「改包重签后无法运行」以及提高自动化扫描与逆向的成本。

在线密钥（BYOS）产物使用 DEXB v7：APK 头部只保存 `server_url` 和 `token_id`，IKM 由服务端保管并在启动时按授权下发，因此仅凭 APK 不能还原 IKM。已授权进程仍会在内存中持有 IKM 和明文代码。

当前正式方案会在应用私有目录使用解密后的 DEX 缓存，**不是完整内存 DEX 或方法代码抽取方案**。Root、进程控制或其他高权限环境下，攻击者仍可能提取运行时代码。标准保护不因 Root 信号拒绝启动；严格保护可阻断部分风险环境，但无法保证识别隐藏 Root 或抵御绕过。

### iOS

iOS 流水线只改工作副本：接入精确版本的上游 Swift Package，生成统一威胁事件封装，调用 Apple 原生 Archive/Export，再核验签名、Team ID、Bundle ID、Entitlements、arm64、隐私清单、dSYM 和选定敏感字符串。freeRASP 的闭源检测能力和已知 RootHide 漏检仍属于上游残余风险。

加固不能替代服务端鉴权、密钥管理和应用自身的安全设计。技术细节见[运行时安全](docs/design/runtime-security.md)、[技术内参](docs/design/internals.md)与 [iOS 加固实现](docs/design/ios-hardening.md)。

## 隐私说明

本地离线密钥模式下，APK、证书、密钥库和签名密码只在本机处理，不上传业务文件。显式启用 BYOS 时，产物 IKM 和构建凭据只发送到你配置的自建 HTTPS 服务，不发送给 Shellsmith 维护者。桌面工具有以下独立数据通道：

| 通道 | 数据与控制方式 |
|---|---|
| 安全错误报告 | 每份报告先预览、再确认发送；不上传原始日志、APK、路径、包名、证书或密码，独立于其他数据通道 |
| 应用使用分享 | 加固/签名页控制，新包名默认选中，同包名取消后跨页及重启保持；成功时发送应用名称、包名、版本码、工具版本、操作、流程、成功日期及协议/去重信息，不带设备标识 |
| BYOS 包外密钥 | 仅在加固配置中显式启用；向用户填写的 HTTPS 服务发送构建凭据和产物 IKM 用于注册/取钥，数据由用户自己的服务端控制 |

应用分享仅维护者可见，明细保留 180 天；取消停止同包名后续分享，不删除已接收记录。**加固后的 APK 不包含这些分享上报。** 数据范围、保留与删除说明见[数据与隐私说明](docs/ops/telemetry.md)。

软件内“问题反馈”不会自动上报：只有在设置页主动填写表单、预览并确认提交后，反馈正文（Bug 反馈还会附带版本、系统、Java 与工具状态等诊断信息）才会发送到 GitHub 公开 issue；服务端不可用时，软件会提供在浏览器打开预填 issue 页面的入口。

iOS balanced/strict 会让目标应用直接集成 freeRASP；其 `watcherMail`、安全事件和网络行为受 Talsec 条款与隐私政策约束，发布前需由应用方完成披露。Shellsmith 不托管 freeRASP 二进制。

## 反馈与交流

- 使用问题请先阅读[反馈指南](docs/process/support.md)，再提交 [GitHub Issue](https://github.com/kairowan/Shellsmith/issues)；也可直接在设置页的“问题反馈”区块提交。
- 功能建议可在设置页的“问题反馈”中选择“需求建议”提交，也可使用[需求表单](https://github.com/kairowan/Shellsmith/issues/new?template=feature_request.yml)；已有相同需求可在原 issue 点赞。
- 安全漏洞请按 [SECURITY.md](SECURITY.md) 私下报告，不公开可利用细节、业务 APK、证书或密码。

## 文档与开发

| 需要了解 | 文档 |
|---|---|
| GUI 操作、签名证书、配置位置、CLI 用法 | [使用指南](docs/usage.md) |
| MCP Server、Agent 集成与工具清单 | [MCP Server](docs/mcp.md) |
| 安装与运行问题 | [本地排障](docs/ops/troubleshooting.md) |
| 从源码编译 | [构建指南](docs/ops/build.md)、[环境要求](docs/ops/environment.md) |
| 模块结构、原理与设计 | [文档导航](docs/README.md) |
| iOS 接入、配置与安全边界 | [iOS 加固实现](docs/design/ios-hardening.md) |
| BYOS 接入协议、错误码与测试向量 | [BYOS HTTPS 密钥服务](docs/design/byos-key-server.md) |
| BYOS 服务端部署、KMS/HSM 与运维 | [服务端参考实现](docs/design/byos-key-server-reference.md) |
| BYOS 本地验证与真实设备排障 | [本地验证记录](docs/process/byos-local-validation.md) |
| 后续规划 | [路线图](docs/process/roadmap.md) |

CLI 与 MCP Server 可从源码构建；`make release` / `scripts/release-cli.sh` 生成的本地 CLI 包同时包含 `shield` 和 `shellsmith-mcp`。构建顺序为先 `make build-stub`，再 `make build-cli` 或 `make build-gui`；完整依赖与平台步骤以构建指南为准。

<details>
<summary>CI/CD 与跨平台发布</summary>

GitHub Actions 位于 `.github/workflows/`：

- 每次推送到 `main` 或创建 Pull Request 时，运行 Rust、Python、iOS 核心和前端检查。
- `Release` 工作流**仅手动触发**：在 `main` 的提交上运行 `workflow_dispatch`，填写与 `package.json` 一致的版本号。工作流会校验来源和版本，在 Linux、macOS、Windows 原生 runner 上构建安装包并创建 GitHub Release，不会因普通 PR 合并自动发版。
- 发布产物包括 Linux `.AppImage`/`.deb`、macOS `.dmg`、Windows `.exe`、Android runtime 资源包及 SHA-256 校验文件，并生成更新清单。
- macOS 默认生成 adhoc 签名包；配置 `MACOS_RELEASE_MODE=developer-id`、Developer ID 身份和 notarytool profile 后，才生成可分发的公证包。

本地也可以复用同一套脚本，版本号直接从 `package.json` 读取：

```bash
VERSION=$(node -p "require('./apps/shield-gui/package.json').version")
VERSION="$VERSION" ./scripts/release-linux.sh
VERSION="$VERSION" ./scripts/release-macos.sh "$VERSION" universal
```

Windows 使用管理员 PowerShell：

```powershell
$version = (Get-Content apps/shield-gui/package.json | ConvertFrom-Json).version
.\scripts/release-windows.ps1 -Version $version
```

三平台构建都包含 Stub、PVM2 Packer、Android 资源和签名工具，发布前仍应在目标系统安装并验证。

</details>

## 致谢

Shellsmith 的加固能力建立在这些上游项目与工具之上。随发布包分发的组件，其许可证与第三方声明见 `tools/licenses/`。

<details>
<summary>上游项目与工具</summary>

### 上游来源工程

| 项目 | 许可证 | 说明 |
|---|---|---|
| [Mocika Shield](https://github.com/mocikadev/mocika-shield) | MIT OR Apache-2.0 | 本项目的来源工程。DEX 加密、壳加载、签名绑定、基础运行时保护与证书/签名管理流程均由此演化而来；Shellsmith 在其基础上扩展了 iOS 加固、AAB 处理、Native VMP 与应用内更新。 |

### 代码保护

| 项目 | 许可证 | 用途 |
|---|---|---|
| [XopProtector](https://github.com/xopJack/XopProtector) | Apache-2.0 | PVM2 与 True-VMP 代码保护；壳运行时源码与打包器源码随本仓库分发（`third_party/xopprotector/`），`xop-pvm2-packer.jar` 随发布包分发 |
| [LLVM](https://llvm.org/) | Apache-2.0 WITH LLVM-exception | Native VMP 以 LLVM 21 Pass 插件形式接入业务 Native 构建（`native-vmp/`，独立组件，尚未接入加固流程） |

### iOS 运行时保护

| 项目 | 许可证 | 用途 |
|---|---|---|
| [freeRASP](https://github.com/talsec/Free-RASP-iOS) 7.1.4 | MIT，另受 Talsec 公平使用政策约束 | iOS 运行时威胁检测；由用户本机解析，发布包不重新分发其二进制 |
| [Swift Confidential](https://github.com/securevale/swift-confidential) 0.5.2 | Apache-2.0 | Swift 敏感字面量保护（可选） |

### 打解包、签名与构建工具

| 项目 | 许可证 | 用途 |
|---|---|---|
| [Apktool](https://apktool.org/) 3.0.3 | Apache-2.0 | APK 反编译与重打包，随发布包分发 |
| [apksigner](https://developer.android.com/tools/apksigner)（Android SDK Build-Tools） | Apache-2.0 | APK 签名与签名校验，随发布包分发 |
| [bundletool](https://github.com/google/bundletool) · [aapt2](https://developer.android.com/tools) | Apache-2.0 | AAB 模块处理与资源编译 |
| [Android NDK](https://developer.android.com/ndk) | Apache-2.0 | 壳 Native 库与 Android 4.4 兼容库的编译 |

桌面框架、前端与 Rust 通用库依赖不在本节逐一列出；完整版本与许可证可从 `Cargo.lock`、`apps/shield-gui/package-lock.json` 与 `shield-stub/gradle/libs.versions.toml` 复现。

</details>

如果这里署名有误、许可证标注不准或遗漏了应当致谢的项目，欢迎提交 issue 或 PR，我们会尽快更正。

## 许可证

采用 **MIT OR Apache-2.0** 双协议，可选择其中任意一种：[MIT](LICENSE-MIT) · [Apache-2.0](LICENSE-APACHE)。
