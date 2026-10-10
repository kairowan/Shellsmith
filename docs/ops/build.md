# Shellsmith — 编译指南

## 环境要求

详细环境配置见 [environment.md](environment.md)。

| 工具 | 版本要求 | 说明 |
|------|----------|------|
| Rust | 1.70+ | 含 rustup |
| Java / JDK | 17+ | 必须为完整 JDK，且 `java`、`javac`、`keytool` 均需在 PATH |
| Android SDK | Platform 35 | 需设置 `ANDROID_HOME` |
| Android build-tools | 35.0.0 | 提供 `d8` 等 Android 构建工具 |
| Android NDK | 29.0.14206865 + 25.2.9519653 | 标准资源使用 r29；Android 4.4 兼容资源使用 r25c |
| cargo-ndk | 最新 | Android 交叉编译 |
| Node.js / npm | Node.js 22+ | React 前端构建 |
| tauri-cli | 最新 | GUI 构建驱动（Tauri GUI 需要） |
| Xcode | 完整 Xcode，iOS 13+ SDK | 仅 macOS iOS Archive/导出需要；Command Line Tools 不够 |

---

## 快速开始（Makefile）

```bash
make build-stub             # ① 构建 Android 壳（必须最先执行）
make build-cli              # ② 编译 shield 命令行工具
make build-gui              # ③ 构建桌面 GUI Tauri 版（需先 build-stub）
make build-all              # build-stub + build-cli + build-gui（Tauri）
make test                   # 运行 Android 核心、iOS 核心、CLI 单元测试
make clean                  # 清理所有构建产物
```

> **构建顺序约束**：`shield`（CLI）和 GUI 运行时均依赖 `resources.zip`，必须先执行 `make build-stub`。

iOS 代码本身可以在没有完整 Xcode 时编译和执行静态检查；只有 `protect-ios` 的 Archive/Export 阶段需要在 macOS 选择完整 Xcode：

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -version
cargo test -p shield-ios
```

如果 `xcodebuild -version` 指向 `/Library/Developer/CommandLineTools` 并报错，Shellsmith 会阻断构建，不会把静态检查伪报为已完成 Archive。

---

## 分步说明

### 1. 构建 shield-stub（Android 壳模块）

```bash
make build-stub
# 等价于：bash scripts/build-stub.sh
```

**Linux / macOS**：运行 `scripts/build-stub.sh`
**Windows**：运行 `scripts\build-stub.ps1`（Makefile 自动选择）

输出：`shield-stub/build/outputs/resources/resources.zip`

壳运行时（静态链入的 Xop PVM2 解释器）直接编译仓库内的 `third_party/xopprotector/native/src/main/cpp`，
不需要检出外部仓库。该目录同时保存了内置打包器 `tools/xop-pvm2-packer.jar` 的 Java 源码，
两者因此始终同源；若要用更新版本的 XopProtector 覆盖，设置 `MOCIKA_XOP_ROOT` 指向新的检出即可，
但必须同时确认内置打包器与该检出同源（发布流程会校验两侧的镜像格式版本）。

首次执行前需添加 Android Rust 编译目标：

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  i686-linux-android x86_64-linux-android
```

### 2. 编译 shield-cli

```bash
make build-cli
# 等价于：cargo build --release -p shield-cli
```

输出（Linux / macOS）：`target/release/shield`
输出（Windows）：`target\release\shield.exe`

### 3. 构建 shield-gui（Tauri 桌面应用）

```bash
make build-gui
# 等价于：cd apps/shield-gui && cargo tauri build --no-bundle
```

Linux 首次构建前请先安装 Tauri 所需系统依赖，见 [environment.md](environment.md#linux-构建依赖)。

输出（Linux / macOS）：`target/release/mocika-shield`
输出（Windows）：`target\\release\\mocika-shield.exe`

如需生成 `.AppImage`、`.deb`、`.dmg`、NSIS `.exe` 等正式 bundle，请使用下方发布脚本，而不是 `make build-gui`。

GUI bundle 会把 `tools/xop-pvm2-packer.jar` 作为默认 PVM2 Packer 内置，并同时携带 `tools/licenses/XopProtector-*` 的 Apache-2.0 许可与 NOTICE。Packer 产物要求 Java 17+；用户在 GUI 中选择外部兼容 JAR 时会覆盖内置版本。

> **本机测试规则**：如果目的是在本机实际验证 GUI 效果、签名、加固等完整桌面流程，不要只使用 `make build-gui` 产出的裸二进制。应构建对应平台的正式应用包；在 macOS 上默认使用 `.app` / `.dmg` 产物进行测试。

## 发布包构建

### Linux / macOS

```bash
# CLI-only 发布包（维护者本地使用）
make release VERSION=x.y.z

# 仅 CLI 发布包（本地生成，不由 GitHub Release 上传）
bash scripts/release-cli.sh x.y.z

# Linux 本地发布（默认 GUI + CLI；CI 设置 SKIP_CLI_RELEASE=1 只上传 GUI）
VERSION=x.y.z make release-linux

# macOS 本地发布（默认 GUI + CLI；CI 设置 SKIP_CLI_RELEASE=1 只上传 GUI）
VERSION=x.y.z make release-macos
```

macOS 默认生成仅供本机测试的 adhoc 包。对外分发必须先把 Apple Developer ID
证书导入钥匙串，并把公证凭据存进钥匙串（不把密码写进脚本或环境变量）：

```bash
xcrun notarytool store-credentials mocika-notary \
  --apple-id you@example.com \
  --team-id TEAMID \
  --password APP_SPECIFIC_PASSWORD

MACOS_RELEASE_MODE=developer-id \
MACOS_SIGN_IDENTITY="Developer ID Application: Example Corp (TEAMID)" \
MACOS_NOTARY_PROFILE=mocika-notary \
VERSION=x.y.z make release-macos
```

`developer-id` 模式会启用 hardened runtime，签署 `.app` 和 `.dmg`，等待 Apple
公证，装订并验证 ticket，再执行 Gatekeeper 检查。证书、钥匙串 profile、公证或
Gatekeeper 任一步缺失/失败都会终止构建，不会退回 adhoc 包。成功产物文件名带
`_notarized`；不带该后缀的本地包不得作为免提示外部分发包。

### Windows（必须在 Windows 原生环境执行）

```powershell
# Windows 本地发布（默认 GUI + CLI；CI 设置 SKIP_CLI_RELEASE=1 只上传 GUI）
.\scripts\release-windows.ps1 -Version x.y.z
```

---

## 发布包结构

### CLI 本地发布包

```
Shellsmith-x.y.z/
├── bin/
│   └── shield              # 可执行文件（Windows 为 shield.exe）
├── lib/
│   ├── apktool.jar
│   ├── apksigner.jar
│   └── xop-pvm2-packer.jar
├── resources/
│   ├── resources.zip       # Android 5+ 完整运行时
│   └── resources-api19.zip # Android 4.4 ARMv7 兼容运行时
├── licenses/               # XopProtector 许可证与声明
└── README.md
```

### GUI 发布包

| 平台 | 产物 |
|------|------|
| Linux（Tauri） | `Shellsmith_x.y.z_linux_amd64.AppImage`、`Shellsmith_x.y.z_linux_amd64.deb` |
| macOS（Tauri） | `Shellsmith_x.y.z_macos_universal.dmg` |
| Windows | `Shellsmith_x.y.z_windows_x64_setup.exe` |

---

## 常见问题

### cargo-ndk / tauri-cli / npm 未安装

```bash
cargo install cargo-ndk
cargo install tauri-cli --version '^2'
node --version
npm --version
```

Windows 发布脚本会自动检测并安装缺失的 cargo 工具。

### Linux：`failed to run linuxdeploy`

这通常不是代码问题，而是 Linux Tauri / AppImage 打包依赖不完整。

优先检查是否已安装 [environment.md](environment.md#linux-构建依赖) 中列出的系统包，尤其是：

- `file`
- `wget`
- `libxdo-dev`
- `librsvg2-dev`
- `libfuse2`

仓库的完整手动 `CI` 包含 Linux Tauri bundle 冒烟检查；修改 Tauri 打包链路后应主动运行，无需等到打 tag 再排查。

### NDK 未找到

```bash
# 检查已安装版本
ls $ANDROID_HOME/ndk/

# 设置环境变量（优先级高于 build.gradle 内硬编码路径）
export ANDROID_NDK_ROOT=$ANDROID_HOME/ndk/29.0.14206865
```

如果本机没有 CI 固定的 NDK，可在标准 Stub 构建时显式选择已安装的兼容版本；这只用于本地验证，发布 CI 仍使用锁定版本：

```bash
MOCIKA_NDK_VERSION=28.2.13676358 \
MOCIKA_RUST_TOOLCHAIN=stable \
MOCIKA_GRADLE_BIN=/path/to/gradle \
  ./scripts/build-stub.sh
```

API19 兼容资源不会因为存在标准 `resources.zip` 就自动生成。必须同时提供
`NDK r25c (25.2.9519653)`、Rust `1.77.2` 的 `armv7-linux-androideabi` target，
并通过 ELF/API19 审计；也可以用 `ANDROID_NDK_API19_ROOT` 指向自定义 NDK 目录，脚本
仍会校验 `source.properties` 的精确版本。缺少任一条件时构建失败关闭，不会把标准包
复制或改名为 `resources-api19.zip`。

`MOCIKA_RUST_TOOLCHAIN` 用于解决系统默认 `cargo` 与 rustup Android target 不一致的问题。API19 资源仍必须通过 r25c（25.2.9519653）和 Rust 1.77.2 的 ELF 审计；如果本机缺少这两个版本，脚本应失败并保留原因，不能复用标准 `.so` 冒充兼容包。

### Rust 目标未安装

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  i686-linux-android x86_64-linux-android

# Windows GUI（MSVC 工具链）
rustup target add x86_64-pc-windows-msvc
```

### Gradle 构建失败

```bash
# 清理缓存后重新构建
./shield-stub/gradlew -p shield-stub clean
make build-stub
```

### Windows：`make` 命令不存在

通过 Scoop 安装：

```powershell
scoop install make
```

### Windows：路径问题（UNC 前缀）

VirtualBox 共享文件夹等场景下 `current_exe()` 可能返回 `\\?\UNC\...` 格式路径。
代码已通过 `dunce` crate 自动规范化，无需手动处理。
