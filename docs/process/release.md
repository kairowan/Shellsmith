# 发布与版本管理

## 版本号语义

稳定版本号格式：`major.minor.patch`（如 `1.2.3`）。预发布版本允许 SemVer 后缀，例如 `1.2.0-rc.1`。

| 版本位 | 触发条件 | 示例 |
|--------|----------|------|
| **Major** | 功能积累到一定程度的里程碑版本，或 CLI/GUI 接口有破坏性变更 | 多个 Minor 功能积累后升为 2.0；CLI 子命令结构重构等 |
| **Minor** | 新增一个完整功能 | 版本更新提示、反调试检测、CLI 子命令等，每个对应一次 minor 升级 |
| **Patch** | Bug 修复，不新增功能 | 签名检测修复、异常路径 fail-closed 修复等 |

> DEXB 格式变化属于内部算法优化，**不触发 major 升级**。由于加固后的 APK 自包含壳模块，格式升级对用户完全无感。

### Git Tag 命名规范

发布时统一使用 `v{version}` 格式，如 `v1.0.0`、`v1.2.3`、`v1.2.0-rc.1`。

- 前缀固定小写 `v`
- 不使用 `V`（大写）、不省略前缀
- 只允许标准 SemVer 预发布后缀（如 `-rc.1`），不使用非标准后缀（如 `-stable`）
- GUI 版本检查解析时兼容大小写（`v`/`V` 均可 strip），但发布时只用小写

### 分支管理策略

当前阶段采用 **单主干 `main` + tag 发布**：

- `main`：长期稳定主干，保持可构建、可发布
- `vX.Y.Z` / `vX.Y.Z-rc.N`：唯一正式发布标记
- `feat/*`：复杂功能的临时开发分支，合并回 `main` 后删除
- `fix/*`：缺陷修复的临时分支，合并回 `main` 后删除

暂不维护长期 `develop` 分支，也不默认创建 `release/*` / `hotfix/*` 分支，避免刚开源阶段增加流程成本。

只有出现以下情况时，才新增长期维护分支：

- 多个正式版本线需要并行维护，例如 `1.2.x` 与 `1.3.x`
- 某个大功能周期较长，不能持续保持 `main` 可发布
- 多人协作规模扩大，需要隔离稳定分支和开发分支

如需维护旧版补丁，优先从对应稳定 tag 拉出 `release/x.y`，修复后打 `vX.Y.Z` patch tag。

#### `main` 分支保护规则

GitHub 的 `main` 分支必须保持保护状态，正式代码统一通过临时分支和 Pull Request 合入。当前规则按单维护者仓库配置，不要求作者无法自行完成的人工审批。

| 规则 | 配置 |
|------|------|
| 合并前必须创建 Pull Request | 启用 |
| 必需审批数 | `0` |
| 合并前必须更新到最新 `main` | 启用 |
| 必须解决全部对话 | 启用 |
| 允许强制推送 | 禁止 |
| 允许删除 `main` | 禁止 |
| 要求签名提交 | 暂不启用 |
| 管理员强制执行 | 暂不启用，保留紧急绕过能力 |

Pull Request 合并前必须通过以下 CI 检查：

- `基础快速检查`

普通 PR 只执行 Rust 格式和脚本契约测试，避免每次提交重复等待完整编译与跨平台打包。完整代码质量检查、Android 壳构建、Linux Tauri 打包冒烟检查、Windows Android 4.4 资源构建和发布前检查仅在手动触发 CI 时执行；版本发布仍由 Release 工作流完整构建三个平台。

日常开发流程：

1. 从最新 `main` 创建 `feat/*`、`fix/*`、`docs/*` 等临时分支。
2. 完成修改和本地验证后推送远端并创建 Pull Request。
3. 等待全部必需 CI 通过，并解决未完成的评审对话。
4. 合并到 `main`，随后删除临时分支。
5. 只有发布版本时才从已验证的 `main` 创建并推送 `vX.Y.Z` tag。

管理员绕过只用于保护规则配置错误、CI 基础设施不可用或紧急安全修复。绕过后必须补建对应 Pull Request 或维护记录，不作为日常直接推送 `main` 的方式。

### GUI 版本更新提示策略

| 检测到版本差异 | 提示方式 |
|----------------|----------|
| **Patch** | 顶部小提示条，可一键关闭 |
| **Minor** | 顶部提示条，持续显示直到用户手动关闭 |
| **Major** | 启动时弹窗，展示新版本说明并由用户确认安装 |

### 应用内更新发布约束

- 自 v1.4.5 起复用 [Tauri 官方更新器](https://v2.tauri.app/plugin/updater/)，固定读取 `https://github.com/kairowan/Shellsmith/releases/latest/download/latest.json`，不需要单独后台。
- 首次发布前生成专用更新签名密钥，把私钥设为 GitHub Actions Secret `TAURI_SIGNING_PRIVATE_KEY`，公钥放 `tauri.conf.json`。私钥必须另行安全备份，不能提交仓库或放进安装包；丢失后旧客户端无法信任新密钥。当前私钥无口令，CI 设置空的 `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`。
- 发布脚本要求提供该环境变量（可为密钥文件路径），Tauri CLI 使用 2.11.5。普通开发构建无需私钥；仅做本地打包测试时可传 `--config '{"bundle":{"createUpdaterArtifacts":false}}'`，不得用这种构建覆盖正式更新产物。
- macOS 在最终应用签名后重新生成 `.app.tar.gz` 并签名；Windows 上传 NSIS `.exe` 和 `.sig`；Linux 上传 AppImage 和 `.sig`。macOS universal 包同时服务两种架构。
- 工作流同步实际打包版本；所有产物上传完成后执行 `scripts/generate_update_manifest.py` 验证文件、地址和签名版本，再上传清单并公开 Release。GitHub 草稿的 `untagged-…` 临时地址仅在确认草稿 tag 匹配后接受，清单始终写正式 tag 地址。客户端仍会执行密码学验签，不能用 SHA-256 替代。
- `requireSignedVersion` 必须保留为 `true`，阻止清单把旧包标成新版本。草稿和预发布不更新稳定通道，已公开的版本不得覆盖，失败只重跑原草稿或提升版本号。
- 更新签名与 Apple Developer ID / 公证、Windows Authenticode 是不同机制；当前 CI 的 macOS adhoc 模式并不等于 Apple 公证。
- 回归入口：`cargo test -p mocika-shield`（含真实签名、篡改及伪造版本测试）、`python3 -m unittest discover -s scripts/tests -v`（含三平台清单完整性测试）。

---

## 版本号同步

升级版本时，需同步修改以下文件：

| 文件 | 字段 |
|------|------|
| `crates/shield-core/Cargo.toml` | `version = "x.y.z[-pre]"` |
| `apps/shield-cli/Cargo.toml` | `version = "x.y.z[-pre]"` |
| `shield-stub/src/main/rust/Cargo.toml` | `version = "x.y.z[-pre]"` |
| `shield-stub/compat/api19-rust/Cargo.toml` | `version = "x.y.z[-pre]"` |
| `shield-stub/compat/api19-rust/Cargo.lock` | 独立兼容 crate 的根包版本；发布构建使用 `--locked` |
| `apps/shield-gui/src-tauri/Cargo.toml` | `version = "x.y.z[-pre]"` |
| `apps/shield-gui/src-tauri/tauri.conf.json` | `"version": "x.y.z[-pre]"` |
| `apps/shield-gui/package.json` | `"version": "x.y.z[-pre]"` |
| `apps/shield-gui/package-lock.json` | `"version": "x.y.z[-pre]"` |

优先使用：

```bash
bash scripts/bump-version.sh x.y.z
bash scripts/bump-version.sh x.y.z-rc.1
```

脚本会使用 Rust 1.77.2 同步 API 19 兼容 crate 的独立锁文件，冷启动环境允许联网获取依赖索引；修改后仍需运行 `cargo build` 或 `make build-all`，使根 `Cargo.lock` 同步更新。

---

## 发布命令

### Linux / macOS

```bash
# CLI-only 发布包（维护者本地使用）
make release VERSION=x.y.z

# 仅 CLI 发布包（tar.gz，本地生成，不由 GitHub Release 上传）
bash scripts/release-cli.sh x.y.z

# Linux 本地发布（默认 GUI + CLI；CI 设置 SKIP_CLI_RELEASE=1 只上传 GUI）
VERSION=x.y.z make release-linux

# macOS 本地发布（默认 GUI + CLI；CI 设置 SKIP_CLI_RELEASE=1 只上传 GUI）
VERSION=x.y.z make release-macos

```

### Windows（必须在 Windows 原生环境执行）

```powershell
# Windows 本地发布（默认 GUI + CLI；CI 设置 SKIP_CLI_RELEASE=1 只上传 GUI）
.\scripts\release-windows.ps1 -Version x.y.z
```

脚本会自动检测并安装缺失的 cargo 工具（tauri-cli / cargo-ndk），并通过 npm 构建 React 前端，首次运行耗时较长。

---

## 发布包结构

本地发布脚本默认仍会生成 CLI 与 GUI 产物，便于维护者离线分发或调试；GitHub Actions 的 Release workflow 会设置 `SKIP_CLI_RELEASE=1`，只构建并上传 GUI 安装包。

### CLI 本地发布包

```
Shellsmith-x.y.z/
├── bin/
│   └── shield              # 可执行文件（Windows 为 shield.exe）
├── lib/
│   ├── apktool.jar
│   └── apksigner.jar
├── resources/
│   └── resources.zip       # shield-stub 产物（Android 壳 DEX + .so）
└── README.md
```

### GUI 发布包

| 平台 | 产物 | 说明 |
|------|------|------|
| Linux（Tauri） | `Shellsmith_x.y.z_linux_amd64.AppImage` | 免安装，直接运行 |
| Linux（Tauri） | `Shellsmith_x.y.z_linux_amd64.deb` | Debian/Ubuntu 安装包 |
| macOS（Tauri） | `Shellsmith_x.y.z_macos_aarch64.dmg` / `Shellsmith_x.y.z_macos_universal.dmg` | Tauri 版 |
| Windows | `Shellsmith_x.y.z_windows_x64_setup.exe` | NSIS 安装包 |

GUI 发布包已内置 apktool.jar、apksigner.jar、resources.zip，用户无需额外配置工具路径。

### Windows 本地发布产物（`dist/` 目录）

```
dist/windows/
├── Shellsmith_x.y.z_windows_x64_setup.exe    # GUI NSIS 安装包
├── Shellsmith-cli-x.y.z-windows-x86_64.zip  # CLI 本地发布包；CI 不上传
└── checksums-sha256.txt
```

---

## 构建顺序约束

`shield`（CLI）和 GUI 运行时均依赖 `resources.zip`，**必须先完成 shield-stub 构建**：

```
make build-stub  →  make build-cli / make build-gui / make release / make release-linux / make release-macos
```

`make release` 是 CLI-only 本地发布包；各平台 GUI 发布脚本均已内置必要构建顺序，无需手动保证。

---

## GitHub Actions CI/CD

仓库包含两个工作流：

| 工作流 | 文件 | 触发 | 内容 |
|--------|------|------|------|
| CI | `.github/workflows/ci.yml` | push / pull request / 手动触发 | 普通提交与 PR 执行基础快速检查；手动触发时执行完整代码质量、Android 壳、Linux Tauri、Windows Android 4.4 资源及发布前检查 |
| Release | `.github/workflows/release.yml` | main 的 CI 成功 / 手动触发 | 并行构建三平台，先上传草稿，再校验并公开 GitHub Release |

> GitHub Release 上传 GUI 安装包、签名更新包、更新清单、校验和与 Android 运行时资源；CLI 包仍可通过本地发布脚本生成。

Release Notes 相关文件：

| 文件 | 作用 |
|------|------|
| `.github/release.yml` | GitHub 自动生成变更列表的分类配置 |
| `.github/release-notes/stable.md` | 稳定版本固定前言模板 |
| `.github/release-notes/prerelease.md` | 预发布版本固定前言模板 |

### 自动发布流程

```bash
# 1. 在临时分支更新版本号，经 PR 和 CI 验证后合并 main
make bump-version V=x.y.z

# 2. 从已验证的 main 触发正式版本发布
gh workflow run release.yml --ref main -f version=x.y.z
```

`Release` workflow 会自动：

1. 手动触发使用输入版本；main 的 CI 成功触发时生成 `x.y.z-build.N` 预发布版本
2. 创建草稿 Release，固定当前构建提交；构建时同步版本号
3. 三个平台并行构建，直接上传草稿，不依赖 Actions artifact 存储额度
4. 校验更新包、签名、版本与校验和文件，生成 `latest.json`
5. 全部成功后公开 Release 并创建对应 tag；稳定版设为 latest，预发布版不进入稳定更新通道

各平台发布脚本生成的校验和保留本地 `dist` 子目录，便于维护者直接校验本地产物。Release 汇总任务上传前会将记录规范化为扁平文件名，并拒绝无效记录或重复文件名，确保下载校验和文件后可在安装包所在目录直接执行校验。

发布可见性规则：

- **稳定版本**（如 `v1.2.0`）：先创建 **Draft**，全部检查通过后公开并设为 latest
- **预发布版本**（如 `v1.2.0-rc.1`、`v1.2.0-build.10`）：先创建 **Draft**，全部检查通过后公开为 **Pre-release**

任一构建或检查失败时保留草稿，不向客户端宣告可更新。

Release Notes 生成规则：

- workflow 先读取稳定版或预发布版的简洁中英文前言模板
- 如果存在 `.github/release-notes/versions/x.y.z.md`，在固定“本次变更”章节下插入该版本系列的人工中英文能力汇总；同一系列的 Alpha、Beta、RC 和正式版复用该文件
- 再查找当前标签之前最近一个已公开正式版本，作为 GitHub Release Notes API 的固定比较基线
- Alpha、Beta、RC 和最终正式版均汇总相对上一正式版本的完整版本周期变更，不以相邻预发布标签作为比较基线
- 合并自动变更列表前移除 GitHub 自带的 `What's Changed` 标题，避免与固定中英文章节重复；分类标题和 `Full Changelog` 保持不变
- 最终将两部分合并后写入 Release
- 只允许重跑未公开的草稿；已公开 tag/Release 不覆盖，修订须使用更高版本号

所有稳定版和预发布版 Release Notes 固定保留以下章节，顺序保持一致：

1. `下载 / Downloads`
2. `使用须知 / Notes`
3. `本次变更 / What's Changed`

Release Notes 末尾同时保留 GitHub 生成的 `Full Changelog` 比较链接，但不要求它作为独立章节。Release Notes 只保留下载入口、必要运行条件、安全边界和本版本变更，不重复 README 中的完整功能介绍。人工精简发布说明时，可以把自动列表整理成 2～5 条中英文版本亮点，但必须放在 `本次变更 / What's Changed` 下，不得改名或删除固定章节。编辑完成后使用 `gh release view <tag> --json body --jq '.body'` 复核章节；若之后重新运行同一个 tag 的发布任务，自动生成内容会覆盖人工修改，需要再次检查固定章节和版本亮点。

### 手动触发发布

在 GitHub Actions 页面选择 `Release` workflow、已验证的 main 和版本号 `x.y.z` 后运行。构建成功会公开 Release 并创建对应 tag，不需要另行推送 tag。仅推送 tag 不会触发当前工作流。输入预发布后缀时，最终公开为 Pre-release。

---

## 发布检查清单

1. 更新版本号（见上方"版本号同步"）
2. 运行发布前轻量检查：`bash scripts/check-release-ready.sh`
3. 确认 CI 通过
4. 打 tag 并推送：`git tag vx.y.z && git push origin main vx.y.z`
5. 等待 Release workflow 完成
6. 检查 GitHub Release 的产物、校验和，以及固定的中英文 Release Notes 章节
7. 稳定版本确认无误后取消草稿正式发布；预发布版本确认可见性与产物即可

### 正式版前产物检查

正式版发布前需额外确认：

- Release 页面只包含 GUI 安装包与校验和文件，不上传 CLI 包
- 安装包内包含 `apktool.jar`、`apksigner.jar`、`resources.zip`
- 安装包内不包含测试 APK、测试证书、`shield.db`、`config.toml`、`.env` 或本地缓存
- README、使用文档、Release Notes 已说明 Java/PVM2 版本、证书管理、密码加密、16 KB 对齐，以及 macOS adhoc 与 Developer ID 公证模式的区别
- 支持与问题反馈文档、issue 模板和关于页诊断信息入口保持一致
- 下载 Release 产物后至少完成一次证书导入/创建、设为默认、签名、加固、自动签名回归
- 解压内置 `resources.zip` 与 `resources-api19.zip`，确认只包含预期 DEX、元数据和 Native 库，不包含 `.DS_Store`、测试文件或其他本机临时产物

`1.2.7` 的候选版本、设备矩阵、未决事项和正式版判断记录在[测试清单的发布前收尾审计](test-checklist.md#2026-07-29127-发布前收尾审计)中。

### 产物与命名规则

| 平台 | 产物文件 |
|------|----------|
| Linux（Tauri） | `Shellsmith_X.Y.Z_linux_amd64.AppImage`、`Shellsmith_X.Y.Z_linux_amd64.deb`、`linux-tauri-checksums-sha256.txt` |
| macOS（Tauri） | `Shellsmith_X.Y.Z_macos_universal.dmg`、`macos-tauri-checksums-sha256.txt` |
| Windows | `Shellsmith_X.Y.Z_windows_x64_setup.exe`、`windows-checksums-sha256.txt` |

> 发布仓库：`kairowan/Shellsmith`（源码与 Release 包同仓库维护）
