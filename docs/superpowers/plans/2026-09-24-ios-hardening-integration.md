# Shellsmith iOS 与 Android 双平台加固实施计划

> 计划日期：2026-09-24，代码落地日期：2026-09-24。执行时保留现有 Android 内部标识和兼容接口，新增界面、文档与发布名称统一使用 **Shellsmith**。代码完成不等于发布验收；真实 Xcode、签名、设备与法律审查仍按门禁记录。

## 当前进度

- [x] 调研 Swift Confidential、freeRASP iOS、Apple 签名与分发限制。
- [x] 明确两套方案的能力边界、代际定位、许可证和隐私约束。
- [x] 明确采用“Android 现有实现保持稳定，iOS 新增独立流水线”的融合方向。
- [x] 阶段零：已冻结产品边界、支持矩阵、精确依赖版本和配置合同。
- [x] 阶段一：已完成 Xcode 工程静态/Xcode 双路径检查、已知问题门禁和 JSON 报告。
- [x] 阶段二：已接入 Swift Confidential 0.5.2，复制并校验选择性配置，Archive 后扫描选定明文。
- [x] 阶段三：已接入 freeRASP iOS 7.1.4，生成稳定威胁事件、分级响应接口和主应用 target 直接依赖。
- [x] 阶段四：Archive、ExportOptions、IPA 定位及 codesign/Team/Bundle/Entitlements/arm64/隐私清单/dSYM 验证代码已完成；完整 Xcode 实跑仍是发布门禁。
- [x] 阶段五：CLI、Tauri 命令、取消/进度状态和 Android/iOS 界面切换已接入。
- [ ] 阶段六：完成真实设备、兼容性、许可证及发布验收。
- [ ] 阶段七：已完成 App Attest 客户端合同；服务端地址为可选增强项，服务端挑战、证明校验与重放防护尚未实现，因此不标记为第四代。

当前主机只有 Apple Command Line Tools，没有完整 Xcode。Rust、SwiftPM 清单、CLI、Tauri 后端与前端验证已完成；`.xcarchive`、IPA、App Store Connect、真机 RASP 与 App Attest 服务端闭环没有被伪报为通过。准确执行证据见[兼容性矩阵](../../process/compatibility-matrix.md)和[测试清单](../../process/test-checklist.md)。

**目标：** 在不破坏 Shellsmith 现有 Android 加固能力和内部兼容标识的前提下，增加以源码工程为输入的 iOS 加固流水线。第一版将 Swift Confidential 的构建期敏感字符串保护与 freeRASP iOS 的运行时检测组合，输出可验证的 `.xcarchive` 和 `.ipa`。

**架构：** Android 继续使用现有 `shield-core` 和壳运行时；iOS 新建独立 `shield-ios` 核心，由 CLI 和 Tauri GUI 复用同一任务接口。iOS 流水线在受控工作副本中修改工程、解析 Swift Package、调用 `xcodebuild`、导出并验证签名，默认不直接改写用户原工程。

**技术栈：** 现有 Rust/Tauri/React；macOS、Xcode 16、Swift 6、Swift Package Manager；Swift Confidential、freeRASP iOS；不为第一版新增自研 Mach-O 重写器、LLVM 混淆器或远程构建服务。

## 一、能力判断与代际定义

本文的“代际”是 Shellsmith 为规划能力而定义的工程分层，不是 Apple、OWASP 或行业统一标准：

| 代际 | 能力 | 本项目对应状态 |
|---|---|---|
| 第一代 | Release 构建、符号裁剪、签名和基础完整性检查 | iOS/Android 平台基线 |
| 第二代 | 静态混淆、字符串/资源保护、符号或控制流变换 | Swift Confidential 提供其中的敏感字符串保护 |
| 第三代 | 运行时应用自保护，检测调试、Hook、越狱、篡改和重打包 | freeRASP iOS；现有 Android 运行时也属于这一层 |
| 第四代 | 服务端证明、动态策略、按实例或按版本下发密钥、编译器级多样化 | 后续 App Attest 与服务端能力，第一版不包含 |

据此给出明确结论：

- **Swift Confidential：第二代的局部方案。** 它在源码/构建阶段对被选中的 Swift 字符串执行压缩、加密和随机化；不提供完整函数混淆、控制流变换、Mach-O 重写或运行时反调试。
- **freeRASP iOS：第三代方案。** 它负责签名、越狱、调试器、运行时操作/Hook、模拟器、非官方商店、截图录屏、时间伪造等运行时信号；不替代静态混淆。
- **二者融合：分层第三代方案。** 组合后同时具备局部第二代静态保护和第三代运行时检测，但仍不能称为完整第四代。
- **Shellsmith Android：现有能力按本定义属于第三代增强方案。** DEX、原生装载、资源和运行时策略继续独立演进；没有服务端证明时不宣称第四代。

## 二、边界与非目标

### 第一版支持边界

- 输入为用户拥有源码和签名权限的 `.xcodeproj` 或 `.xcworkspace`。
- macOS 执行依赖解析、Archive、导出和签名；Windows/Linux 仅允许配置编辑、静态检查和报告查看。
- SwiftUI 与 UIKit 为一等支持对象；混合 Objective-C 工程可以接入 RASP，但 Swift Confidential 只处理 Swift 源码。
- Widget、Extension、App Clip 等目标逐个检查 Bundle ID、签名和依赖，不能默认复用主应用配置。
- 最低部署版本以 Swift Confidential 当前包声明的 iOS 13 为基线；正式锁定依赖时再次读取上游 Package 清单。
- 仅有 `.ipa` 时提供包结构、签名、权限、依赖和风险审计，不承诺自动注入并重新签名。

### 第一版非目标

- 不修改任意第三方 IPA，不绕过签名、DRM 或 App Store 审核规则。
- 不采用下载后执行代码、JIT、自修改代码或 Android 式动态 DEX 装载设计。
- 不宣称“无法破解”“绝对安全”或把风险检测结果当作攻击事实。
- 不自动加密所有字符串；本地化键、Objective-C selector、反射名称、Storyboard/资源名等必须保持兼容。
- 未获得明确再分发授权前，不把 freeRASP 二进制复制、改名或打包进 Shellsmith 安装包。
- 第一版不自研 LLVM Pass、控制流平坦化、Mach-O 函数虚拟化或资源容器。
- 不重命名现有 Android crate、命令、namespace、数据目录和环境变量；外部产品名称使用 Shellsmith，内部标识保留兼容。

## 三、总体架构

### 目录与责任

```text
crates/shield-ios/
  src/lib.rs                 # 稳定的 iOS 任务接口与阶段编排
  src/project_inspect.rs     # 工程、target、scheme、Bundle ID 和部署版本检查
  src/confidential.rs        # Swift Confidential 配置、版本锁定和候选项校验
  src/freerasp.rs            # freeRASP 配置与启动代码生成
  src/xcodebuild.rs          # resolve、archive、export 命令和结构化进度
  src/archive_verify.rs      # Archive/IPA、Mach-O、依赖、隐私清单和架构验证
  src/signing.rs             # Team、Provisioning、Entitlements 和 codesign 校验

ios-runtime/
  Package.swift
  Sources/ShellsmithRuntime/ # 对上游 RASP 的最薄封装和统一回调
  Plugins/ShellsmithPlugin/  # 生成配置、接线检查；不实现二进制重写
```

`shield-ios` 保持独立，不在第一版把 Android 代码重构成抽象平台框架。CLI/Tauri 只共享已有任务生命周期、日志、取消和进度机制，避免为了统一名称改动稳定的 Android 核心。

### 流水线

```text
Xcode 源码工程
  -> 预检 macOS/Xcode/scheme/target/Bundle ID/Team/部署版本
  -> 创建受控工作副本并生成 shellsmith-ios.toml
  -> 锁定并解析 Swift Package 依赖
  -> 生成 Swift Confidential 选择性保护配置
  -> 生成 ShellsmithRuntime/freeRASP 启动与响应配置
  -> xcodebuild -resolvePackageDependencies
  -> xcodebuild archive
  -> xcodebuild -exportArchive
  -> codesign/Entitlements/Provisioning/Mach-O/依赖/敏感字符串检查
  -> 输出 xcarchive、ipa、机器可读报告和人类可读报告
```

默认输出目录必须与源码目录分离。每次任务生成变更清单和工作目录；取消或失败后可以直接删除工作目录，用户原工程不需要回滚。若后续提供 `--apply` 原地接入模式，必须先展示补丁并由用户显式选择。

## 四、配置合同

第一版使用仓库根目录可审查的 `shellsmith-ios.toml`，只保存工程事实和保护策略，不保存证书私钥、钥匙串密码或 Apple 账号令牌：

```toml
[project]
workspace = "App.xcworkspace"
scheme = "App"
configuration = "Release"
team_id = "ABCDE12345"
bundle_ids = ["com.example.app"]

[protection]
profile = "balanced"

[confidential]
enabled = true
config = "confidential.yml"

[rasp]
provider = "freerasp"
is_prod = true
watcher_mail = "security@example.com"
critical = ["signature", "jailbreak", "debugger", "runtimeManipulation"]
```

约束：

- 工程路径必须解析在用户选择的源码根目录内，拒绝路径穿越和符号链接逃逸。
- `team_id`、Bundle ID、scheme 和 target 必须与 Xcode 工程实际值相符，不能只信任配置文件。
- 签名身份、Provisioning Profile 和私钥留在 Xcode/Keychain；命令行仅传引用或 Apple 支持的导出选项。
- 上游包必须锁定精确版本和解析后的校验信息；Swift Confidential 主包与插件版本必须一致。
- freeRASP 为显式选择能力。未接受其条款、隐私披露和流量政策时，只能运行不含 freeRASP 的兼容档。

### 保护档位

| 档位 | 内容 | 适用场景 |
|---|---|---|
| `compat` | Release 构建、符号/签名/Entitlements 检查，不接入第三方 RASP | 首次迁移、兼容性优先 |
| `balanced` | 选择性 Swift Confidential + freeRASP + 分级响应 | 第一版推荐默认值 |
| `strict` | balanced + App Attest 接口合同 + 更严格的敏感功能限制 | 已有服务端验证端点的应用 |

`strict` 只有在 App Attest 服务端完成挑战、验证和重放防护后才能标记为第四代；单独生成客户端调用不能计入完成。

## 五、威胁响应策略

freeRASP 事件统一转换为 Shellsmith 内部枚举，业务层决定响应。第一版不使用单一“发现即退出”策略：

| 等级 | 典型信号 | 默认响应 |
|---|---|---|
| 观察 | VPN、截图、录屏、模拟器或低置信环境变化 | 本地记录、提示或由业务决定，不阻断普通功能 |
| 限制 | 越狱、调试器、运行时 Hook、签名异常 | 禁用密钥导出、支付、管理等敏感功能，并使会话失效 |
| 终止 | 生产环境确认的签名篡改或策略配置的复合高危信号 | 清理短期敏感状态后终止当前敏感流程；是否退出应用由使用方显式配置 |

开发与测试构建必须关闭生产阻断，保证 Xcode 调试和模拟器测试可用。报告中区分“观察到信号”“已执行响应”和“无法判断”，避免把单一环境信号误报为攻击。

## 六、分阶段实施

### 阶段零：冻结合同和上游版本

- [ ] 新建 `docs/design/ios-hardening.md`，记录威胁模型、代际定义、Apple 限制和支持矩阵。
- [ ] 读取并记录 Swift Confidential 与 freeRASP 的准确版本、最低 Xcode/Swift/iOS 要求、许可证全文和发布校验值。
- [ ] 确认 freeRASP 免费额度、公平使用政策、遥测字段、数据区域、停用方式和二进制再分发条款。
- [ ] 决定依赖从客户工程直接解析上游，Shellsmith 不托管 freeRASP 二进制。
- [ ] 冻结 `shellsmith-ios.toml`、保护档位、事件枚举和报告 JSON schema。
- [ ] 为 CLI/Tauri 定义同一 `IosProtectRequest`、`IosProtectProgress`、`IosProtectReport`；不让前端拼接 shell 命令。

**阶段出口：** 版本、许可、隐私和配置合同均可审查；任何未确认的许可问题以“阻断发布”记录，不能用技术实现绕过。

### 阶段一：工程检查与只读审计

- [ ] 新建 workspace crate `crates/shield-ios`，只实现检查，不修改用户工程。
- [ ] 使用 `xcodebuild -list -json`、`-showBuildSettings` 和工程文件解析现有 scheme、target、Bundle ID、Team、部署版本及扩展目标。
- [ ] 检查 macOS、Xcode、Swift、命令行工具选择和许可证状态；错误信息包含事实与修复建议。
- [ ] 对 `.ipa`/`.xcarchive` 实现只读审计：签名链、Entitlements、Provisioning、Mach-O 架构、加密标记、动态库和隐私清单。
- [ ] 增加 `shield check-ios --workspace ... --scheme ...`，输出 JSON 与终端摘要。
- [ ] 非 macOS 返回“可编辑配置/不可构建”的明确能力结果，不伪装成构建失败。

**阶段出口：** 对一个 SwiftUI 样例、一个 UIKit 样例和一个含 Extension 的样例生成稳定报告；重复执行不修改源码，报告不包含私钥、口令或账号令牌。

### 阶段二：Swift Confidential 集成

- [ ] `ios-runtime/Package.swift` 锁定 Swift Confidential 及其插件的同一精确版本。
- [ ] 生成 `confidential.yml` 模板，允许为每个 target 选择算法、压缩方式和待保护字符串。
- [ ] 扫描源码只生成候选列表，不自动改写；排除本地化键、资源名、selector、反射名、URL scheme、Bundle ID 和公开协议常量。
- [ ] 支持宏标记和配置文件两种上游正式用法，优先使用上游接口，不复制其密码实现。
- [ ] 构建后以受限 `strings`/符号检查验证被选字面量未直接出现，同时验证运行时功能结果一致。
- [ ] 报告明确注明密钥和解密逻辑仍在客户端，保护目标是提高静态分析成本。

**阶段出口：** 样例工程中选定的测试密钥字面量不再以明文出现；未选字符串、本地化、深链和反射调用保持正常；清理构建后能够从锁文件复现依赖。

### 阶段三：freeRASP iOS 集成

- [ ] 通过上游 Swift Package 直接解析 `TalsecRuntime.xcframework`，Shellsmith 只生成配置与最薄封装。
- [ ] 实现 `ShellsmithRuntime.start()`，从已校验配置构建 `TalsecConfig` 并调用上游启动接口。
- [ ] 提供 SwiftUI `App.init` 和 UIKit `application(_:didFinishLaunchingWithOptions:)` 两种显式接入片段，不使用生命周期方法交换。
- [ ] 把上游回调映射到稳定事件：signature、jailbreak、debugger、runtimeManipulation、passcode、simulator、secureEnclave、VPN、deviceChange、unofficialStore、screenshot、screenRecording、timeSpoofing。
- [ ] 实现观察、限制、终止三级策略；默认 `balanced` 只对高置信生产信号限制敏感功能。
- [ ] 检查 freeRASP 隐私清单、遥测说明、watcher 邮箱和用户披露是否满足发布要求。

**阶段出口：** 真机 Release 正常启动；Debug/Simulator 不被生产策略误杀；可控调试、截图录屏和签名异常测试能产生期望事件与响应。

### 阶段四：Archive、导出和验证

- [ ] 在独立工作目录生成集成结果，记录新增文件、工程变更和依赖锁定信息。
- [ ] 顺序执行依赖解析、`xcodebuild archive` 和 `xcodebuild -exportArchive`；命令参数以参数数组传递，拒绝 shell 拼接。
- [ ] 支持 Xcode 自动签名和用户提供的 `ExportOptions.plist`；日志中遮盖路径中的账号信息和敏感参数。
- [ ] 对 `.xcarchive` 与 `.ipa` 执行 `codesign --verify --deep --strict`，并比对 Team ID、Bundle ID、Entitlements、Provisioning 和嵌入框架签名。
- [ ] 检查每个 target 的 arm64 架构、最低系统版本、Swift runtime、第三方 framework 和 privacy manifest。
- [ ] 生成 `shellsmith-report.json` 与摘要，记录工具版本、上游版本、输入事实、保护档位、各阶段结果和未覆盖风险。
- [ ] 失败时保留可诊断报告，删除临时证书导出物；绝不删除用户 Keychain 项。

**阶段出口：** 在干净 macOS 构建机上从锁定源码生成可安装 `.ipa`；签名严格验证通过；关闭任一保护模块时产物和报告准确反映实际状态。

### 阶段五：CLI 与 GUI 融合

- [ ] 保留现有 `shield protect` Android 行为，新增 `shield protect-ios --workspace ... --scheme ... --configuration Release --team-id ... --profile balanced`。
- [ ] CLI 增加 `--output`、`--report-json` 和 `--dry-run`；默认不原地修改源码。
- [ ] GUI 加固页增加平台选择：Android APK/AAB、iOS Xcode 工程；沿用现有任务队列、取消、进度和诊断组件。
- [ ] iOS 表单只展示工程/工作区、scheme、configuration、Team、签名方式、保护档位和输出位置。
- [ ] 高级项折叠展示敏感字符串配置、RASP 响应和导出选项，避免把实现术语放进主流程。
- [ ] Windows/Linux 隐藏构建动作并显示可执行的下一步；macOS 缺少 Xcode 时在任务开始前阻断。
- [ ] 中英文界面、文档和报告统一使用 Shellsmith；现有 Android 内部兼容标识不批量替换。

**阶段出口：** CLI 和 GUI 调用同一个 Rust 接口；取消任务能终止子进程并清理工作目录；旧 Android 加固和签名路径无行为变化。

### 阶段六：完整验收与发布

- [ ] Android 现有 APK/AAB、CLI、GUI 和运行时回归全部通过，确认新增 iOS crate 没有改变旧默认值。
- [ ] iOS 覆盖 SwiftUI、UIKit、混合 Objective-C、Extension、多 scheme、自动签名和手动导出配置。
- [ ] 真机验证启动、前后台、深链、推送、Keychain、网络、截图录屏和敏感功能限制。
- [ ] 在受控设备验证调试器、越狱/Hook 和重签名样本；无法稳定复现的项目记录为人工或实验室测试。
- [ ] 记录 Archive 时间、应用启动时间、包体积和运行内存的基线与增量，超出预算时定位到具体模块。
- [ ] 执行 App Store 上传/验证检查，确认没有私有 API、错误签名、缺少 privacy manifest 或动态代码问题。
- [ ] 生成第三方 NOTICE、SBOM、版本锁定和隐私说明；法律/产品负责人确认 freeRASP 商用与遥测条件后才能公开发布该档位。
- [ ] 发布说明准确标注“敏感字符串保护 + 运行时检测”，不把其描述为完整代码虚拟化或绝对防破解。

**阶段出口：** 双平台支持矩阵、真实设备结果、签名结果、许可证材料和回滚方案齐全；Beta 包通过人工安装和核心业务验收。

### 阶段七：第四代能力（后续）

- [ ] 定义 App Attest 注册、挑战、证明、断言、重放防护和设备迁移协议。
- [ ] 服务端只在证明与业务风险策略通过后返回短期敏感配置或密钥材料。
- [ ] 将 RASP 信号作为风险输入之一，不由客户端单方面决定账号封禁。
- [ ] 为断网、Apple 服务不可用、旧系统和迁移设备定义降级策略与恢复窗口。
- [ ] 独立评估 LLVM/Mach-O 商业保护提供商，通过 provider 接口接入，避免污染基础流水线。

**阶段出口：** 客户端与服务端联合验收通过后，Shellsmith 才能把对应配置标记为第四代；未配置服务端的用户继续使用第三代能力。

## 七、验收矩阵

| 平台/输入 | 检查 | 加固构建 | 签名导出 | 备注 |
|---|---:|---:|---:|---|
| Android APK/AAB | 是 | 保持现有能力 | 保持现有能力 | 本计划不改变旧行为 |
| macOS + Xcode 源码工程 | 是 | 是 | 是 | iOS 第一版主路径 |
| Windows/Linux + Xcode 工程 | 是（有限） | 否 | 否 | 生成配置与静态报告 |
| IPA/XCArchive | 是 | 否 | 仅验证 | 不承诺通用注入与重签 |
| SwiftUI/UIKit | 是 | 是 | 是 | 第一版一等支持 |
| Objective-C | 是 | RASP 可用 | 是 | Swift 字符串保护不适用 |
| Extension/Widget/App Clip | 是 | 按 target | 按 target | 分别校验标识和签名 |

## 八、完成定义

- [ ] Android 原命令、GUI 默认流程、内部标识和既有数据目录保持兼容。
- [ ] iOS 在干净的受支持 macOS 环境可以从源码生成 `.xcarchive`、`.ipa` 和两种报告。
- [ ] 上游依赖使用精确版本，Swift Confidential 主包与插件一致，锁文件可复现。
- [ ] 选中的测试敏感字符串不以明文出现在最终 Mach-O；运行时读取结果正确。
- [ ] freeRASP 已链接并启动，事件映射和分级响应在 Release 真机得到验证。
- [ ] `codesign --verify --deep --strict`、Entitlements、Provisioning、Bundle ID、Team ID 和所有嵌入 framework 检查通过。
- [ ] 不支持的输入、平台或功能返回明确诊断，不生成看似成功的产物。
- [ ] 报告、日志和配置不包含私钥、口令、Apple 令牌或未遮盖的敏感数据。
- [ ] NOTICE、SBOM、隐私披露、遥测说明和 freeRASP 使用条件完成审查。
- [ ] 文档不作超过实际能力的安全承诺，用户可以单独关闭 Swift Confidential 或 freeRASP。

## 九、风险与回滚

| 风险 | 处理 |
|---|---|
| Swift 宏/插件或字符串变换造成编译、反射、本地化问题 | 仅处理明确选择项；候选扫描默认只报告；按 target 回归 |
| RASP 误报导致正常用户受限 | 分级策略、开发环境例外、远程可调业务响应；单一信号不默认封禁账号 |
| freeRASP 条款、额度或遥测不满足产品要求 | 功能保持可选；依赖由客户工程直连上游；发布前许可证与隐私门禁 |
| Xcode/SPM 上游变化导致不可复现 | 精确版本、锁文件、工具链版本和解析校验写入报告 |
| 签名配置泄露或被误改 | 使用 Keychain/Xcode 原生能力；配置不存私钥；原工程默认只读 |
| Apple 审核拒绝 | 不引入动态下载执行、自修改代码或私有 API；在发布前执行官方验证 |
| iOS 新能力影响 Android | 独立 crate、独立命令和 feature gate；Android 回归作为发布阻断项 |

回滚按模块执行：关闭 iOS feature gate 或移除对应命令即可恢复只含 Android 的发布；对单个客户工程，删除 Shellsmith 输出工作目录并使用原源码构建。上游 RASP 出现条款或稳定性问题时，`compat` 档继续提供签名和构建检查，不能用静默替换的二进制继续发布。

## 十、实施依据

- [Swift Confidential 仓库](https://github.com/securevale/swift-confidential)：构建期 Swift 字符串保护、Package/插件和许可证来源。
- [freeRASP iOS 仓库](https://github.com/talsec/Free-RASP-iOS)：iOS RASP 包、示例、版本和仓库许可证来源。
- [Talsec freeRASP iOS 文档](https://docs.talsec.app/freerasp/integration/ios)：配置、威胁回调、遥测与运行要求来源。
- [Apple Code Signing 指南](https://developer.apple.com/support/code-signing/)：iOS 代码签名和分发约束。
- [App Store Review Guidelines 2.5](https://developer.apple.com/app-store/review/guidelines/#software-requirements)：动态代码与软件要求边界。
- [Apple App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)：第四代服务端证明的官方基础。
- [OWASP MASTG iOS 混淆测试](https://mas.owasp.org/MASTG/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0213/)：混淆、韧性和验证范围参考。

## 自审结论

计划将 Swift Confidential 定位为局部第二代静态保护，将 freeRASP 定位为第三代运行时保护，组合后仍不虚报为完整第四代。第一版使用源码工程和 Apple 原生构建签名链，避开任意 IPA 注入及动态代码路线；Android 保持现有实现，iOS 通过独立 crate 和运行时包接入。实施顺序先解决许可证、隐私、配置和只读审计，再做工程改写与发布，任何一个阶段都能以兼容档或关闭 iOS feature gate 回滚。
