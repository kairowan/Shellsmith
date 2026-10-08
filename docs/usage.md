# Shellsmith — 使用指南

## GUI 用法（推荐）

从 [Releases](https://github.com/kairowan/Shellsmith/releases/latest) 下载对应平台的安装包，安装后直接使用。

> **macOS 首次打开（未签名版本）**
>
> macOS 会提示「无法验证开发者」，在终端执行以下命令去除隔离标记，执行后正常双击打开即可，只需操作一次：
> ```bash
> xattr -rd com.apple.quarantine /Applications/Shellsmith.app
> ```

正式 GUI 为 Tauri 版，Linux / macOS / Windows 使用同一套界面。当前界面以加固、签名、证书、设置、关于为主，签名证书已从设置页拆出，由证书页统一管理。

- **加固**：在 Android/iOS 间切换；Android 选择 APK，iOS 选择 Xcode 工程并在工作副本中接入保护
- **签名**：拖入或选择 APK → 选择证书 → 点击签名；签名成功后只保留“继续签名”入口
- **证书**：导入已有 keystore / p12，或创建新的 PKCS12 证书；可设置默认证书
- **设置**：配置主题、语言与应用级选项
- **关于**：显示版本号与构建信息、检查更新，并支持手动重新检测环境和复制诊断信息

### 应用内更新

从 v1.4.5 开始，启动时或在「关于 → 检查更新」读取 GitHub 最新稳定版清单，不再使用一天的版本缓存。发现更新后点击顶部「查看更新」，阅读说明并选择「下载并安装，完成后重启」。仅创建 tag 不会触发客户端更新：Release 工作流必须成功公开安装包、签名与 `latest.json`。预发布版不会进入稳定更新通道。

- macOS 支持 Intel 与 Apple Silicon；请先将 `.app` 从 DMG 移入「应用程序」后运行。
- Windows x64 使用带进度的 NSIS 安装器，系统需要时可能请求授权。
- Linux x64 AppImage 支持覆盖更新；deb 仍需到 Release 页面下载并通过系统安装。
- 加固或签名尚未结束时不能更新，更新期间不能新建加固/签名任务或普通退出。强制结束进程、断电与磁盘故障不在此保护范围内。
- 安装前校验更新包签名及签名绑定版本；下载或验签失败不会进入安装。本地 `config.toml`、`shield.db`、`keystores/` 不随更新清除。未保存的表单请先保存。
- v1.4.4 及更早版本需手动安装一次 v1.4.5，之后才能使用覆盖更新；开发模式只检查版本。

### 适用场景

- **优先使用 GUI**：日常加固、重新签名、管理签名证书
- **使用 CLI**：批处理脚本、CI 流水线、本地调试加固过程

### 首次使用建议流程

1. 先在 **证书** 页面导入已有 keystore / p12，或创建新的 PKCS12 证书
2. 将常用证书设为默认
3. 返回 **加固** 页面选择已签名 APK
4. 需要直接得到可安装产物时，使用默认启用自动签名的证书
5. 只做重签名时，使用 **签名** 页面并选择证书

当前版本签名资料由证书页统一维护：

- 导入证书保存前会校验 keystore 密码、alias 与证书可用性
- 创建证书默认生成 PKCS12 keystore，并保存到应用数据目录 `keystores/`
- 创建证书时 Keystore 密码至少 6 位；Key 密码可留空，填写时同样至少 6 位
- PKCS12 证书的 Alias 可能会被 `keytool` 规范为小写；GUI 会按大小写不敏感方式校验，并保存 keystore 中实际返回的 Alias
- 已保存证书的材料不可直接编辑；编辑入口只用于修改名称、备注、签名版本和自动签名偏好
- 如需更换 keystore 文件、Alias、类型或密码，请重新导入或创建一条证书记录
- 启用自动签名时，加固页会先校验原 APK 与当前所选证书指纹，一致时才执行
- 签名页不会维护临时签名配置，只从证书列表中选择
- 自动签名产物默认建议名为 `{name}_protected_signed.apk`，开始前可修改
- GUI 内部会在输出前自动完成 APK ZIP 对齐，无需手动运行 `zipalign`

### 加固设置与输出记忆

常用加固选项保存到 `config.toml` 的 `protect_defaults`：运行系统兼容性、运行环境保护、加固页证书选择与自动签名偏好、输出目录模式及固定目录。重新启动后沿用已保存值；加固页所选证书与证书管理中的默认证书不是同一个概念。

输出目录可选择原 APK 同目录或固定目录；文件名根据当前输入和签名选择生成建议值，也可在执行前修改，不把上一个 APK 的文件名作为通用默认。任务开始后使用固定快照，运行中及结果页不能修改本次配置。旧 ABI 排除确认仍只对当前任务有效，不持久化。

### 应用使用情况分享

Beta.6 起，加固和签名页分别提供“分享加固使用情况”“分享签名使用情况”单行选择。新应用默认选中；取消只针对当前包名，两页共用并长期记住选择，同包名升级或更换 APK 路径不会重置。

成功操作可发送应用包名、名称、版本码、工具版本、操作类型、流程和成功日期，以及协议版本、说明版本和去重提交编号；不上传 APK、路径、证书、密码或原始日志，不关联匿名安装标识。仅维护者可查询，明细保留 180 天。取消停止同包名后续分享，不自动删除以前已收到的数据。关闭设置中的匿名统计不等于关闭这项分享。

分享识别和网络失败不会阻止本地加固或签名；加固后的 APK 不包含本功能的运行时上报。详细说明见[数据通道与边界](ops/telemetry.md)。

### 标准模式下的旧架构库

如果 APK 同时包含受支持架构与旧 SDK 附带的 `armeabi`、`mips`、`mips64` 等不支持架构，开始加固时会列出排除与保留清单。选择“排除这些架构并继续”后，仅从输出 APK 移除对应架构目录，原 APK 不变。此确认不保存，每个新任务重新确认；只有不支持架构的 APK 仍会被阻止。保留架构的业务库需完整，完成后请验证启动及相关 SDK 功能。

CLI 默认拒绝这类混合 APK，需要显式传入本次排除清单，例如：

```bash
shield protect -i input.apk -o output.apk --exclude-abis armeabi,mips,mips64
```

清单必须与原 APK 中实际需要排除的架构匹配，不允许排除本工具支持的架构。Android 4.4 工控模式继续执行原有 ABI 限制。

### 签名材料准备

建议提前准备以下材料：

- 已签名的原始 APK
- `keystore` / `p12`
- `alias`
- `keystore` 密码
- `key` 密码（相同可留空）

启用自动签名时，GUI 会在预检时比对原 APK 与当前所选证书的指纹，并在后端开始加固前再次校验。指纹不一致或证书读取失败都会阻止加固，因为改用其他证书签名会导致运行时无法解密和启动。

加固页提供“运行系统兼容性”选项。默认使用“Android 5.0 及以上”标准模式；目标设备包含 Android 4.4 工控板时，可选择“兼容 Android 4.4”。标准模式已覆盖 Android 5.0～6.0 的旧版 ART 注入路径，并包含 ARouter 运行期扫描和 Android 9 `org.apache.http.legacy` 兼容处理。兼容模式当前仅接受不含 Native 库，或 Native 库仅包含 `armeabi-v7a` 的 APK；后端会再次检查 ABI，并从应用内置的固定兼容资源包加固，前端不能传入任意资源路径。GUI 会将该选择保存为常用设置，每个任务开始时冻结，旧版请求未携带此字段时仍按标准模式执行。Android 4.4.2 `armeabi-v7a`/NEON 工控真机已确认能够正常运行；完整业务测试未全部覆盖，其他 CPU、厂商系统和硬件交互仍需按实际设备验证。

加固页同时提供“运行环境保护”选项：

| 模式 | 默认值 | 行为 | 适用建议 |
|------|--------|------|----------|
| 标准保护（推荐） | 初始默认 | 始终保留反调试检查；Root 信号不阻止应用启动 | 普通应用、模拟器、工控设备以及无法确认设备环境时使用 |
| 严格保护 | 否 | 反调试或高置信 Root、ADB Root、注入信号命中时拒绝启动 | 仅用于明确不允许 Root 环境运行的受控部署场景 |

运行环境策略写入 `config.toml` 的常用加固设置，每个任务仍使用开始时固定的快照。任务开始后不能修改；如需切换策略，必须重新选择并加固 APK，运行时不会从严格模式静默降级。严格策略只能提高常见提取和分析成本，不能承诺抵御隐藏 Root、检测绕过、内核级控制或进程内提取。若目标设备出现误判，请改用标准保护重新加固，并提供设备系统及 Root 方案信息协助排查。

GUI 会在应用启动时检测一次本机 Java 环境，并将结果缓存到全局状态中；若未检测到完整 JDK 8+，或缺少 `keytool`，加固、签名、Alias 识别会直接阻断并给出明确提示。运行流程不依赖 `javac`。
如果应用启动后你又安装或切换了 JDK，可在关于页手动点击“重新检测环境”刷新状态。

### iOS 源码工程加固

iOS 完整构建要求 macOS、完整 Xcode、可用的 Apple Team 和 Provisioning Profile。Shellsmith 会自动发现常见位置的完整 Xcode，即使系统 `xcode-select` 暂时仍指向 Command Line Tools，也会对本次任务使用发现到的 Xcode；Windows/Linux 可以查看静态检查结果，但不能 Archive 或导出 IPA。

1. 在 **加固** 页面切换到 **iOS**，选择 `.xcodeproj` 或 `.xcworkspace`。
2. 填写 scheme、Release configuration、10 位 Team ID 和允许的 Bundle ID；多 Bundle ID 用逗号或空格分隔。
3. 点击“检查工程”。存在非应用 target、共享 scheme 缺失、完整 Xcode 缺失或上游已知错误接法时，构建按钮保持禁用。
4. `confidential.yml` 和 freeRASP `watcherMail` 都是可选项。提供 `confidential.yml` 时，只保护明确列入配置的 Swift 字面量；未提供时仍启用 freeRASP，只跳过项目自定义敏感字面量保护。本地化键、selector、反射名称和资源名不要加入。
5. `strict` 的 App Attest 服务端地址可选。不填写时仍执行严格客户端加固；填写后，客户端只生成调用接口，业务服务端仍须实现挑战、证明校验和重放防护。
6. 选择独立的空输出目录和导出方式。只有允许 Xcode 使用本机开发者账号更新描述文件时，才开启“允许更新 Provisioning”。
7. 完成后在输出目录检查工作副本、`.xcarchive`、IPA 和 `shellsmith-report.json`，再用目标设备验证启动、敏感流程和威胁响应。

标准纯 Objective-C UIKit 工程可通过 `AppDelegate.m` 中已有的 `application:didFinishLaunchingWithOptions:` 回调接入 balanced/strict 运行时保护；若发现多个启动回调，在“iOS 启动入口”中明确填写目标 `.m` 路径。Shellsmith 会在工作副本该回调的开头启动保护，保持 `main.m` 和原有回调逻辑不变。Swift Confidential 不处理 OC 字符串，纯 OC 工程请勿提供 `confidential.yml`；无该回调的自定义启动方式暂不支持自动注入。

Shellsmith 不修改原工程，也不保存 Apple 账号令牌、钥匙串密码或私钥。生成的本地 Swift Package 锁定 Swift Confidential 0.5.2 和 freeRASP iOS 7.1.4，并直接链接到应用 target，避免 XCFramework 重复产物与二级 framework 嵌套问题。

三个档位的边界：

| 档位 | 行为 |
|---|---|
| `compat` | Apple 原生 Release/Archive、签名和产物检查，不接入第三方 RASP |
| `balanced` | freeRASP 分级事件；提供 `confidential.yml` 时再启用选择性 Swift Confidential，推荐默认值 |
| `strict` | balanced + App Attest 客户端接口；服务端地址可选，未配置时明确标记为没有服务端证明闭环 |

freeRASP 的越狱、Hook、签名异常等结果是风险信号。生成的封装会发出稳定回调与通知，不会擅自退出应用或封禁账号。Dopamine 2 RootHide 漏检属于上游闭源实现的残余风险，strict 应结合 App Attest 和服务端业务风控。完整说明见 [iOS 加固实现](design/ios-hardening.md)。

### 配置与证书数据位置

GUI 启动时会一次性加载应用配置与证书数据库，运行期间使用同一份内存状态，不会在页面切换时反复从磁盘读取。应用级配置写入 `config.toml`；证书列表、默认证书、签名密码与校验状态写入本地 SQLite 数据库 `shield.db`。密码字段以 `enc:v1` 格式加密落盘；旧明文记录不再兼容，如遇到旧测试数据请重新导入或创建证书。

证书记录和托管 keystore 属于当前 macOS/Linux/Windows 用户的本地应用数据，不会打进项目、APK 或 Shellsmith 安装包，也不会上传到 CI。升级或重新下载并安装 Shellsmith 时，系统通常会保留原应用数据目录，因此旧证书仍会显示。要删除单条记录，请在 **证书** 页面使用删除按钮；若要彻底清空本机资料，请退出 Shellsmith 后备份并删除下表中的应用数据目录，再重新启动应用。不要直接删除仍在使用的生产 keystore。

| 平台 | 应用配置 | 证书数据库 |
|------|----------|------------|
| Linux | `~/.config/dev.mocika.shield-gui/config.toml` | `~/.local/share/dev.mocika.shield-gui/shield.db` |
| macOS | `~/Library/Application Support/dev.mocika.shield-gui/config.toml` | `~/Library/Application Support/dev.mocika.shield-gui/shield.db` |
| Windows | `%APPDATA%\\dev.mocika.shield-gui\\config.toml` | `%APPDATA%\\dev.mocika.shield-gui\\shield.db` |

应用数据目录还会新增：

- `shield.db`：证书列表、默认证书、签名密码、校验状态
- `keystores/`：应用内新建或托管的 keystore 文件

---

## CLI 用法

### iOS

先复制并修改 [`examples/shellsmith-ios.toml`](../examples/shellsmith-ios.toml)。需要保护项目自定义敏感字面量时，再按需创建 [`examples/confidential.yml`](../examples/confidential.yml) 的副本：

```bash
# 只读检查，输出 JSON；不要求修改工程
shield check-ios /path/App.xcworkspace --scheme App

# 验证配置和已知问题处理，不执行 Archive
shield protect-ios \
  --ios-config shellsmith-ios.toml \
  --output /path/to/empty-output \
  --dry-run --json

# 在完整 Xcode 的 macOS 上构建、签名、导出和验证
shield protect-ios \
  --ios-config shellsmith-ios.toml \
  --output /path/to/empty-output \
  --export-method development
```

自动化可以传入预先审查的 `--export-options ExportOptions.plist`。命令使用参数数组调用 `xcodebuild`，不会拼接 shell 命令。输出目录不得位于源码目录内，且必须不存在或为空。

### 基础用法

```bash
shield protect -i input.apk -o protected.apk
```

保护级别和 AI 静态语义恢复抵抗强度可以独立选择：

```bash
shield protect -i input.apk -o protected.apk \
  --profile balanced \
  --ai-resistance balanced
```

- `compat`：优先兼容 API 19–36，关闭高风险高级变换。
- `balanced`：默认策略。未提供 Xop 参数时显示 `xop-contract-only`；显式启用嵌入式 PVM2 时显示 `xop-pvm2-embedded`。
- `strict`：要求真实嵌入式 Xop PVM2。GUI 默认使用安装包内置的 Packer，只需提供至少一个自有业务类前缀；CLI 仍需显式传入 Packer 路径。严格模式同时启用资源路径缩短、同类型资源 ID 重排、PAS2 分块认证加密和符合安全策略的业务 ELF 函数区域选择性加密。资源 ID 若出现在 Native/opaque 数据或 packed-switch 中会自动固定；PAS2 会改写可识别的 `AssetManager.open/openFd/getAssets`，以 DEX/ELF 中的路径或目录常量覆盖常见动态拼接，并通过应用私有 overlay 支持常见 Native `AAssetManager` 读取。缺少必要条件会在变换前失败关闭。该状态为 `xop-pvm2-embedded`，不代表 Hollow、LLVM Native VMP 或完整 Xop RASP 已融合。
- `ai-resistance` 支持 `off`、`balanced`、`high`，映射为 DEXB v6 的 1/2/3 层 Zstandard 认证载荷。它与可选的 PVM2 方法虚拟化是两层能力：前者提高载荷静态恢复成本，后者让选定方法由 Native 解释器执行。两者都不能替代服务端授权和密钥保护。

将 Xop PVM2 嵌入 Shellsmith 单 Stub（不引入第二个 Application/JNI 壳）：

```bash
shield protect -i input.apk -o protected.apk \
  --profile balanced --ai-resistance high \
  --xop-pvm2-packer /path/to/protector-packer.jar \
  --xop-true-vmp-prefix 'Lcom/example/payment/'
```

可重复传入 `--xop-true-vmp-prefix`。前缀必须指向自有业务类，建议先从少量纯业务方法开始，避免把 Activity、Application、框架回调和大型 SDK 全包虚拟化。所选 Runtime 必须声明 `xop_pvm2=true`；API19 资源不支持此能力并会在变换前拒绝。

GUI 安装包已经内置 Xop PVM2 Packer：Packer 路径留空即使用内置版本，无需额外选择文件；“选择自定义 Packer JAR”会覆盖内置版本，“恢复使用内置 Packer”可随时切回。自定义 JAR 会以当前用户权限在本机执行，因此必须来自可信来源，并兼容 `pvm2-transform` 与 code.bin v6 契约；输出仍会由核心验证。业务类前缀仍需在“调整设置 → Xop PVM2 方法虚拟化”中用逗号填写。严格模式要求 PVM2 成功覆盖率至少达到 70%，并输出选中、尝试、成功、跳过原因及未覆盖指令统计；低于门槛会失败关闭。严格代码保护只有在标准运行时、Java 17+、可用 Packer 和有效前缀都就绪时才允许开始；路径和业务类名不会出现在脱敏诊断摘要中，摘要只记录 PVM2 是否已配置。

PVM2 v6 已支持普通/复杂条件分支、`switch`、异常表与 `throw`、对象/原始数组、标准反射调用所需的 invoke 路径，以及 `monitor-enter/exit` 同步语义。每次构建会改变虚拟 Opcode、虚拟寄存器映射、立即数编码、Handler 顺序，并从三套 Dispatcher 模板中选择一套；覆盖报告中的 `isa` 可用于确认变体。仍不满足契约的方法（例如个别 `invoke-custom`/`invoke-polymorphic`、超出寄存器或代码预算的方法）必须记入跳过原因，不能当作成功。

为保证音频/视频拖动和解码器状态，内置 Packer 会把播放器、解码器、音频/波形类及其 Kotlin/R8 合成访问器整体留在 ART；RecyclerView 适配器、Widget/View/Binding、资源/文件 Helper（兼容历史包名中的 `hepler`）也留在 ART，避免空接收者、回调和资源 ID 语义被 PVM2 改写。报告会以 `compatibility` 记录这些跳过项。资源 PAS2 同样默认跳过常见音视频扩展名，避免把需要随机访问的媒体流包装成只读顺序流。

这些是按 DEX 描述符、方法指令和 Android 生命周期边界计算的通用规则，不依赖某个业务包名或某个应用的类名。PVM2 对对象接收者执行路径敏感的控制流保护：`if-eqz`/`if-nez` 已证明非空的路径可以继续虚拟化，多个路径合流时只保留所有路径都能证明的非空事实；直线调用仍保持 ART 与 PVM2 相同的空接收者异常语义。跨分支或异常边界、又无法证明非空的接收者记为 `nullable_receiver` 并保留 ART，本地创建且可证明非空的对象仍可继续虚拟化。静态调用不会被误当作需要接收者证明的实例调用。工具对无法证明语义等价的方法失败关闭并保留 ART；这能显著降低兼容风险，但不能对任意第三方 APK、厂商 ROM 或未提供的业务 Native SDK 做绝对“零崩溃”保证，正式发布仍需用目标 APK 和设备矩阵回归。

业务 `.so` 的 APK 后处理层是“按库策略选择 + ELF 符号函数边界静态加密 + PSO2 认证密钥表 + 私有目录按函数区域解密加载”，能够提高直接静态反汇编成本。任一 ABI 缺少安全函数符号、含不安全重定位、超预算或属于系统/壳/高风险运行库时，整个同名库会跳过并计入报告，避免只加密部分 ABI。它仍是函数粒度的静态保护。

需要真实 Native VMP 时，使用 [`native-vmp`](../native-vmp/README.md) 接入业务 CMake/NDK 编译链：显式 `MOCIKA_VMP` 函数会在 LLVM bitcode 阶段变为自定义 VM 字节码，原函数体替换为解释器入口；不支持的已标注语义会编译失败。当前真实子集覆盖最多 64 位的整数参数/返回、算术/位运算、比较、分支、循环、PHI、`select` 和整数转换；指针/内存、浮点、外部调用、异常、原子与同步仍不在子集内。它不能对 APK 中已有的第三方 ELF 补做 VMP，但可以先对有源码的业务函数做 VMP，再由 strict PSO2 保护最终 `.so`。

GUI 的系统推荐默认值是“标准运行时 + 兼容环境保护 + balanced 代码保护 + balanced AI”，无需配置 PVM2 即可直接加固。高级设置会持久化；若上次保存了尚未配置完整的 strict 设置，主卡片会显示“使用推荐默认值（可直接加固）”，点击后恢复可用的推荐方案。该操作是显式切换，不会把 strict 静默降级。

“第几代”没有统一行业标准。按本项目内部能力分层，当前 strict 标准运行时仍标为 **3.5 代工程能力**：单 Stub、Java/Kotlin 方法级 PVM2、构建级多态、资源/asset、业务 ELF 函数区域保护，以及可选的源码级整数语义 Native VMP 已形成可运行链路；但 Native VMP 尚未覆盖通用 C/C++ 内存/调用/异常语义，Play 内测和 Android 5～16 全设备矩阵也尚未完成，因此不能宣传为完整第四代，不能把本地结构验证算成真实设备或 Play 证据。

AAB 预检不会把 APK 解包器误用于 AAB：

```bash
shield check-aab app.aab
```

输出中的 `module_processing=preflight-only` 表示尚未执行模块变换；正式 AAB 处理需在 AGP/bundletool 产物阶段完成并通过 split APK 真机验收。

如果本机已经准备好 bundletool 和签名测试证书，可以额外验证 AAB 并生成本地 APKS：

```bash
shield check-aab app.aab \
  --bundletool /path/to/bundletool.jar \
  --apks-output build/app.apks \
  --apks-mode universal \
  --ks test.jks --ks-alias test --ks-pass "$MOCIKA_SHIELD_KS_PASS"
```

这一步只验证 bundletool/APKS 转换，不执行加固。模块变换必须使用下方
`protect-aab`，并以其模块报告、Play 内测与设备回归为准。

有连接的测试设备时，可以继续验证 split APK 安装链路：

```bash
shield install-apks build/app.apks --bundletool /path/to/bundletool.jar
```

`install-apks` 只负责 bundletool 安装和设备选择，不会绕过签名、模块或运行时门禁。

`protect-aab --engine mocika` 可处理单 base、install-time/条件/on-demand dynamic-feature，以及 install-time/fast-follow/on-demand Asset Pack。动态功能 DEX 与 base 共用 PVM2 密钥和全局 DEX 编号；dynamic-feature 与 Asset Pack 的 `assets` 必须全部转为 PAS2 后才会写回模块；dynamic-feature 的独立 `lib/<abi>/*.so` 会与 base 共用 PSO2 变换和运行时密钥表。fast-follow/on-demand Asset Pack 必须显式声明 `--play-delivery-adapter`，否则失败关闭。Instant App、dynamic-feature 的 `root/` 文件和无法被 PAS2/PSO2 覆盖的模块仍拒绝生成半保护包：

```bash
MOCIKA_SHIELD_KS_PASS='upload-keystore密码' \
MOCIKA_SHIELD_KEY_PASS='upload-key密码' \
shield protect-aab \
  -i app.aab \
  -o app-protected.aab \
  --bundletool /path/to/bundletool-all.jar \
  --aapt2 "$ANDROID_HOME/build-tools/35.0.0/aapt2" \
  --runtime-cert-sha256 "$PLAY_APP_SIGNING_SHA256" \
  --ks upload.jks \
  --key-alias upload \
  --profile strict \
  --xop-pvm2-packer /path/to/protector-packer.jar \
  --xop-true-vmp-prefix 'Lcom/example/payment/' \
  --play-delivery-adapter \
  --apks-output build/app.apks
```

该命令会执行 AAB 校验、base APK 加固、模块级 PVM2/PAS2/PSO2 写回、protobuf base 重建、upload key 签名和最终 bundletool 校验。多模块保护要求 `--engine mocika --profile strict`、PVM2 Packer 和至少一个真实业务类前缀；任一代码、资源或 Native 模块未覆盖都会终止。`--runtime-cert-sha256` 是最终设备证书绑定，不是 upload key。若只是本地设备实验，可改用 `--allow-upload-cert-binding`，但该结果不能作为 Play 发布证据。最终仍必须在目标 Play 应用的内部测试轨道验证 Play 应用签名、服务端转换、下载/卸载/更新生命周期和真实 split APK。

延迟 Asset Pack 的业务侧使用稳定类 `dev.mocika.shield.loader.MocikaPlayDelivery`。`scripts/build-stub.sh` 会生成 `shield-stub/build/outputs/resources/mocika-play-delivery-api.jar`，业务工程只允许用 `compileOnly(files(".../mocika-play-delivery-api.jar"))` 引用；不要把这个 JAR 打进 APK，真实实现会由加固 Stub 注入。Pack 可用后用 `openAsset(context, packName, path)` 流式读取认证明文，或用 `materializeAsset(...)` 写入应用私有目录供需要 seek/文件路径的 Native SDK 使用。运行时会反射注册可选的 SplitInstall/AssetPack 完成监听；业务未使用 Play Core 或监听不可用时，在自己的安装 Task 成功回调里调用 `MocikaPlayDelivery.refresh(context)`。

多模块 AAB 必须让 Shellsmith 使用内嵌 PVM2，在上述命令追加：

```bash
--xop-pvm2-packer /path/to/protector-packer.jar \
--xop-true-vmp-prefix 'Lcom/example/payment/'
```

如果要让单 base AAB 走 Xop 的 PVM/Hollow/SO 单壳路径，可把 APK 变换引擎切换为
`xop`（仍然不能处理 dynamic-feature 或 Asset Pack）：

```bash
MOCIKA_SHIELD_KS_PASS='上传密钥库密码' \
MOCIKA_SHIELD_KEY_PASS='上传私钥密码' \
shield protect-aab \
  -i app.aab -o app-xop-protected.aab \
  --engine xop \
  --xop-packer /path/to/protector-packer.jar \
  --xop-shell-dir /path/to/exportShellFiles \
  --xop-profile industry \
  --ai-resistance high \
  --runtime-cert-sha256 "$PLAY_APP_SIGNING_SHA256" \
  --bundletool /path/to/bundletool-all.jar \
  --aapt2 "$ANDROID_HOME/build-tools/35.0.0/aapt2" \
  --ks upload.jks --key-alias upload
```

这里 Xop 是唯一的 APK 壳引擎，Shellsmith 不会再套一层；`--runtime-cert-sha256` 必须填写
最终 Play App Signing 证书，而不是 upload key。最终 AAB 仍由本地
bundletool 重建、upload key 签名并校验。该路径同样需要 Play 内部测试和目标设备回归，
且 Xop Packer 默认输出未签名的中间 APK，最终 AAB 签名由本命令完成。

若 `--runtime-cert-sha256` 与 upload key 指纹相同，可继续加上
`--apks-output build/app.apks --install-apks --device-id <serial> --smoke-package <applicationId>` 做本地安装和进程存活烟测；也可以配合 `--device-spec device-spec.json` 只生成目标设备的 split APKS；
若使用 Play App Signing 证书，则本地 APKS 只能做结构验证，不能冒充 Play 设备验证。

如果要同时使用尚未融入 Shellsmith Stub 的 Xop Hollow/Native SO/RASP，应选择 Xop 独立单壳入口，不要先执行 `shield protect` 再执行 Xop：

```bash
shield protect-xop \
  -i app.apk \
  -o app-xop.apk \
  --packer /path/to/protector-packer.jar \
  --shell-dir /path/to/exportShellFiles \
  --profile industry \
  --ai-resistance high \
  --ks release.jks \
  --key-alias release
```

`protect-xop` 默认要求 keystore、alias 和密码，先让 Xop 按最终证书绑定，再签出可安装 APK；密码建议通过 `MOCIKA_SHIELD_KS_PASS` / `MOCIKA_SHIELD_KEY_PASS` 传入。只有内部调试才使用 `--allow-unsigned`。它会拒绝已含 Shellsmith/Xop 载荷的 APK；该入口的生命周期和回退矩阵由 Xop 负责。只需 PVM2 且要求 Shellsmith 单 Stub 时，使用前文 `--xop-pvm2-packer` 路径。

运行 CLI 前请先确认本机已安装完整 JDK 8+，且 `java`、`keytool` 可执行。

详细日志输出：

```bash
shield protect -v -i input.apk -o protected.apk
```

签名命令会先执行内置 ZIP 对齐，再调用发布包中的 `apksigner.jar`：

```bash
MOCIKA_SHIELD_KS_PASS='keystore密码' \
MOCIKA_SHIELD_KEY_PASS='key密码' \
shield sign \
  -i protected.apk \
  -o protected-signed.apk \
  --ks release.jks \
  --key-alias release
```

未设置 `MOCIKA_SHIELD_KEY_PASS` 时，Key 密码默认沿用 Keystore 密码。也可以使用 `--ks-pass` 和 `--key-pass` 显式传入，但自动化环境优先使用环境变量，避免密码直接出现在命令历史中。

### CLI 配置文件

CLI 人工配置建议固定命名为 `shield-cli.toml`，与 GUI 自动维护的 `config.toml` 完全独立。当前格式版本为 `1`：

```toml
schema_version = 1

[protect]
input = "input.apk"
output = "build/protected.apk"
environment_policy = "compatible"
profile = "balanced"
ai_resistance = "balanced"

[sign]
input = "build/protected.apk"
output = "build/protected-signed.apk"
keystore = "release.jks"
key_alias = "release"
keystore_type = "jks"
v1 = true
v2 = true
v3 = true
v4 = false
```

配置中的相对路径以配置文件所在目录为基准。命令行参数优先于配置文件：

```bash
shield --config shield-cli.toml protect
MOCIKA_SHIELD_KS_PASS='keystore密码' shield --config shield-cli.toml sign
shield --config shield-cli.toml protect -i another.apk -o another-protected.apk
```

配置文件不接受密码字段，密码只能通过环境变量或当前命令参数提供；CLI 不会把密码写入进度、错误或调试输出。

### 机器可读输出与退出码

`protect`、`sign` 增加 `--json` 后，每行输出一个独立 JSON 事件，事件类型固定为 `progress`、`done` 或 `error`。原有 `--json-progress` 继续作为 `protect --json` 的兼容别名。

- 成功退出码为 `0`，并以 `done` 事件结束。
- 参数、配置、加固、对齐或签名失败的退出码为 `1`。
- JSON 模式下错误写入标准输出的 `error` 事件；普通模式错误写入标准错误。
- 调试日志不会混入 JSON 标准输出。

### 完整流程

加固完成后 APK 未签名，需手动签名后才能安装：

```bash
# 1. 加固
shield protect -i input.apk -o protected.apk

# 2. 签名（无需额外执行 zipalign）
MOCIKA_SHIELD_KS_PASS='keystore密码' \
shield sign -i protected.apk -o protected-signed.apk \
  --ks keystore.jks --key-alias alias

# 3. 安装
adb install -r protected-signed.apk
```

### 查看帮助 / 版本

```bash
shield --help
shield --version
```

---

## 验证加固结果

```bash
# 查看 DEX 与 Native 库条目；壳库可能使用任务生成的别名
unzip -l protected.apk | grep -E 'lib/|classes.*\.dex'
```

应看到：

- `lib/<abi>/*.so` — 输出所需 ABI 的业务库与壳库；壳库文件名不应假定固定为 `libmocikashield.so`
- `classes.dex` — 壳 DEX，末尾追加加密载荷；静态工具不展示载荷不代表载荷无法被发现或提取

条目存在只能验证结构，不能代替签名验证与设备安装、启动测试。

```bash
# 对比体积（off/balanced/high 的压缩层数会影响最终大小和首次加载成本）
ls -lh input.apk protected.apk
```

---

## 常见问题

### 找不到 apktool.jar / resources.zip

- **发布包**：jar 已内置，确保发布包目录结构完整（`lib/`、`resources/` 在 `bin/` 同级父目录下）
- **开发环境**：先执行 `make build-stub`，jar 在项目根 `tools/` 目录下

### 加固后 APK 崩溃

1. 查看日志：
   ```bash
   adb logcat | grep -E "AndroidRuntime|ax|dx|lx|rx|e[1-4]"
   ```

   当前壳层日志 tag 已做弱特征化处理，常见 tag 为 `ax`（StubApp）、`dx`（DEX 注入）、`lx`（Ld）、`rx`（ARouterCompat）。

2. 确认未用未签名 APK 加固（必须先签名再加固）：
   ```bash
   java -jar apksigner.jar verify input.apk
   ```

   `apksigner verify` 退出码为 `0` 表示 APK 已签名；V2/V3/V4 签名不一定会在 `META-INF/` 下留下证书文件。

3. 确认设备架构与注入的 so 匹配：
   ```bash
   unzip -l protected.apk | grep libmocikashield.so
   adb shell getprop ro.product.cpu.abi
   ```

4. 标准模式按 Android 5.0（API 21）及以上设计：API 21、23 已通过官方 ARM64 模拟器回归，Android 6.0 工控设备已验证首次安装、清除数据、覆盖安装、多 DEX、Native 库和主要业务功能；Android 4.4（API 19～20）须选择“Android 4.4 工控兼容”模式，当前已验证 Android 4.4.2 `armeabi-v7a`/NEON 工控设备

### 能否重复加固？

不可以。GUI 会在选择文件时提示，核心加固入口也会在解包和创建输出前再次检测，因此 GUI 和 CLI 都无法对已加固 APK 重复操作。请始终使用原始未加固的 APK。

### 为什么证书页保存后其他页面会立即生效？

GUI 只维护一份全局证书状态。证书页保存、删除或切换默认证书后，会同时更新内存状态和本地 `shield.db`，加固页、签名页会立即复用最新证书列表。

### 反馈问题时需要提供什么？

如果需要在 GitHub issue 中反馈加固、签名或环境检测问题，建议先在 **关于** 页面点击“复制诊断信息”，并将内容粘贴到 issue 中。诊断信息只包含版本、平台、Java 状态、工具状态和配置/数据目录可用性，不包含 APK 路径、证书路径、密码或完整用户目录。

### 加固后为什么体积反而变小？

DEX 文件经 Zstd 压缩后体积通常会明显减小；`high` 会再增加压缩层，实际体积和启动耗时应以目标 APK/设备实测为准。

---

## 性能参考

典型压缩率（Zstd level 19）：

| 文件 | 原始大小 | 压缩后 | 压缩率 |
|------|---------|--------|--------|
| classes.dex | 30 MB | 4.2 MB | 14% |
| classes2.dex | 12 MB | 3.7 MB | 30% |
| classes3.dex | 6.7 MB | 1.9 MB | 29% |

- 首次启动额外耗时：取决于 AI 抵抗等级（单层/双层/三层解压、JNI 解密和缓存策略），必须用目标设备实测
- Runtime 内存占用：约 1–2 MB

## 更多界面预览

以下截图使用当前 Shellsmith 界面，具体选项以当前版本为准。

![Shellsmith 当前加固页](assets/screenshots/readme-protect-main.png)
