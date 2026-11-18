# 显式业务资源保护的当前实现

本文涵盖 Android APK、AAB 各交付模块和 iOS 主应用的业务资源授权，以及 iOS App Extension 的加密副本读取。资源需要由应用使用相应的读取接口。新增资源能力需要与密钥服务端的同名迭代分支同步验收。[实施计划](android-ios-resource-protection-plan.md)

## Android 应用接入

在 Android 工程以 `compileOnly` 引用由 `scripts/build-stub.sh` 生成的 `mocika-play-delivery-api.jar`。在应用的 I/O 工作线程调用 `MocikaProtectedResources.open(context, "rules")`，按普通 `InputStream` 使用并关闭。应用需要在自己构建的原包中接好读取入口，确认必保资源的业务消费者均使用对应 ID。可选重载接受调试器拦截开关和应用侧事件回调。事件回调应快速返回并处理自身异常。

将业务文件放在 APK 的 `assets/` 下，并为 CLI、桌面加固或 MCP 准备同一份清单。所有条目按必保处理。资源及组 ID 接受 1 至 64 位小写 ASCII 字母、数字、下划线或连字符，`version` 取非零无符号 32 位整数。

```json
{
  "version": 1,
  "resources": [
    {"id": "rules", "source": "rules.json", "group": "policy", "version": 1, "read": "stream"}
  ]
}
```

CLI 入口为 `shield protect --protected-resource-manifest /本机路径/resources.json`，同时提供标准加固参数及 `--byos-auth device_approval` 和已有 BYOS 构建配置。MCP 的参数为 `protected_resource_manifest`。桌面在 Android 标准模式选择设备批准配置后显示资源清单。目标 APK 使用 API 24 及以上的设备批准壳，且服务支持资源接口。APK 加固、正式签名和覆盖升级按既有流程处理。

### AAB

- 清单省略 `module` 时，`source` 相对于 `base/assets/`。功能模块和 Asset Pack 可在同一清单声明 `"module": "install_assets"`，此时 `source` 相对于该模块的 `assets/`。资源 ID 在同一应用构建内唯一，要为模块独立授权时给它分配独立的 `group`。交付清单沿用原有 bundle 配置，未选择的资源继续按既有 PAS2 路径处理。
- CLI 使用 `shield protect-aab --protected-resource-manifest /本机路径/resources.json --byos-endpoint https://测试域名`，通过环境变量 `SHELLSMITH_BYOS_API_KEY` 传入构建凭据，同时提供原流程的签名及构建工具参数。MCP 对应 `protected_resource_manifest`、`byos_endpoint` 和 `byos_api_key_env`。GUI 在 AAB 页选择清单和设备批准的 BYOS 配置。
- Play 分发的 `--runtime-cert-sha256` 填 Play App Signing 证书的 SHA-256。上传时使用上传密钥。只在同一把测试上传密钥签署本地 split 时，显式使用 `--allow-upload-cert-binding`。启用后 base DEX 与业务资源都走设备批准 BYOS。
- 索引留在 base，密文回到声明的交付模块。运行时从 AssetManager、已安装 split 或现有 Play Asset Delivery 路径访问密文，应用在模块交付完成后调用读取接口。独立 split Context 需要 Android API 26 起。最终 AAB 检查索引、模块密文、原文件路径及所有模块中的相同明文。

当前资源编译上限为单文件 16 MiB、一次构建 64 MiB、最多 256 项。运行时默认在进程内保留最长 60 秒的资源组授权。授权失效、组密钥错误和密文认证失败均会使后续受控读取失败。读取时已经交给业务的数据由业务管理。

## iOS 主应用接入

在现有 `shellsmith-ios.toml` 中声明可选配置。清单使用上面的 JSON 格式，`source_root` 相对于 Xcode 工作副本的源码根目录。只把业务代码直接读取的文件纳入清单，保持 Asset Catalog、Storyboard、系统资源及 Extension 资源走原有流程。

```toml
[protected_resources]
manifest = "resources.json"
source_root = "MyApp/ProtectedAssets"
byos_endpoint = "https://测试域名"
environment = "development"
# App ID Prefix 与 Team ID 不一致时显式配置 app_id_prefix。
```

业务入口使用 `import ShellsmithRuntime` 和 `try await ShellsmithProtectedResources.data("rules")`。iOS 14 起在 App Attest 可用的设备上支持读取。首次有效证明登记待审批，审批后重试读取。应用应处理 `pendingApproval`、`unavailable`、`denied` 与网络错误。工作副本会移除匹配的主 target Copy Bundle Resources 项，将密文放进生成的 Swift Package。其他 target 共用的明文和不能安全归属的同名引用会失败。Archive 与最终 IPA 都检查密文、索引和明文残留，最终 IPA 另外要求 App ID 和 App Attest entitlement 与配置一致。

在配置启用后，用 CLI `shield protect-ios --ios-config /本机路径/shellsmith-ios.toml --output /本机路径/输出目录` 或 MCP 执行。真实构建从本机环境读取 `SHELLSMITH_IOS_BYOS_API_KEY`，MCP 可通过 `byos_api_key_env` 指明注入的环境变量。App Attest 资源密钥的 Keychain 账户按 App ID 和证明环境区分，同时保留此前的 App Attest Keychain 账户。开发与 TestFlight 使用各自的 BYOS 应用配置，TestFlight 使用 `production`。

### iOS App Extension

请把 `[project]` 中的 `bundle_ids` 按主应用、扩展的顺序配置。在同一个 Xcode project 选择一个 iOS 14 起的 Extension，并在主应用及 Extension 都启用相同的 App Groups 和 Keychain Sharing，更新两个 target 的描述文件。配置中使用签名后实际的 Keychain Access Group 值。

```toml
[protected_resources.app_group]
identifier = "group.com.example.app"
keychain_access_group = "ABCDEF1234.com.example.app.shared"
extension_target = "Share Extension"
extension_bundle_id = "com.example.app.Share"
```

主应用调用 `try await ShellsmithProtectedResources.publishToExtension("rules")` 完成 App Attest 授权，并使用单独的 AES-GCM 密钥生成加密副本。扩展导入生成的 `ShellsmithSharedResources` 产品，调用 `try ShellsmithSharedResources.data("rules")`。快照使用原授权的剩余时间，最多 60 秒。加密文件保存在 App Group，短期密钥保存在双方指定的共享 Keychain。切换账号或主动撤销共享时，主应用可调用 `invalidateExtensionResource`。已返回给业务的字节由业务生命周期管理。Archive 和 IPA 都会核对两个可执行文件的 App ID、App Group 及 Keychain 权限。

iOS 资源租约使用包含设备睡眠时间的连续时钟。主应用先写入带独立文件名的密文，再提交共享 Keychain 指针。提交失败保留之前仍有效的快照。扩展返回数据前复核同一授权记录和有效期。

## 运行时事件与范围读取

- Android 可通过 `observeEnvironment` 在应用启动及恢复前台采样，通过 `openObserved` 或 `readRangeObserved` 接收授权与读取结果。传入待拦截的组 ID 时，平台报告已连接调试器将拒绝该组。其他本地信号用于记录。
- iOS 可通过 `observeEnvironment` 在启动及前台采样，通过 `data(_:range:blockRuntimeGroups:observer:)` 接收事件。显式列入策略的资源组会检查现有 RASP 的调试器、签名及运行时完整性信号。
- 事件记录生命周期、环境、授权或读取阶段，以及 `read_id` 与可选 `authorization_id`。缓存读取可关联签发它的授权。资源请求附带短期 `X-Shellsmith-Request-ID`，BYOS 日志记录对应挑战与授权决定。旧请求体、签名方式和 HTTP 响应沿用原契约。
- 用 `read: "range"` 表达业务使用范围读取。Android `readRange` 使用偏移和长度，iOS `data(id, range: ...)` 接受半开字节范围。当前每次按顺序认证整份最多 16 MiB 的 SSR1，只交付选中的字节且无需写临时明文。适用于字节范围型消费者，文件路径和 FD 型消费者仍需分别验收适配。

## 容器与交互

容器 `SSR1` 的头部依次为 4 字节标记、16 字节构建 ID、1 字节组 ID 长度及组 ID、1 字节资源 ID 长度及资源 ID、4 字节版本、8 字节原文长度。整数为大端序。正文依次存放 64 KiB 分片，末片长度由原文总长度决定。每个记录依次为 12 字节随机 Nonce、对应长度的密文和 16 字节认证标签。AES-256-GCM 认证数据为完整头部加从零起的 4 字节大端分片序号。

Android 签名载荷内的 `assets/shellsmith-resources/index.json` 记录版本、构建 ID、服务地址、组 token 和资源 ID 至组和版本的映射。组密钥留在服务端封存。构建会核对输出中所有组密文和索引的摘要，并搜索匹配的明文副本。签名报告重绑定时重新核验密文和索引。

注册、挑战和领取分别走 `/v1/resource-keys/register`、`/challenge` 和 `/fetch`。资源 token 按服务端应用身份、构建和组划定范围。挑战请求由已批准设备签名，挑战保留 60 秒并限同一设备使用一次。领取继续使用绑定请求摘要的 RSA-OAEP 响应信封。服务端通过不同域标识和资源 token 前缀强制分流。旧 Android DEXB v7 客户端继续访问 `/v1/keys/*`。

iOS 使用 `/v1/ios-resource-keys/*` 和独立的 `i_` token。服务端验证 Apple 根证书链、nonce、App ID、证明环境和持久化断言计数。挑战绑定构建、资源组、安装公钥和一次性的 RSA 响应公钥。设备明确批准后才发送资源组密钥。设备或构建撤销后拒绝新授权，在客户端已经签发的租约最多存续 60 秒。

## 本轮证据与仍需准备项

| 项目 | 当前证据或所需操作 |
|---|---|
| 构建容器及双端解码 | Rust 生成的密文已由 JVM Java 与 macOS Swift CryptoKit 实际读取。互操作回归覆盖跨片、篡改、截断、额外尾部和授权失效。 |
| 旧、新服务共存 | 在独立 PostgreSQL 运行服务端既有 HTTP 冒烟和新旧接口的取钥回归，覆盖旧 IKM、挑战重放、错误资源组、跨接口取钥拒绝和撤销。 |
| 旧保护路径 | Android API 35 的 4 KB 真机、API 37 的 16 KB 模拟器分别通过上一轮保留的严格模式 APK 原样安装、冷启动与缓存启动，覆盖 Application、Activity 与 secondary DEX。上一轮同时验证过未加固基线与同签覆盖安装。签名夹具、摘要和日志保存在本机 `target/resource-protection-device-evidence/`。历史正式签名 BYOS 客户端还需在测试服务验收。 |
| Android 新链实际联调 | 需要隔离、证书受信任的 BYOS HTTPS 测试服务和专用测试应用身份。先部署服务端迭代代码，再用授权测试 APK 从原始版本覆盖升级，核验资源组注册、首次读取、到期、撤销和普通业务。 |
| AAB 旧配置 | 回归夹具通过 `bundletool validate`，生成的 split 在 16 KB 模拟器冷启动，确认 Application、Provider、Activity 和 Native 探针。 |
| AAB 资源授权 | 临时 CLI 使用隔离的测试 CA，通过 HTTPS 在独立 PostgreSQL 登记 base DEX 和业务资源组，成功生成并检查签名 AAB、split APKS、SSR1 密文、明文残留和重绑定报告。测试 CA 只在该测试构建里。Play 下发和设备端读取留待实际渠道验证。 |
| iOS 接线及授权 | 用 iPhoneOS SDK 对 App Attest、资源授权及读取源代码执行 arm64/iOS 14 类型检查。工程接线回归验证只删除主应用对应路径的复制项。服务用模拟 Apple 签名链覆盖审批、重放、签名请求、旧计数和撤销。真机证明和签名 IPA 覆盖升级留待实际环境。 |
| 多模块 AAB | 隔离 HTTPS 服务登记四个独立组，分别检查条件功能模块、install-time、fast-follow 和 on-demand Asset Pack 的 SSR1 落位、原件残留、索引和 split 生成。相同输入使用旧配置仍产出四个 PAS2 资源，旧 split 在 16 KB 模拟器上通过功能模块与 install-time 读取。 |
| 范围读取与运行时 | Java 与 Swift 用同一份 SSR1 验证跨分片读取及未选分片篡改。服务端回归验证新关联 ID 可串联挑战、批准或拒绝，旧取钥路由沿用原契约。4 KB 真机与 16 KB 模拟器重复启动保留的历史严格模式 APK。 |
| App Group | 主应用和 Extension 通过 iPhoneOS SDK 类型检查，包含 `-application-extension` 检查。工程夹具验证包仅接入指定扩展，权限夹具验证签名身份、App Group 和共享 Keychain 匹配。正式签名和跨进程 Keychain 访问留待项目真机。 |
| 离线同签升级 | 在 API 35 的 4 KB 真机和 API 37 的 16 KB 模拟器上，测试包从已加固版本 21 覆盖安装到已加固版本 22。升级前写入的业务数据在升级后首次与二次启动均保留，secondary DEX、Native 和 `openFd` 检查通过。 |
| 离线读取与快照回归 | 16 MiB SSR1 在两台 Android 测试设备的 ART 中通过完整读取、64 字节范围读取和未选中末片篡改拒绝。恰好读到末字节后关闭只记录一次 `verified`。Swift 夹具覆盖旧快照记录解码、有效期和 Keychain 写入失败时保留旧快照；主应用与扩展产出 iPhoneOS arm64 目标文件。 |

同一份 16 MiB 夹具连续选择 64 字节范围并认证全文件。预热后采样 20 次，Android 4 KB 真机 P95 为 51.53 ms，16 KB 模拟器 P95 为 21.90 ms。macOS Swift 测试中，按分片释放临时对象后，整段进程峰值 RSS 从约 377 MiB 降至 7.3 MiB，P95 从 13.18 ms 变为 15.05 ms。这些数值用于本机回归对照，iPhone 的性能与内存仍需在真机验收。

### 正式验收前需要的输入

1. 在本机以管理员身份处理 `sudo xcodebuild -license`，在 Xcode 登录团队并使 `security find-identity -v -p codesigning` 可列出有效的 iOS 签名身份。连接及信任测试 iPhone，开发安装按需启用开发者模式。
2. 提供 Apple Team ID、测试 Bundle ID、原签名 IPA、本轮同应用身份且可提升版本号的源码路径。在 Developer Identifiers 为测试 Bundle ID 启用 App Attest，在 Xcode 主 target 配置该能力，更新 provisioning。开发真机配置为 `development`，TestFlight 为 `production`。保留历史 Keychain Access Groups 与使用中的签名权限。
3. 为 Android 测试应用在 Play Console 的 App Integrity 页面取得 **App Signing Key Certificate** 的 SHA-256，准备原内测版及能上传的新版本。保持相同包名，提升 `versionCode`，用上传签名发到已有内测轨道，由测试账号通过 Play 覆盖安装。
4. 提供一个隔离的 BYOS HTTPS 服务地址，证书同时受构建电脑和测试设备信任。先备份并升级测试库，再创建 Android 测试应用与 iOS 专用应用及构建凭据，将构建凭据保留在本机或测试 CI。在待审批列表核对本次安装设备后批准，完成读取、断网重试、撤销及旧包回归。

复验容器互操作可运行 `cargo test -p shield-core --test protected_resource_interop -- --ignored`，要求可用 JDK 和 macOS Swift CryptoKit。Android 业务应用需用签名产物、真实服务和设备独立验收。各环境验证结果见[旧产物兼容检查](../process/test-checklist.md#保护能力升级的旧产物兼容检查)。
