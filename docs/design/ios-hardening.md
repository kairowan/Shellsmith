# iOS 加固实现

## 能力和边界

Shellsmith 的 iOS 流水线以用户拥有源码及签名权限的 `.xcodeproj` 或 `.xcworkspace` 为输入。它在独立工作副本中接入保护，不修改原工程；Xcode 探测不会只依赖当前 `xcode-select`，当系统默认目录仍指向 Command Line Tools 时，会自动检查 `DEVELOPER_DIR`、常见 Xcode 安装目录和 Spotlight 找到的 Xcode，并把同一个开发者目录用于检查、依赖解析、Archive 和导出：

1. 按需使用 Swift Confidential 0.5.2 和同版本构建插件保护明确选择的 Swift 字面量；不提供 `confidential.yml` 时跳过该可选层，不影响其余保护。
2. 使用 freeRASP iOS 7.1.4 检测签名异常、越狱、调试器、Hook、模拟器、非官方安装、截图录屏等运行时信号。
3. 使用 Apple 原生 `xcodebuild archive`、`-exportArchive`、Keychain 和 Provisioning Profile 完成构建签名。
4. 验证 `codesign`、Team ID、Bundle ID、Entitlements、arm64、Privacy Manifest、TalsecRuntime dSYM 和选择性敏感字符串。

运行时事件在 ShellsmithRuntime 内部去重，并统一异步投递到主线程；启动期间产生的威胁会保留，可通过 `observedThreats()` 在业务监听器注册后重放。第三方 RASP 的启动调用不会在 Shellsmith 锁内执行，避免同步回调造成启动死锁。

Swift Confidential 属于局部静态保护，freeRASP 属于运行时应用自保护。组合后是分层的第三代方案；只有客户端 RASP 或 App Attest 客户端接口时不能称为第四代。`strict` 可以不配置服务端地址执行客户端加固；配置地址后才具备接入服务端证明闭环的条件，服务端仍需自行实现挑战、Apple 证明校验和重放防护。

保护流水线会审计自己生成的 `.xcarchive` 与 IPA。只提供 IPA 时不执行通用注入、绕过签名或重新打包。Windows/Linux 可以检查配置和工程静态信息，Archive 与 IPA 导出必须在安装完整 Xcode 的 macOS 上执行。

## 目录和流程

Rust 核心位于 `crates/shield-ios`，CLI/Tauri GUI 调用同一接口。保护任务依次执行：

```text
工程预检
  -> 独立工作副本
  -> .shellsmith/ShellsmithRuntime 本地 Swift Package
  -> 修改唯一 Swift @main 或 Objective-C AppDelegate 启动回调
  -> 应用 target 接入本地 Package
  -> 解析精确版本依赖
  -> Archive
  -> 导出 IPA
  -> 签名和安全验证
  -> shellsmith-report.json
```

生成的本地 Package 直接依赖上游仓库，Shellsmith 安装包不携带或改名 freeRASP 闭源二进制。启用 Swift Confidential 时，主包与插件使用相同精确版本；未启用时不接入该插件。Archive 前必须生成唯一且非空的 `Package.resolved`，报告记录其 SHA-256；生产构建不跳过已启用的 Swift Package 插件或宏校验。构建失败、取消或验证阻断只影响输出工作副本。

纯 Objective-C UIKit 工程通过 `AppDelegate.m` 的 `application:didFinishLaunchingWithOptions:` 接入同一 Swift Package 的 Objective-C 启动桥，在已有回调的开头启动保护；其余回调逻辑和 `main.m` 保持不变。Swift Confidential 不保护 OC 字符串。无该启动回调或无法唯一确定目标时明确阻断，需人工适配。

包含 Share Extension 等依赖 target 的工程中，对象 ID 会先出现在 `containerPortal` 等引用字段里。工程接入必须定位实际对象声明，将 `packageReferences` 写入 `PBXProject`，不能写入 Frameworks 构建阶段。依赖解析后只检查本次选中的工程或工作区内的锁文件，缺失或版本不符时在 Archive 前停止。CI 使用带分享扩展的纯 OC 样例，通过 `.xcodeproj` 和 `.xcworkspace` 分别解析真实 freeRASP 依赖并执行无签名 Archive；该检查不替代开发者签名和真机运行验证。

## 配置

从 [示例配置](../../examples/shellsmith-ios.toml) 开始；只有需要保护项目自定义敏感字面量时才创建 [敏感字符串配置](../../examples/confidential.yml)。配置不得保存证书私钥、钥匙串密码或 Apple 账号令牌。

保护档位：

| 档位 | 行为 |
|---|---|
| `compat` | 原生 Release/Archive/签名验证，不接入第三方保护 |
| `balanced` | freeRASP；提供 `confidential.yml` 时再加上 Swift Confidential |
| `strict` | balanced + App Attest 客户端接口；HTTPS 服务端地址可选 |

freeRASP 事件转换为稳定的 Shellsmith 名称，并通过回调及 `Notification.Name.shellsmithThreatDetected` 发给应用。Shellsmith 不擅自终止进程或封禁账号；业务应根据事件的 `observe`、`restrict`、`critical` 等级限制支付、密钥导出、管理操作等敏感流程。

`strict` 档生成的 App Attest 客户端会把 key ID 保存在 Keychain，并提供挑战摘要、attestation/assertion envelope 和 HTTPS 提交方法。服务端地址不是加固任务的必填输入；没有服务端完成闭环时，报告会明确标记“未配置 App Attest 服务端”，不能把客户端接口当作已完成的设备证明。

## 上游问题处理

| 上游问题 | Shellsmith 处理 |
|---|---|
| Swift Confidential [#12](https://github.com/securevale/swift-confidential/issues/12) XCFramework Archive 重复产物 | 仅接入应用 target；检测 framework/`BUILD_LIBRARY_FOR_DISTRIBUTION` 后拒绝错误接法 |
| freeRASP [#17](https://github.com/talsec/Free-RASP-iOS/issues/17) 动态 framework 嵌套 | 本地 Swift Package 作为应用 target 的直接产品依赖，禁止接到二级 framework |
| freeRASP [#55](https://github.com/talsec/Free-RASP-iOS/issues/55) SPM 接入反馈 | Archive 前强制 `-resolvePackageDependencies`，解析失败立即停止并保留诊断 |
| freeRASP [#41](https://github.com/talsec/Free-RASP-iOS/issues/41) Dopamine 2 RootHide 漏检 | 报告保留残余风险；strict 要求 App Attest/服务端联合判断，不宣传已覆盖 |
| TalsecRuntime 缺失 dSYM | Archive 对比 Mach-O/dSYM UUID；缺失时警告并指向同版本 Release |

闭源 freeRASP 内部检测算法不能由 Shellsmith 修补。上游未修复的漏检会作为残余风险保留，不能用本地文案改成“已解决”。

## 命令

```bash
# 只读检查；其他系统也可运行
cargo run -p shield-cli -- check-ios /path/App.xcworkspace --scheme App

# 完整保护、归档、签名和验证
cargo run -p shield-cli -- protect-ios \
  --ios-config examples/shellsmith-ios.toml \
  --output /path/to/empty-output \
  --export-method development
```

自动化环境可以追加 `--json`。只有确实允许 Xcode 使用本机开发者账号更新描述文件时才传 `--allow-provisioning-updates`。

## 许可证与隐私

- Swift Confidential 使用 Apache-2.0 及其运行时例外，发布时保留许可证和 NOTICE。
- freeRASP 同时包含 MIT 开源部分和 Talsec 所有的闭源二进制，并受 freemium/公平使用政策约束。
- `watcherMail` 会用于安全报告、产品更新和 Talsec Portal；产品接入前必须完成隐私披露和使用条款审查。
- Shellsmith 不重新分发 freeRASP 二进制。客户工程通过精确版本的上游依赖解析取得它。

## 当前验证限制

Rust 核心、工程补丁、配置、CLI、Tauri 后端和前端可以在普通开发环境自动验证。Archive 验证会递归检查 App、Extension、Framework 和动态库的签名、Team ID 与 arm64，但它不能替代真机运行。

发布前必须在真实设备执行以下 P2 回归：冷启动/热启动、后台恢复、Scene 重建、推送和深链、蓝牙、音频、定位、录屏截图、锁屏解锁、内存压力和异常网络。报告会保留 `runtime_device_validation` 警告，直到外部测试系统把这些结果回填。Windows/Linux 不能执行 Archive；没有完整 Xcode、开发者签名、受控设备或 App Attest 服务端时，Shellsmith 不会伪报通过。
