# BYOS 风险事件客户端

本文说明风险事件协议 v1 基线。新增详细证据、服务端能力协商与撤销收据见 [v2 接入说明](byos-risk-events-v2.md)。只更新 Shellsmith 客户端和构建产物，不修改或部署密钥服务。

## 启用与身份

- Android 构建显式写入 `KEY_SOURCE=local/byos` 和 `RISK_PROTOCOL=0/1`。只有支持 `risk_events_v1` 的设备批准运行时使用协议 1；旧运行时缺少能力字段时使用 0，继续沿用原取钥流程。Play-only 使用 0，不使用匿名身份或构建凭据上报。
- iOS 资源索引显式携带 `key_source=byos`、`risk_protocol=1`、实际构建 ID 和资源组 token；旧索引缺少字段时不启用。
- 首次响应必须经过 RSA OAEP 解密、64 字节长度校验和请求摘要校验，才能保存无密钥的授权标记、绑定风险监听器。Android 旧 DEXB 和纯资源共用这个成功分支。
- 标记绑定完整 HTTPS 基础 URL、实际取钥 token、构建与资源组、安装密钥身份。恢复时匹配当前构建范围及安装身份；新安装密钥不继承旧标记。标记不参与资源授权判断，也不替代服务端 `device_key_grants`。
- 同安装此前成功取钥后，断网、取钥拒绝、撤销、租约过期不停止风险队列；资源使用仍由原有授权和最长 60 秒租约控制。风险收据不恢复资源授权。
- 本地密钥和 Play-only 变体不链接签名上报实现，不创建待报队列，并在覆盖安装后清空旧待报状态。iOS 未启用 BYOS 资源的生成工程不包含风险客户端，并清除旧风险存储。

Android 安装身份为原 Keystore EC 公钥 DER SPKI 的 SHA-256，签名使用同一个不可导出私钥和 `SHA256withECDSA`。iOS 安装身份为原 App Attest key ID 解码后的 32 字节十六进制，报告使用 `generateAssertion` 的完整 CBOR 数据。

## 回调、串行与持久化

Android 订阅现有环境检查，固定码为 `debugger`、`root`、`runtimeSuspect`、`runtimeManipulation`。授权后在进程存活期间每 30 秒复查一次；不创建常驻服务，不唤醒已退出应用。信号沿用现有检测能力，不能据此识别所有逆向工具或证明检测结果真实。

Android 每个进程使用稳定进程名隔离的私有 SharedPreferences，避免多进程覆盖队列；安装私钥仍跨进程复用。每进程最多 64 个授权范围、每范围 16 条，重复未确认检测码合并。使用一个后台串行工作线程，挑战至少间隔 6 秒。队列和授权标记不包含 IKM、构建 API key、管理员会话、资源密文。

iOS 在授权后订阅 `dev.shellsmith.threat-detected`，并读取已有检测状态。每安装最多 64 个授权范围、每范围 16 条；队列写入独立 Application Support 目录，原子替换文件并排除备份。Key ID 是公开身份，私钥由 App Attest 管理。

**iOS 资源取钥与风险任务共用同一个 `previous` 尾任务**，覆盖 assertion 生成至 HTTP 响应全过程，不能使用独立的上报队列绕开计数顺序。重试已保存的报告时复用原 assertion；需要新挑战时保留事件 ID、检测时间和正文。安装密钥失效会清除对应监听与待报状态，不能继承到新身份。

Android 原生库仍先通过原有完整性校验，再恢复风险身份和监听，不提前加载未经校验的库。

## 签名与失败处理

规范化摘要使用 UTF-8 与 LF，末尾无换行，不对 JSON 求摘要。完整基础 URL 保留路径前缀；构建端统一去掉末尾 `/`。旧 DEXB 的空构建和空资源组保留分隔位置。

实现固定事件摘要、挑战摘要与报告摘要。挑战和报告独立于资源取钥协议；事件签名不使用 IKM。Android 证明使用摘要作为 `SHA256withECDSA` 输入；iOS 将报告摘要作为 `clientDataHash`。

| 结果 | 客户端行为 |
| --- | --- |
| `accepted`，事件 ID 匹配，动作合法，授权版本为非负整数 | 删除对应事件；不更改资源租约 |
| 503、断网、未获确认 | 保留事件和原报告，指数退避并加入抖动，最长一小时 |
| 429 | 退避，保留队列，限制挑战频率 |
| 403 | 固定诊断，不降级身份；原挑战已过期时清除该证明，下次申请新挑战 |
| 404 | 配置诊断，至少一小时后重试 |
| 400、409、无效收据 | 停止该条自动提交，保留脱敏诊断；不阻塞其他条目 |
| 超过 24 小时 | 丢弃并记录固定诊断，不修改检测时间重新提交 |

日志只输出 `R_*` 固定分类，不输出事件正文、证明、IKM 或系统异常原文。挑战请求最多 4096 字节，报告最多 32768 字节；禁止跟随 HTTP 重定向。公开风险请求不添加 Bearer 或管理员会话。

## 可重复验证

用户提供的公开固定向量保存在 `tests/fixtures/risk-events/risk-event-vector.json`。Android 和 Swift 独立复现三个摘要。

```bash
python3 tests/scripts/check-risk-events.py
cargo test -p shield-core -p shield-ios -p shield-cli
MOCIKA_BYOS_RUNTIME=1 ANDROID_HOME=/path/to/sdk \
  ./shield-stub/gradlew -p shield-stub assembleDebugAndroidTest testDebugUnitTest -x buildRustLibs
adb install -r -t shield-stub/build-byos/outputs/apk/androidTest/debug/shield-stub-debug-androidTest.apk
adb shell am instrument -w dev.mocika.shield.stub.test/dev.mocika.shield.loader.ByosDeviceContractTest
python3 tests/scripts/check-byos-resources.py
```

Swift 检查在临时副本中替换 App Attest 和网络传输，执行真实客户端状态机与真实 RSA OAEP 解密。覆盖本地模式、旧索引、拒绝取钥、错误摘要、成功启用、持久恢复、新安装身份、丢失收据与取钥/上报计数串行。它不代表 Apple 签发链或实际 HTTPS 验收。

Android 仪器测试使用真实 AndroidKeyStore，覆盖错误响应不启用、原安装签名、原报告重试和独立纯资源取钥入口；HTTPS 连接由测试 APK 拦截，不能当作公网 TLS 或生产服务验收。发布 ZIP 检查确保只有设备批准变体包含风险摘要与风险路由，离线和 Play-only 不包含。

## 需要外部环境的最终验收

1. 部署与接入文档匹配的服务端实现，先备份数据库，在隔离环境执行版本 6 迁移、检查，再启用 `risk_events`。本机当前密钥服务仓库尚未包含这份风险实现；不能用旧版服务宣称联调已通过。
2. 保留完整 HTTPS 基础 URL 和代理前缀，开放两条风险 POST 路由。先采用 `record` 策略，再对已验证的固定码开启 `revoke`。
3. Android：真实服务完成纯资源首装登记、批准、成功解包、上报可见、撤销、再次取钥拒绝、60 秒租约失效、管理员复核恢复；保留一份已发布旧 APK 验证原公网取钥。
4. iOS：本机 Xcode 初始化、普通开发签名和真机启动已完成；App Attest 与 TestFlight 验收还需具备对应权限的付费开发者团队。配置真实 App ID 和 App Attest 环境，分别验收 development/production，尤其是跨接口计数、丢失响应、重复确认、撤销后上报与重装新身份。
5. 用真实服务补验伪造签名、token/组/安装身份替换、重放、延迟、限流及断网恢复。客户端和服务端都检查脱敏日志。

此次不改变 DEXB v5/v6/v7 格式、资源加密格式、取钥响应结构、旧设备批准身份、App Attest 账户范围和租约上限。已发布应用不会因构建工具升级自动获得新模块；需要重新加固/接入并发布新客户端。

## 本地执行记录（2026-11-19）

| 检查 | 结果 |
| --- | --- |
| Rust 核心、iOS 核心与 CLI | Android 核心 267 项、iOS 核心 69 项、CLI 两组各 22 项及附加 4 项通过；既有忽略项不计为通过 |
| Android 协议仪器测试 | HONOR API 35 / 4 KB、模拟器 API 37 / 16 KB 均为 2 项、0 失败；包括固定向量、Keystore 签名、错误响应不启用、丢失收据重试、独立纯资源入口 |
| Swift 软件状态机 | 三个摘要、正确/错误 OAEP 封装、本地与旧索引关闭、持久恢复、新身份、原报告重试、共享计数串行通过；写盘失败时不发出未持久化报告 |
| iOS 目标类型检查 | 真实生成的 App Attest 包装与资源客户端通过 iOS 14 arm64 SDK 类型检查；不等同签名 Archive 或真机运行 |
| 完整 Xcode 归档 | Xcode 27.2、官方 freeRASP 7.1.4；资源客户端、风险模块、App Attest 包装与分享扩展通过工程/工作区两条归档路径；主二进制包含框架加载路径 |
| iOS 开发签名 | Xcode 初始化完成，免费 Personal Team 开发证书及中间证书链有效；应用和分享扩展签名通过，开发描述文件到 2026-11-26 有效，可重新生成 |
| iOS 运行 | iPhone 15 / iOS 27.2.1 启动与再次启动成功；iPhone 17 Pro / iOS 26.2 模拟器启动、前后台恢复成功；均无远程授权标记和风险待报目录 |
| 发布运行时隔离 | 离线、设备批准、Play 三个 ZIP 通过；只有设备批准 ZIP 包含风险摘要及风险路由。API 19 兼容包重建并通过 ELF 检查 |
| 旧运行时覆盖升级 | 保留旧 CLI/旧运行时构建基线，用同一测试签名证书升级到新 CLI/新运行时；两台设备冷启动、缓存启动、业务数据、多 DEX、Native 与 openFd 均通过 |
| 桌面应用 | 更新 CLI 与 macOS `.app`；应用内四种 Android 运行时与构建输出逐一核对 SHA-256，应用签名校验通过 |

原始记录和产物摘要位于 `target/risk-event-evidence/`，其中基线二进制和测试 APK 只用于本次兼容回归，不纳入 Git。上表不包含真实 BYOS 风险服务、Apple 生产证明、公网旧包取钥或检测误判率验收。

完整 Xcode 验证的工程、签名测试包和日志另保存在 `target/ios-xcode-validation/`，不包含导出的签名私钥。主应用路径修复覆盖缺省值、字符串、数组、注释、SDK 条件、多个构建配置及重复接入；分享扩展路径保持原值。安装验证同时补齐了测试扩展的名称字段和测试应用的 Scene 生命周期；这些测试夹具调整不修改业务工程的生命周期。

免费开发签名的启动验证不等同 App Attest 验收，也不代表客户已发布 IPA 的同团队覆盖升级、越狱/Hook 检测率或运行开销已经测完；这些项目仍按目标业务包与受控设备单独验收。
