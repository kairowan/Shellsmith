# BYOS 风险证据升级与服务端接入

本次只修改 Shellsmith，不修改 BYOS 服务端或线上撤销规则。新客户端兼容原风险协议 v1；只有成功取钥响应明确声明能力，才产生 v2 事件。已安装的旧 APK/IPA 不会因桌面工具升级自动更新，获得详细证据需要重新加固或重新接入 SDK 后发布。

## 为什么原事件不自动撤销

此前真机测试事件的后台处置是 `record`。`record` 表示记录，不代表设备已撤销；后续人工撤销和恢复属于独立授权操作。截图显示当前 `approved` 与历史事件“已记录”可以同时成立。

客户端负责观察、认证上报和执行有效的撤销回执；BYOS 负责规则匹配、授权状态变更、拒绝后续取钥与审计；管理界面负责解释事实、规则及历史状态。只翻译 `debugger` 无法补回客户端没有上传的证据。签名通过只说明持有安装密钥，不证明风险检测一定准确或具有恶意。

## Shellsmith 已实现的变化

- Android 保留原低位环境标志和阻断策略，新增具体检测来源。旧 Native 没有详细标志时继续使用聚合码。Java 调试器与 Native ptrace 来源分别上报。
- iOS 使用 freeRASP 原有威胁回调，并明确标为 SDK 回调。上游没有暴露进程、模块、具体命令或调试器名称时，不伪造这些信息。未开启 freeRASP 的工程保留撤销保护，不产生虚构的 freeRASP 检测结果。
- v2 将有界证据纳入事件摘要和原有安装密钥认证。JSON 字段顺序不影响签名；任何证据值变化都会改变摘要。
- v2 收据返回当前授权状态和版本后，客户端可限制当前进程后续受保护访问。旧 v1 收据行为保持不变。
- 本地密钥模式继续不绑定这套监听、不建立上报队列、不调用风险接口。Play-only 继续不链接设备批准风险实现。

## 服务端改造顺序

1. 数据库增加可空证据、协议版本及规则命中记录，保留原事件表与 v1 验签逻辑。先跑两个固定向量，再跑伪造、重放和幂等检查。
2. 在既有两个风险接口按 `event.protocol` 分发 v1/v2 验证。v2 的证据必须参加签名校验，验证成功后才能入库、执行规则。
3. 实现 v2 收据的当前授权字段；事件原始处置与当前状态分开返回。实现设备撤销、授权版本递增及审计的事务。
4. 管理界面增加中文事实、来源、置信度、命中规则、处置原因和授权时间线。旧事件展示“未采集详细证据”。
5. 用隔离测试产物启用能力声明，默认 `record`；验收通过后再为明确的应用/产物开启自动撤销规则。
6. 后端全链路上线后重新加固测试包，按“登记→批准→取钥→触发→自动撤销→拒绝取钥→恢复→重启”联调。不要先在旧服务器声明 v2。

## 成功取钥响应增加可选能力

仅在 `/v1/keys/fetch`、`/v1/resource-keys/fetch` 和 `/v1/ios-resource-keys/fetch` 的成功响应增加：

```json
{
  "risk_events_v2": { "authorization_version": 7 }
}
```

其余原字段原样保留。版本为 0～2^63−1 的整数（拒绝布尔、小数和数字字符串），表示此次成功授权的最新版本；不得回退。同一安装在此授权范围内的批准、撤销、恢复都应单调递增。v2 客户端记录已观察到的最大版本。

- 不增加 `/v1/keys/check` 返回字段：现有构建端对未知字段严格检查。
- 不修改旧注册请求、旧取钥请求、取钥摘要、`fetch_protocol=2` 或安装密钥别名。
- 字段缺失或 `null` 时，新客户端继续发 v1；错误类型、缺少版本、负数或回退的版本不得被当作成功 v2 授权。
- 只有原 RSA OAEP 解密、长度和请求摘要校验完成后才能采用该声明；配置地址、待批准和仅收到 `granted` 字样均不够。
- 声明通过原有已校验证书的 HTTPS 信任通道传递；不要关闭 TLS 验证或跟随重定向。
- 以前成功授权范围的风险队列仍可恢复、认证重试；此标记不提供资源访问权，不替代重新取钥。

## v2 事件字段与验证边界

保留 v1 全部基础字段，仅将 `protocol` 改为 `2`、`detector_version` 改为 `"2"` 并增加 `evidence`：

```json
{
  "protocol": 2,
  "platform": "android",
  "token_id": "实际产物 token",
  "build_id": "",
  "resource_group": "",
  "installation_id": "安装公钥 SPKI 的 SHA-256 小写十六进制",
  "event_id": "32 位小写十六进制",
  "detected_at": 1800000000,
  "detection_code": "debugger",
  "detector_version": "2",
  "evidence": {
    "schema": "1",
    "signal": "android.java_debugger_connected",
    "source": "android.os.Debug.isDebuggerConnected",
    "observed": "true",
    "confidence": "high",
    "observation_type": "state_sample",
    "payload": "dex",
    "dexb_version": "7"
  }
}
```

证据必须为扁平的字符串字典，不允许 JSON 数字、布尔、数组或嵌套对象。字段数量 1～32；`schema` 必须为 `"1"`；键匹配 ASCII `[a-z][a-z0-9_]{0,47}`；每值最多 256 个 UTF-8 字节，禁止 U+0000～U+001F 和 U+007F；拒绝无效 Unicode。整个证据规范化文本最多 2048 个 UTF-8 字节。客户端上下文元数据另限 128 字节，无法读取或超限时填 `unavailable`。

服务端沿用原有基础字段、时间窗口、安装绑定、产物归属和 HTTP 大小限制；拒绝重复 JSON 键、超大/错误类型和未知事件协议。v1 不能附带未签名证据。未知证据键可以验签后保留展示，不能自动赋予高风险语义。请求字段应使用明确白名单并随 v2 增加 `evidence`。

可选上下文包括 `app_id`、`app_version`、`app_version_code`、`os_version`、`os_api`、`device_model`、`process_name`、`debuggable`、`payload`。这些是客户端观察值，不能替代后台登记的签名指纹、包名或可信产物元数据；`debuggable=true` 不能单独证明调试器已连接。不要上传 API key、IKM、私钥、用户录音、完整文件路径/映射、账号或整机应用清单。

## 摘要和签名

使用 UTF-8、LF 换行、末尾无换行。证据键按 ASCII 升序排列；不对 JSON 序列化结果求摘要。值可包含 `=`，服务端直接按键值构造文本，禁止拆分后重解释。

```text
shellsmith-risk-evidence-v1
app_id=com.palmzem.voicerecorder
confidence=high
...
signal=android.java_debugger_connected
source=android.os.Debug.isDebuggerConnected
```

`evidence_digest = SHA256(上述文本)`。v2 事件规范化文本为：

```text
shellsmith-risk-event-v2
规范化 HTTPS 基础地址（保留路径前缀，无末尾斜杠）
2
platform
token_id
build_id
resource_group
installation_id
event_id
detected_at 的十进制整数
detection_code
detector_version
evidence_digest 的小写十六进制
```

空 `build_id`、`resource_group` 保留空行。`event_digest = SHA256(上述文本)`。挑战和报告域继续用原 v1 域，因为其中已绑定带版本域的事件摘要：

```text
challenge_digest = SHA256("shellsmith-risk-challenge-v1\n" + hex(event_digest) + "\n" + timestamp + "\n" + request_id)
report_digest = SHA256("shellsmith-risk-report-v1\n" + hex(event_digest) + "\n" + challenge)
```

Android 使用取钥时同一 P-256 安装私钥，将 32 字节 digest 传给 `SHA256withECDSA`。算法会再做一次 SHA-256；服务端必须匹配原协议，签名为 ASN.1 DER，标准 Base64 编码，不能擅自替换成裸 `r||s`。iOS 保留现有 App Attest 完整 assertion，`clientDataHash=report_digest`，与取钥共享计数器顺序；不能用普通开发签名测试替代 Apple 证明链验收。

原路由 `/v1/risk-events/challenge` 与 `/v1/risk-events/report`、请求外层结构和证明方式不变。事件协议版本不等于 URL 版本，不新增 `/v2` 路由。

固定向量：

- `tests/fixtures/risk-events/risk-event-vector.json`：用户提供的 v1 文件，原样保留。
- `tests/fixtures/risk-events/risk-event-vector-v2.json`：独立 Python SHA-256 计算的 v2 文件，包含证据、事件、挑战、报告四个摘要。Android 与 Swift 必须分别复现。

## 检测码与管理界面映射

`detection_code` 保留旧粗分类，规则优先匹配 v2 `evidence.signal`。`confidence` 表示对观察信号的置信度，不是“恶意概率”。

| signal | 建议中文说明 | 实际观察与边界 |
| --- | --- | --- |
| `android.java_debugger_connected` | Java 调试器已连接 | Android Debug API 返回 true；不能据此得知调试器名称或执行命令 |
| `android.native_tracer` | 当前进程被追踪 | 自身 `/proc/self/status` 的 TracerPid 非零；未采集追踪者工具身份 |
| `android.frida_mapping` | 进程映射出现 Frida 名称特征 | 自身 maps 匹配已知名称；改名/隐藏可绕过 |
| `android.frida_thread` | 线程出现注入特征名称 | 自身 task 的特定线程名称匹配；仍需排除测试环境 |
| `android.frida_port` | 出现常见 Frida 本地端口 | tcp/tcp6 本地端口命中，不证明监听者属于本 App，也不证明连接/注入成功；低置信 |
| `android.frida_file` | 存在常见 Frida 路径 | 只检查路径存在，不证明正在运行或注入；低置信 |
| `android.hook_mapping` | 进程映射出现 Hook 名称特征 | 已知框架映射名称命中；不能推断具体 Hook 方法 |
| `android.glib_thread` | 出现通用 GLib 线程 | 普通程序也可能使用；低置信，不建议单独撤销 |
| `android.su_executable` | 存在可执行 su 文件 | 已知路径及可执行权限；不证明本 App 已取得 Root |
| `android.privileged_uid` | 当前进程有效 UID 为 0 | 自身 status 的有效用户 ID |
| `android.adb_root` | 系统报告 adb Root 状态 | `service.adb.root=1`；测试固件可合法出现 |
| `android.root_framework_trace` | 发现 Root 框架名称痕迹 | 进程映射或挂载记录的名称匹配 |
| `android.vm_gate_blocked` | 保护执行门已阻断 | 保护状态结果，不应当作另一次独立攻击 |
| `runtime.aggregate` | 运行时检测命中，未采集细项 | 旧信号或原聚合入口，不补造证据 |
| `ios.freerasp.<detection_code>` | freeRASP 报告对应威胁 | 只收到 SDK 威胁回调；无法声称看到了某条 LLDB/Frida 命令 |

iOS 的 `policy_severity` 只表示应用配置的本地处置等级，不替代服务端规则等级。同一状态每次采样都可能再次上报，应展示“首次/最近观察与次数”，不要把多次采样描述为执行了多次攻击操作。

界面建议同时显示：中文事件标题、原始码/信号、原始观察值及来源、观察时间/服务器接收时间、安装身份与验签结果、应用版本/签名/产物、命中规则与规则版本、自动/人工处置及原因、事件当时授权版本、当前设备状态和版本、复核人与理由。摘要与完整事件 ID 可复制，默认折叠结构化原始证据；未知字段按纯文本转义渲染。

旧 DEXB 的 `build_id` 为空并不表示格式老旧。UI 应显示“未携带 build_id”，并优先从登记产物元数据读取 DEXB 格式；v2 新 Android 载荷事件另带 `payload=dex`、`dexb_version=7`。没有这些信息的旧事件不能反推版本。

## 自动撤销事务与 v2 收据

自动撤销必须由后台明确启用的应用/产物规则驱动。例如隔离测试产物可配置 `signal=android.java_debugger_connected -> revoke`；生产规则先验证误报，不以未知信号或单个低置信端口/GLib 状态直接撤销。客户端上报值不能自行决定后台动作。

在同一数据库事务内完成：检查授权范围和当前状态→写入唯一事件→记录命中规则版本及原因→必要时撤销对应设备授权并递增版本→写审计→提交。撤销应立即影响之后的取钥；同一事件重试不能重复撤销、重复递增版本或重复执行外部动作。

v2 `accepted` 收据必须保留原字段并增加：

```json
{
  "status": "accepted",
  "event_id": "原事件 ID",
  "action": "revoke",
  "authorization_version": 8,
  "current_status": "revoked",
  "current_authorization_version": 8
}
```

`action`、`authorization_version` 是该事件的历史处置，首次确认后固定。`current_status` 为当前 `approved|revoked`；`current_authorization_version` 不小于历史版本，按响应时最新状态读取。人工恢复后重发同一事件，应保留 `action=revoke, authorization_version=8`，但返回 `current_status=approved, current_authorization_version=9`。

- 幂等键至少绑定平台、产物/组、安装身份和事件 ID；相同 ID 不同摘要必须拒绝，不能覆盖证据。
- 挑战消费、证明计数与重复收据沿用原重试协议；丢失 HTTP 收据后允许原事件和原报告安全重试。iOS 不得对已经验过的同一报告当作新 assertion 重复推进计数。
- 同一服务、应用身份与安装密钥跨产物/资源组共用最大授权版本，不能分别按 token 保存。当前版本低于这个最大值时，客户端确认历史事件但忽略该过期状态，不误封已恢复授权的会话。不同服务和不同安装身份不混用版本。
- 当前状态为 revoked 且版本有效时，Android 标记当前进程已撤销、关闭 Native 保护执行门、擦除资源组缓存密钥并拒绝后续读取；iOS 清理租约缓存并拒绝后续取钥/受保护读取。
- `approved` 收据不能重新授权，撤销后的当前进程不自动解锁；管理员恢复后必须重启并再次成功取钥。
- v1 收据维持原行为，不凭缺少当前状态字段的旧历史 `revoke` 动作阻断已恢复会话。旧客户端仍由服务端拒绝后续取钥和原租约上限限制。

这不是远程擦除：已交给业务的明文、已加载的任意 Java 代码、已输出的录音不能收回。iOS App Group 扩展在其他进程读取的既有快照沿用最多 60 秒有效期，此次不增加跨进程实时撤销通道。离线或没有新回执时也不能承诺瞬间阻断；服务端拒绝后续取钥始终是授权边界。本次远程撤销不转成前台强杀，原有独立环境阻断策略仍生效；不以安全事件删除用户数据。

## 兼容、灰度与回滚验收

| 场景 | 预期 |
| --- | --- |
| 已发布 v1 客户端 + 升级后服务端 | 原摘要/身份/注册/取钥不变；v1 事件可继续认证 |
| 新客户端 + 未声明能力的 v1 服务端 | 发 v1，不附带 evidence，不要求 v2 收据 |
| 新客户端 + 声明能力的服务端 | 解包校验成功后才产生 v2；四个向量摘要一致 |
| 未批准/错误封装/摘要不匹配 | 不产生首次授权标记和回调，不接受能力声明 |
| 本地对照包 | 无回调、无队列、无两条风险请求 |
| v1 队列尚未确认时升级能力 | 保留原正文和证明继续提交，不转换协议或更换 event_id |
| 修改任一证据字段、替换 token/安装身份 | 验签拒绝，不入有效事件、不执行规则 |
| v2 丢失收据后原报告重试 | 一个事件、一份处置和一次授权版本变化 |
| 历史 revoke，随后人工恢复 | 当前 approved、版本更高；旧收据不误封恢复会话 |
| v2 有效当前 revoke | 后续保护访问拒绝，服务端取钥拒绝；恢复并重启后重新取钥 |
| 旧包覆盖升级 | 同签名、业务数据保留，DEX/Native/资源读取与冷启动回归 |

服务端先双读 v1/v2，再仅对测试产物声明能力。停止声明只影响后续新事件；已经落盘的 v2 队列仍会重试，不能立即下线 v2 处理器或恢复不认识 v2 的数据库。客户端工具回滚也不会改写已经安装的应用。

本次软件回归采用 Android 真机真实 Keystore + 隔离 HTTPS 传输、Swift 真实 OAEP 状态机 + 软件 App Attest 替身，以及旧运行时覆盖升级夹具。它们不等于新后端公网联调；v2 后端启用和 iOS 真实 App Attest 证明仍需对应服务/团队环境。


## 本地执行记录（2026-11-19）

- Rust：Android 核心 267 项、Native 32 项、iOS 70 项、CLI 两组各 22 项及附加 4 项通过；既有忽略项不计为通过，Clippy 严格检查通过。
- Java：离线 57 项、设备批准 BYOS 61 项、Play 61 项通过；新增来源分类与“远程执行门关闭不转成前台强杀”回归。
- Android 真机：HONOR API 35 / 4 KB，两个协议仪器测试入口、零失败。使用真实不可导出 Keystore 密钥，覆盖 v1/v2 向量、证据篡改、错误能力不启用、升级不改写旧报告、原证明重试、过期撤销收据不误封、有效撤销后取钥及资源打开拒绝。
- 最终混淆 DEX/SO 真机 JNI 注册通过。旧运行时签名夹具覆盖安装到新运行时，两次冷启动、业务数据、DEX、Native 和 openFd 通过；测试夹具已卸载，没有替换手机录音应用。
- Swift 软件状态机：v1/v2 摘要、非法证据、错误封装不启用、旧队列原样重试、协商、旧状态防误封、撤销后清理租约及拒绝再次取得租约通过。iOS SDK 对不启用 freeRASP 的生成资源工程完整类型检查通过；真实 freeRASP 7.1.4 与 iOS SDK 的完整类型检查通过。
- 标准、设备批准、Play 四 ABI 及独立 API 19 资源重新构建；API 19 ELF 依赖/对齐检查通过，未把 API 35 真机结果算作 API 19 设备验收。离线/Play 分发 ZIP 不包含风险协议和风险路由，设备批准 ZIP 同时支持 v1/v2。
- CLI、MCP 和 macOS `.app` 已重新构建。构建和回归证据位于本机忽略目录 `target/risk-v2-evidence` 与 `target/risk-v2-*.log`。

真实 BYOS v2 联调、后台自动撤销规则与新界面尚未实施；iOS 真实 App Attest 仍需对应开发者团队和服务环境。此次没有修改线上 BYOS 策略，也没有让现有录音包自动切换协议。


## 跨资源组恢复与严格整数修复（2026-11-19）

上一轮防误封测试覆盖同一范围，未覆盖跨组。本轮补齐：资源组 B 已成功取钥版本 9 后，资源组 A 的旧撤销版本 8 不得阻断当前进程，也不得接受版本 8 的新授权。Android 与 iOS 的范围队列和事件正文保持独立，最大授权版本按服务与安装身份共享并原子持久化；首次读取时从旧范围状态迁移最大版本。新字段不进入事件正文、签名、注册或取钥请求。

Android 使用按原进程名隔离的私有 `shellsmith_risk_v1[_进程摘要]_auth` SharedPreferences；iOS 在原风险目录保存 `authorization-摘要.version`。只保存公开身份摘要与版本，不保存 IKM 或私钥。清理旧范围或重启不丢失独立版本记录；本地/Play 变体继续不链接上报实现，并清理旧授权版本状态。跨进程即时同步仍不属于本次保证。

iOS 在两个 HTTP 响应解析入口共用严格版本检查，再交给 Decodable。使用 Foundation 解析保留的 NSNumber 类型区分整数和浮点数，避免 JSONDecoder 将 `7.0`、`7e0` 接受为 Int；同时拒绝布尔、数字字符串、负数和超出 Int64 的值。0 和 2^63−1 均为有效边界。版本持久化失败时，新 v2 取钥不返回密钥；已验证的撤销仍先在当前进程生效，报告保留以便重试。

本轮不要求服务端新增字段或新路由，仍按服务端《风险证据 v2 与灰度接入》启用新 token 的灰度及产物信号规则。软件状态机、Android 真机和业务 APK 公网验收分别记录，不能互相替代。


本轮执行结果：Android 真机协议测试与 Swift 状态机通过跨组旧收据、重启防回退、旧范围版本迁移和严格整数检查；原签名业务 APK 完成公网 v2 事件、自动撤销、原报告幂等、撤销后 403、管理员恢复及两次冷启动。历史处置版本 4 保持不变，当前状态恢复为批准版本 6。9 秒录音、保存、播放通过，原有 28 份音频摘要不变，唯一新增测试录音移至回收站。事件、token 和具体客户签名材料只保留在本机忽略目录 `target/risk-v2-fix-live` 的验收说明与记录，不写入公开协议示例。真实 iOS App Attest 仍未验收。
