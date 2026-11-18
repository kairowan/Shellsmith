# 显式业务资源保护的当前实现

本文描述迭代分支已实现的 Android 设备批准链路，以及与 Swift 共用的容器。实施范围、后续任务和兼容门禁见[实施计划](android-ios-resource-protection-plan.md)。新增资源能力需要与密钥服务端的同名迭代分支同步验收。

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

当前资源编译上限为单文件 16 MiB、一次构建 64 MiB、最多 256 项。运行时默认在进程内保留最长 60 秒的资源组授权。授权失效、组密钥错误和密文认证失败均会使后续受控读取失败。读取时已经交给业务的数据由业务管理。

## 容器与交互

容器 `SSR1` 的头部依次为 4 字节标记、16 字节构建 ID、1 字节组 ID 长度及组 ID、1 字节资源 ID 长度及资源 ID、4 字节版本、8 字节原文长度。整数为大端序。正文依次存放 64 KiB 分片，末片长度由原文总长度决定。每个记录依次为 12 字节随机 Nonce、对应长度的密文和 16 字节认证标签。AES-256-GCM 认证数据为完整头部加从零起的 4 字节大端分片序号。

Android 签名载荷内的 `assets/shellsmith-resources/index.json` 记录版本、构建 ID、服务地址、组 token 和资源 ID 至组和版本的映射。组密钥留在服务端封存。构建会核对输出中所有组密文和索引的摘要，并搜索匹配的明文副本。签名报告重绑定时重新核验密文和索引。

注册、挑战和领取分别走 `/v1/resource-keys/register`、`/challenge` 和 `/fetch`。资源 token 按服务端应用身份、构建和组划定范围。挑战请求由已批准设备签名，挑战保留 60 秒并限同一设备使用一次。领取继续使用绑定请求摘要的 RSA-OAEP 响应信封。服务端通过不同域标识和资源 token 前缀强制分流。旧 Android DEXB v7 客户端继续访问 `/v1/keys/*`。

## 本轮证据与仍需准备项

| 项目 | 当前证据或所需操作 |
|---|---|
| 构建容器及双端解码 | Rust 生成的密文已由 JVM Java 与 macOS Swift CryptoKit 实际读取。互操作回归覆盖跨片、篡改、截断、额外尾部和授权失效。 |
| 旧、新服务共存 | 在独立 PostgreSQL 运行服务端既有 HTTP 冒烟和新旧接口的取钥回归，覆盖旧 IKM、挑战重放、错误资源组、跨接口取钥拒绝和撤销。 |
| 旧保护路径 | Android API 35 的 4 KB 真机、API 37 的 16 KB 模拟器分别通过现有严格模式端到端夹具。场景包括未加固基线、同签覆盖安装及缓存启动。签名夹具和摘要保存在本机 `target/resource-protection-device-evidence/`，用于后续重复检查。历史正式签名 APK 与新服务上的实际取钥仍待验收。 |
| Android 新链实际联调 | 需要隔离、证书受信任的 BYOS HTTPS 测试服务和专用测试应用身份。先部署服务端迭代代码，再用授权测试 APK 从原始版本覆盖升级，核验资源组注册、首次读取、到期、撤销和普通业务。 |
| iOS 发行链 | 当前交叉测试只验证 Swift 容器读取。App Attest 服务端、Xcode 工作副本资源接线和最终 IPA 仍需完成。真实证据需要接受 Xcode 许可、有效签名身份、可信 iPhone、历史测试 IPA 和相同应用身份的新版本源码。 |
| Play 与物理页大小 | 渠道需有可用 Play 内测轨道及授权测试应用的签名。物理 16 KB 测试需要系统报告 `16384` 的实际设备。模拟器证据单独记录。 |

复验容器互操作可运行 `cargo test -p shield-core --test protected_resource_interop -- --ignored`，要求可用 JDK 和 macOS Swift CryptoKit。Android 业务应用需用签名产物、真实服务和设备独立验收。各环境验证结果见[旧产物兼容检查](../process/test-checklist.md#保护能力升级的旧产物兼容检查)。
