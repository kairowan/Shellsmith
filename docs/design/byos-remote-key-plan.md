# BYOS 包外密钥实现与交付范围

BYOS 保留默认本地离线加固，并提供用户自建 HTTPS 服务的包外密钥模式。Shellsmith 不运营共享密钥服务。具体服务开发输入见 [HTTPS 密钥服务接入协议](byos-key-server.md)。

## 背景与边界

DEXB v6 的证书指纹、build_id、包裹 IKM 和派生逻辑都随 APK 交付，因此仓库白盒工具可以只用包内公开材料恢复载荷。既有 REA 验证只代表对应样本、方法范围和工具版本，不能转换成所有项目的还原成功概率。

BYOS 的 DEXB v7 从 APK 移除 IKM 包裹字段；每次进程加载必须经用户服务按显式选择的设备批准或 Play Integrity 策略授权后获取 IKM。虚拟化与运行时策略继续复用；本功能不承诺阻止授权进程中的 Hook、内存转储或解密 DEX 缓存提取。

## 实施时修正的约束

- **系统范围**：设备授权要求输入 APK minSdkVersion >= 24。API 24～30 的 AndroidKeyStore 依赖全局 Application，取钥期间暂时提供已 attach 的壳 Application，成功、拒绝、超时均恢复原状态；字段不可访问时失败关闭。Play SDK 1.4.0 自身要求 API 23，但壳的同步启动路径使用 API 29 的公开服务绑定 Executor，避免主线程等待与服务连接回调互锁，所以 Play 模式仍要求 minSdkVersion >= 29。默认离线兼容范围不变。
- **请求绑定**：随机 request_id 与端点、token、包名、证书、时间、授权方式和两份公钥一起哈希为 nonce；服务端验证设备签名及批准记录，或 Google 解码结果，并原子消费 nonce。
- **信任来源**：API key 只用于构建注册，必须由服务端预先绑定应用、最终签名、授权方式及发布策略。手机自报身份不能成为放行依据。
- **密钥来源**：BYOS 每次构建独立随机生成 32 字节 IKM，不由本机项目种子派生，不进入项目备份或报告。客户服务可适配自己的密钥库/KMS/HSM 封存 IKM，账号/签名/许可证用于授权；这些材料不能直接替代产物 IKM。构建机内存仍会持有当次 IKM。
- **运行时隔离**：设备授权资源无 Google SDK；Play SDK 仅进入专用 Play 资源，与离线/设备资源分开构建。仅保留 Classic 取钥路径，将依赖一起改名，并对输出残留公共 SDK 类名作失败检查。
- **缓存认证**：命中解密 DEX 缓存也必须重新取钥；没有 PVM2 的包也执行该检查。
- **头部认证**：v7 从 magic 到 payload_nonce 的完整头部作为 ChaCha20-Poly1305 AAD。修改端点、token、build_id 或其他头部字段会使解密失败。
- **现有兼容**：继续读取 v5/v6，默认新包仍生成 v6。v7 取钥失败无离线回退。
- **授权方式**：device_approval 使用 Android Keystore EC 签名和客户服务端批准；play_integrity 使用 Play 关联应用的 Classic API。没有默认 Play 必填、没有鉴权降级。本轮支持 GUI 与 CLI 的 APK 流程；AAB、iOS 和 API 19 BYOS 不在当前交付范围。
- **响应加密**：取钥协议 2 使用每次请求新的 RSA-2048 公钥，OAEP SHA-256/MGF1-SHA256 包裹请求摘要与 IKM，拒绝旧的明文 IKM 响应。设备授权只证明持有批准密钥，不证明应用版本或完整性。

## 实现清单

| 部分 | 实现与检查 |
|---|---|
| 核心打包 | `pack_byos`、共享明文载荷构造、独立 v7 头部与 AAD；v6 格式不变 |
| 连接检查 | GUI 草稿/已存配置调用只读 `/v1/keys/check`；HTTPS、凭据、模式/协议检查，结果脱敏；不注册 IKM、不写草稿 |
| 客户密钥后端 | 自有随机主密钥、KMS/HSM 均由客户 HTTPS 服务适配，主秘密不进入桌面/APK；连接检查识别固定的后端未就绪错误，成功响应与手机协议不变 |
| 注册客户端 | `ureq` 同步 HTTPS，标准 base64，禁止跳转，15 秒超时，响应长度/令牌校验，错误脱敏 |
| 核心流程 | endpoint/API key/auth 三项完整校验，专用 Runtime 能力验证，注册 IKM 后打包，报告区分交付模式 |
| GUI | 加固设置中新增/编辑/选择服务；设备授权默认无 Google 配置；API key 仅后端读取，整套配置 AEAD 加密保存，绑定独立随机本地密钥 |
| CLI | `--byos-auth`、`--byos-endpoint`、`--byos-api-key` / `SHELLSMITH_BYOS_API_KEY`、最终证书覆盖参数；凭据不进 TOML |
| Manifest | 最低系统检查，BYOS 能力标记、联网权限；仅 Play 模式增加商店可见性；不静默提高 minSdk |
| Java | 工作线程发起证明/HTTPS，设备授权适配 API 26～30 的启动上下文，Play 使用 API 29 服务回调，响应身份绑定，整个等待 8 秒上限，不保存 IKM |
| Rust/JNI | v7 严格解析，回调 Java 取钥，复用 HKDF 与 DEX/PVM2/资源/Native 派生，缓存路径同样认证 |
| 构建 | `make build-byos` 输出设备资源 `resources-byos.zip`，`make build-byos-play` 输出 `resources-byos-play.zip`，四 ABI；不会覆盖默认 `resources.zip` |
| 分发 | GUI/CLI 发布包包含离线、设备批准、Play 三套隔离资源；资源检查脚本核对实际 ZIP 的模式与 Google 依赖 |
| 白盒检查 | 识别合法 v7 后记录 `external_key_required`；未知版本或截断为检查错误，不作防护成功 |
| 服务文档 | 条件配置、设备批准/业务授权接入点、Google 结果验证、加密响应、防重放、吊销与联调清单 |

## v7 字节布局

所有整数为小端，字符串为 UTF-8（当前地址/令牌限定 ASCII）。

```text
magic(4 = DEXB) | version(u32 = 7) | dex_count(u32) | flags(u32)
| sig_len(u8 = 64) | signature(sig_len)
| build_id(16)
| token_id_len(u16) | token_id
| server_url_len(u16) | server_url
| payload_nonce(12)
| ciphertext_and_tag
```

v7 没有 wrap_nonce、wrapped_ikm 或明文 IKM。密文之前的全部字节为 AAD。载荷仍是原有压缩 DEX/可选 PVM2 容器，派生仍用 IKM、payload_nonce、证书指纹；修改端点或 token 后必须重新加固，不能只改头部。

## 验证要求

本地无需真实服务的检查：

```bash
cargo test -p shield-core -p shield-cli -p mocika-shield
cargo test -p shield-core v7_java_whitebox -- --ignored
MOCIKA_BYOS_RUNTIME=1 ./shield-stub/gradlew -p shield-stub testReleaseUnitTest
make build-stub build-byos build-byos-play
python3 tests/scripts/check-byos-resources.py
```

覆盖构建注册请求、错误/重定向拒绝、凭据脱敏、CLI 成对参数、SDK 门槛、nonce 跨语言固定向量、v7 三种压缩层的打包与真实 Rust 解析器往返、缓存无密钥失败、错误 IKM、v6 公开派生材料失效、头部与密文篡改、截断，以及 Java 白盒的合法/未知/截断格式分类。

**外部验收范围**：设备批准模式已完成原签名业务 APK 的真实 HTTPS 注册、批准取钥、风险 v2 上报、自动撤销、拒绝再次取钥及恢复启动，当前结果见 [风险事件联调记录](byos-risk-events-v2.md#真实联调验收2026-11-20)。该结果限定于实际测试的应用、设备和策略；Play 模式仍需真实测试轨道、Google 证明与配额验收。密钥丢失后的重批、网络故障、重放、延时与 ANR 按目标业务环境继续回归，APK 白盒检查本身不能证明服务器安全。

本地实现与回归的实际命令、结果记录在 [BYOS 本地验收记录](../process/byos-local-validation.md)。
