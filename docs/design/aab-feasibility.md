# AAB 加固可行性结论

本文档沉淀 AAB 模块加固实验的验证结论、适用边界和正式发布门禁。CLI 已具备单 base、install-time/条件/on-demand dynamic-feature，以及 install-time/fast-follow/on-demand Asset Pack 的本地变换链；本地通过不代表 Google Play 服务端分发已经验证。

`protect-aab --engine mocika` 先用 bundletool 生成仅含 base 的 APK，再执行 Shellsmith 单 Stub 加固。所有 dynamic-feature DEX 会暂存到同一 PVM2 变换中，共享构建密钥和全局 DEX 编号后写回原模块；模块 assets 会暂存到同一 PAS2 变换，独立 Native 库会暂存到同一 PSO2 变换，只有全部目标生成密文后才删除明文并写回。最后由 aapt2/bundletool 重建、用 upload key 签署并校验 AAB。fast-follow/on-demand Asset Pack 还要求 `--play-delivery-adapter`；`--engine xop` 仍只支持单 base，Instant App 和 dynamic-feature `root/` 文件继续失败关闭。

产品交付目标已明确为“可上传 Google Play 的受保护 `.aab`”。生成 universal APK/APKS、仅检查 AAB，或把 APK 改名为 AAB 都不满足该目标。正式交付需要在 AAB 模块边界完成变换、用用户配置的 Play upload key 签署，并以 Google Play 应用签名后的实际分发 APK 做验证；当前 CLI 只能报告“本地 bundletool/设备校验通过”，GUI 尚无 AAB 加固入口，不可宣称已完成 Play 分发验证。

## 实验目标

实验优先验证现有 DEXB v6 是否可以穿过 AAB 到设备 APK 的转换链路，并确认现有壳加载方案在拆分安装场景中的基础可行性：

1. `base/dex/classes.dex` 的 DEX 头部 `file_size` 之外追加载荷，经过 bundletool 生成拆分 APK 和通用 APK 后是否保留。
2. 单 base 模块能否复用现有 DEXB v5、混淆 Stub DEX、Native 解密和 `PathClassLoader` 注入链路。
3. ABI 配置 APK、dynamic-feature、install-time Asset Pack、多 DEX、覆盖更新、清除数据和错误签名拒绝是否符合预期。
4. AAB 上传证书、Play 应用签名证书与本地测试证书之间需要怎样的签名绑定边界。

## 已验证结论

实验环境使用 bundletool 1.18.3，并在 Android 15/HONOR 与 Android 16/Pixel arm64 真机完成运行验证。当前证据是本地 upload key 绑定，不是 Google Play App Signing 证据。

### DEX 尾部载荷保真

- AAB 中 `base/dex/classes.dex` 的 DEX 头部 `file_size` 保持原值，固定实验标记追加在物理文件末尾。
- bundletool 默认拆分 APK 集、通用 APK、重新 JAR 签名后的 AAB 和设备实际安装的 base APK 均保留尾部标记。
- bundletool 的设备选择、安装和 Android 包管理器安装过程没有清理 DEX 头部声明范围之外的载荷。

该结果证明现有尾部容器可以通过本地 bundletool 链路，但不能据此推断 Google Play 服务端一定采用相同行为。

### DEXB v6 与 strict 运行链路

- 正式 `shield-core` packer 生成的 DEXB v6 可以追加到单 base 模块的 Stub DEX。
- bundletool 生成并安装设备 APK 集后，Native 库能够从对应 ABI 配置 APK 加载。
- 壳 DEX 不包含原始业务 Activity；运行时完成解密和 DEX 注入后，原始 Activity 可以正常启动。
- 强制停止后再次启动、清除应用数据后重建缓存均正常。
- 最终 APK 使用错误证书签名时，运行时按预期拒绝解密；恢复绑定证书后可以正常启动。
- strict 夹具在单 base AAB 上完成 PVM2、PAS2 Java/Native 读取、资源路径改写和 4 ABI 业务 `.so` 保护；设备安装 2 个 Split 后，主进程、Native 探针、动态 `openFd` 和远程服务均成功。
- 重建 AAB 时先用 `bundletool dump config` 把二进制 `BundleConfig.pb` 转为 build-bundle 所需 JSON；不能把 protobuf 直接传给 `--config`。
- 业务 `.so` 可能位于 ABI split，运行时会同时检查 `sourceDir` 与 `splitSourceDirs`，再从匹配 split 解密到应用私有目录；只检查 base APK 会导致加密指令直接执行。

### dynamic-feature 与 Asset Pack

- 代码功能模块与 base 在一次 PVM2 变换中处理，变换后的 DEX 写回原模块；构建报告会分别给出 dynamic module 数量。
- install-time、条件和 on-demand dynamic-feature 都保留原 delivery Manifest；功能模块的独立 assets/lib 分别进入 PAS2/PSO2 后写回原模块。
- Asset Pack 接受 install-time、fast-follow 和 on-demand。后两者只有在调用方显式声明 `--play-delivery-adapter` 时才允许生成。
- Asset Pack 的资源与 base 共用 PAS2 派生密钥。原始资源条目必须消失，写回条目必须以 `PAS2` 开头；任一文件因路径未引用、格式跳过或冲突而未加密时，整个任务失败。
- 组合夹具经 bundletool 1.18.3 校验后，在 Android 15/HONOR 和 Android 16/Pixel 上均安装 3 个 Split；动态功能方法执行和 Asset Pack 解密读取日志均通过。
- 扩展夹具包含 3 个 dynamic-feature、3 个 Asset Pack、条件/on-demand/fast-follow delivery、功能模块 assets 和四 ABI 独立 `.so`；受保护 AAB 通过 bundletool 校验并成功生成对应 APKS，明文资源均消失，delivery Manifest 保持不变。
- 扩展夹具还在 NDK 29 编译阶段把功能模块中的一个纯整数业务函数转为 `.mocika.vmp` 字节码，再叠加 PSO2；这是 Android ELF/AAB 结构证据，尚不是 deferred 模块真机执行证据。
- 真实设备证据目前仍只覆盖本地 install-time 分发，不覆盖 Play 内测、条件触发、按需下载、卸载或更新。

### ABI、多 DEX 与覆盖更新

- 四种 ABI Native 库由 AAB 模块的 `jniLibs` 在构建阶段提供，bundletool 会生成独立 ABI 配置 APK；arm64 设备只安装对应的 arm64 配置。
- 业务 `classes.dex` 与 `classes2.dex` 均可进入同一 DEXB v5 载荷并在运行时成功加载。
- 使用同一证书从较低 `versionCode` 覆盖到较高版本后，版本隔离缓存能够重建，应用继续正常启动。
- Native 库必须在 AAB 模块构建阶段纳入，不能沿用“生成 AAB 后再注入 Native 库”的做法。

## 尚未验证的门禁

以下项目未完成，因此不能把本地模块链宣传成“所有 AAB 场景均支持”：

- Google Play 内部测试轨道是否保留 DEX 尾部载荷。
- Play 应用签名证书绑定，以及上传证书与设备最终证书的配置流程。
- on-demand/条件 dynamic-feature 的真实下载、安装、卸载和更新生命周期。
- fast-follow/on-demand Asset Pack 的 Google Play 服务端下载、失败重试和升级生命周期。
- dynamic-feature 内 assets/lib 在主流厂商真机上的安装后刷新与 Native 加载。
- Instant App、第三方应用商店转换链路和 GUI AAB 入口。

`protect-aab` 已覆盖上述模块的本地 CLI 变换、bundletool 校验和 APKS 生成；install-time 子集另有两台设备安装启动闭环。延迟模块由稳定 `MocikaPlayDelivery` API、可选 Play 状态监听以及 Split 安装后的 assets/Native 刷新承接。GUI 尚未提供 AAB 入口。超出契约的模块会在入口或模块变换阶段拒绝，不生成部分受保护、部分明文的 AAB。真实业务 AAB 与 Google Play 内部测试轨道仍未验证。

## 正式支持边界

AAB 是发布格式，设备实际安装的是由 Google Play 或 bundletool 生成的 base APK、配置 APK和功能模块 APK。AAB 通常使用上传密钥签名，而设备 APK 使用 Play 应用签名密钥。因此，APK 流程中“从输入文件提取当前证书并绑定 DEXB 密钥”的策略不能原样复用。

正式方案至少需要：

1. 允许用户配置并校验 Play 应用签名证书 SHA-256 指纹。
2. 为本地 bundletool 测试和 Play 分发建立明确、互不混淆的证书模式。
3. 在模块构建阶段生成 Stub DEX、Manifest 和 ABI Native 库，而不是事后修改已生成 AAB 的模块结构。
4. 按 base、install-time、条件/按需和 Asset Pack 交付模式建立独立测试矩阵。
5. 验证 Google Play 服务端产物后，才能在 GUI、CLI 和用户文档中声明正式支持。

## 后续版本规划

AAB 正式支持规划为 `1.5.0` 独立主题版本，不并入 `1.3.0` 的运行时安全收尾，也不与 `1.4.0` 的内存 DEX 生产化混合。

建议阶段：

| 阶段 | 目标 |
|------|------|
| `1.5.0-alpha.1` | 建立单 base 模块正式加固流程、Play 签名指纹配置和本地 bundletool 端到端测试 |
| `1.5.0-beta.1` | 完成 Google Play 内部测试轨道、四 ABI、单/多 DEX及覆盖更新验证 |
| `1.5.0-rc.1` | 冻结输入输出协议和 GUI/CLI 行为，只修复阻塞缺陷 |
| `1.5.0` | 在 Play 产物和发布矩阵全部通过后提供稳定支持 |

当前本地工具范围包括单 base、install-time/条件/on-demand dynamic-feature 和三种 Asset Pack delivery；其中延迟交付只具备代码、AAB、APKS 和运行时适配器证据，尚未进入稳定 Play 兼容声明。Play 内部测试上传及轨道发布属于外部账号操作，必须由项目所有者执行或明确授权，不能用本地 bundletool 结果替代。

条件/按需模块和 fast-follow/on-demand Asset Pack 是否进入稳定范围，应依据真实业务接入与 Play 轨道证据确定；不得从 install-time 本地结果外推。
