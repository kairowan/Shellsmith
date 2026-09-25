# PAS2 assets 保护

严格保护模式现已将 `assets/` PAS2 分块认证加密接入 Shellsmith 单 Stub。该能力提高 APK 静态分析和批量提取成本，但不代表能够阻止已控制应用进程的攻击者取得运行时明文。

## 采用的方向

- 严格模式默认处理被 Java 或业务 ELF 引用、且可安全代理读取的 `assets/` 文件；每个文件按 1 MiB 分片，每片独立 AES-GCM 认证。
- 加固端把常见 `AssetManager.open(String[, int])` 与 `openFd(String)` 调用改写到 Shellsmith 单 Stub。`openFd` 会先完成逐片认证，再原子写入按 APK 版本隔离的应用私有缓存并返回只读描述符，因此经该描述符进行随机读取或 mmap 仍可使用。
- DEX 字符串池中的精确路径和目录前缀都会参与选择，因此 `"voices/" + name` 这类常见动态拼接可覆盖该目录下的安全文件。
- 加固端还会有界扫描业务 ELF 中的静态资源路径，并生成经过认证的 Native 索引。被改写的 `Context.getAssets()` / `Resources.getAssets()` 会返回加入应用私有明文 ZIP overlay 的 `AssetManager`，覆盖常见 Java→JNI→`AAssetManager_open/openFileDescriptor` 交接路径。
- 每次构建使用独立密钥并绑定应用签名；APK 内不保留明文 assets 路径索引。
- DEX/JAR/APK/AAB、`.so`、数据库、字体和模型仍默认跳过；它们常由平台加载器、数据库引擎或第三方 mmap 路径直接消费，强制代理会降低兼容性。音视频可在检测到受支持读取路径时进入 PAS2，但必须用真实播放器回归 seek、并发和后台恢复。

## 不采用的首轮方案

- 不 Hook 系统 `AssetManager`；只改写当前 DEX 中可静态识别的 `open`/`openFd`/`getAssets` 调用。
- 无法从 DEX 或 ELF 静态字符串推导出路径/目录前缀的完全动态路径、反射调用、启动前缓存的 `AssetManager`、直接文件系统路径以及第三方自建资源容器不会被伪装成已覆盖。未进入 PAS2 选择集的文件保持原样。
- 不加密 Android 安装、资源索引、主题、布局或系统启动阶段必须直接访问的文件。
- 不把明文长期释放到公共存储；确需临时文件时只能使用应用私有目录并定义清理策略。
- 不复用 DEXB v5 表示资源载荷；资源格式必须独立版本化并失败关闭。

## 当前验收范围

1. PAS2 头、分片长度和每片认证失败均关闭读取。
2. 小文件与百兆级文件按固定上限流式解密，不一次性展开整个文件。
3. GUI 明确显示严格模式是否启用 PAS2。
4. `openFd` 缓存只在认证成功后发布，临时文件失败会清理；APK 更新后使用新的缓存目录。
5. 项目夹具已验证 Java 动态拼接 `openFd` 和 Java→JNI `AAssetManager_open`；仍必须用真实业务 APK 验证 WebView、Unity、第三方 Native SDK、目录枚举、seek/mmap 和多进程读取。

## 关键问题

- 大文件使用整块认证还是分片认证，如何避免可交换分片和回滚。
- 需要文件描述符、随机访问或 mmap 的第三方 SDK 如何接入。
- 多进程并发、进程重启和缓存清理如何保持一致。
- fast-follow/on-demand Asset Pack 已通过 `MocikaPlayDelivery` 提供流式读取、私有文件
  物化与安装后刷新；仍需真实 Play 下载、失败重试、升级和卸载证据。
- Android 4.4 与现代系统在文件映射、私有缓存和密钥派生上的差异。

## 验收与停止条件

- 未配置的资源完全不改变；配置资源无法从 APK 静态获得可用明文。
- 错签名、载荷篡改、分片错序和缓存损坏均失败关闭。
- 应用侧接口具备清晰的生命周期和错误语义，不要求业务依赖 ART 或系统私有 Hook。
- 性能按文件大小和访问模式可预测，不在主线程隐式解密大型文件。
- 若主要用户场景都依赖第三方 SDK 的原始文件路径且无法合理改造，保留调研结论，不进入正式实现。
- 所有 Asset Pack delivery 都必须通过模块级 PAS2 写回和 bundletool/APKS 校验；
  install-time 还需 split 真机读取，fast-follow/on-demand 还需 Play 轨道生命周期验证。

## 路线定位

PAS2 是严格模式的默认静态保护层，不替代服务端授权、设备证明或硬件密钥。普通 APK 遇到未覆盖的访问方式时保持原资源并报告跳过；任何 Asset Pack 或 dynamic-feature assets 则要求模块内每个文件都被 PAS2 覆盖，否则整次 AAB 构建失败关闭。
