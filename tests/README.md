# 端到端回归测试

## 授权业务 APK 的限定范围验收

先保留原 APK，并从独立测试包名的同签名基线构建各配置。已有签名自检应保持原样；包名变更、第三方服务绑定以及未执行的登录/录音/网络流程须在报告中列明。不要用此测试替换手机上的正式应用。

`tests/java/dev/mocika/shield/acceptance/MethodProbe.java` 复用 Android 原生 Instrumentation，通过目标应用实际 ClassLoader 调用方法。将其编入外部同签名测试 APK，设置 `instrumentation.targetPackage`，在该测试 APK 的 `assets/cases.json` 放用例数组，例如：

```json
[{"class":"example.Calculator","receiver":"static","method":"add","types":["int","int"],"args":[1,2],"expected":3}]
```

接收者支持 `static`、公开无参 `constructor`、Kotlin `INSTANCE`；参数限 `int`、`long`、`boolean`、`String` 和标量包装值/空值形式的 `Object`，返回值限可直接比较的标量。只用于已审查的纯方法，不自动扫描执行应用方法。每例预热 1 次、顺序 20 次，再由 4 个线程各执行 20 次；结果通过 `am instrument -w` 返回。顺序计时包含反射与断言，不是单指令延迟，也不是正式业务 SLA。需要状态、副作用、异常消息/堆栈或浮点容差的路径使用业务测试。

每条用例必须且只能提供 `expected` 或 `expected_exception`。后者填写完整异常类名（例如 `java.lang.NullPointerException`），按被调方法真实抛出的异常精确比较，不把反射包装异常当作业务结果；正常返回或抛出其他异常均失败。

显式添加 `am instrument -w -e benchmark true ...` 可运行逐方法测量：每个用例另预热 100 次，执行 9 轮、每轮每用例 20 次，轮换方法顺序。输出 `method_benchmarks` JSON（完整方法签名、用例数、每轮调用数与原始纳秒数）及单独的 `benchmark_calls`，原有 `calls` 仍只统计功能回归。比较时固定用例、签名、编译状态和构建配置，重复独立进程；结果包含反射、循环及断言，异常用例也计入对应方法，不能直接作为生产调用延迟或业务 SLA。

`tests/scripts/measure-apk-acceptance.py` 接受多个 `--apk 名称=路径`、`--package`、完整 `--component`、`--serial`、`--adb`、`--aapt2`、`--apksigner` 和新建的 `--output` JSON 路径。只接受 `.shieldtest` 结尾的包名；验证每个 APK 的包名、签名，并确认设备已有测试包的字节摘要属于本次输入，再覆盖安装和清理该测试包数据。脚本不卸载应用。

默认每配置 30 次、每块 5 次，固定种子轮换；每块统一 `reset + verify` 编译状态并预热 3 次，每次停止后等待 12 秒，可用 `--interval-seconds` 明确修改。记录进程冷启动 `am start -W`、1 秒后主进程 PSS、温度、热状态与原始计时。没有正常冷启动时间、锁屏、过热、安装失败或进程消失会停止并保留部分记录，不填零、不静默重试。`UNKNOWN` 等计时失败应查看 `dumpsys activity exit-info` 和该包日志；厂商高频清理不是可直接算入成功的样本。使用新输出路径重跑，并保留失败记录。自检：

```bash
python3 tests/scripts/measure-apk-acceptance.py --self-test
```

启动失败、超时以及后续进程消失等错误，会在脚本最终强停之前尽力保存 `exit-info`、有限系统错误日志、独立 crash 缓冲区末尾 100 条日志、system_server 在 main/system 缓冲区的末尾 400 条日志与设备运行时间；即使没有重试预算也保留诊断。某条诊断命令失败不会覆盖原始错误，日志不清空。新增 `warmups` 保留每次预热，`first_after_clear=true` 单独标记清数据后的首次启动，不能与缓存启动样本合并计算。诊断日志可能含设备信息，仅保存在授权的本地报告中。

`launches` 在发起每一次启动前落盘，保留预热、采样及重试的身份、UTC 时间和宿主单调时钟，随后更新为 `measured` 或 `failed`；中断后仍为 `running` 的条目不能计为成功。启动计时成功也不代替后续 PSS/进程存活检查，正式统计仍以 `rows` 为准。单调时钟只用于同一次宿主开机内的间隔比较。

采样节奏必须先按设备校准，不能失败后静默调整。2026-10-15 的 HONOR Android 15 系统实现按用户、包名和进程累计创建次数，300 秒内达到 30 次会触发 `CrashClean`；原 5 秒间隔的未加固基线在最后 30 次创建跨越 270.075 秒时被清理。当前默认间隔改为 12 秒，并通过连续系统日志核对实际创建间隔；它不是其他厂商的通用安全阈值。各对照组必须使用同一预设间隔，保持零重试预算和系统策略。高频压力测试可以显式采用更短间隔，但应单独报告，不能与正常节奏的性能采样混为一项。

需继续部分记录时，先保留失败报告副本，再用完全相同的输入和参数加 `--resume`；脚本核对产物、设备和采样条件，只补未完成的分块。明确设置 `--max-invalid-starts 1..5` 才允许对没有 `TotalTime` 的 `UNKNOWN` 启动保存退出历史、冷却 30 秒并重试；预热与正式采样共享预算并分别标记。其他错误仍停止。发生过异常的完成状态为 `measured_with_invalid_starts`，只能表示补齐有效计时，不能表示稳定性验收通过。

恢复时的 `phase=previous_run` 条目也可能表示温控、锁屏等采样中断，须按 `error` 区分，不能把条目数直接当作启动失败次数。温控中断后保持原温控门槛，记录降温条件与时间，再按原参数恢复；未完成分块会重新清测试数据并预热。原失败快照保留，汇总须标注分段测量及重复预热，不能写成无中断通过。

`tests/java/com/yqsh/protector/packer/ApkRecoveryCheck.java` 复现 DEXB v6 的公开材料恢复边界，使用现有打包器依赖、JDK 17 和本机 `zstd`，不需要 keystore 或构建密钥：

```bash
javac --release 17 -cp tools/xop-pvm2-packer.jar -d target/recovery-check tests/java/com/yqsh/protector/packer/ApkRecoveryCheck.java tests/java/com/yqsh/protector/packer/Pvm2RuntimeImages.java
java -cp target/recovery-check:tools/xop-pvm2-packer.jar com.yqsh.protector.packer.ApkRecoveryCheck protected.apk new-recovery-dir /path/to/zstd protected.apk.protection.json
```

Windows classpath 分隔符改为 `;`。输出目录必须不存在。检查恢复 DEX、VM 镜像、产物绑定及完整跳板，并使用公开的指令布局将操作码、寄存器和立即数映射规范化。存在 PSO2 密钥表时，也尝试恢复其中列出的 ELF 函数区域，记录恢复文件摘要；需另与授权原 APK 对照。规范化结果一致只能证明这一层的分析可复用；语义恢复还需独立核验输入输出。耗时只记录已有检查工具的执行时间，不包括开发工具、阅读源码或黑盒分析时间。恢复结果含业务代码，仅保留在授权的本地输出目录。

## PVM2 必保方法清理与 v8 声明参数

`make test-pvm2` 验证 schema 2 报告及认证策略，`make test-pvm2-runtime` 用实际 Java 编译器/加密器生成三种 ISA 的普通、必保和异常镜像，再由生产 C++ 在宿主 JVM 中执行。断言覆盖普通缓存保留、必保方法正常及异常返回后的清理、递归和并发、认证失败不使用明文及阻断时的清理。

可空接收者不再因分支或异常区被静态拒绝。生产 JNI 对照覆盖两种接收者语义、三种 ISA 的 900 次正常与异常路径；结构检查仍拒绝损坏指令、非指令边界的跳转、错误载荷、越界调用寄存器及异常处理表。代码长度检查覆盖 4096/4097 个代码单元边界、数组载荷展开超过 65535 字节的拒绝，以及不丢失字符的 UTF-8 编码边界。

v8 追加经认证的参数类型表，包装对象按声明保留引用。v9 的 `invoke-super` 方法引用记录 `直接父类|原引用类型->方法签名`，类调用从声明父类分派，接口调用保留原接口；旧运行时因协议版本不匹配拒绝新镜像。新运行时仍能解析 v6/v7/v8，未知未来版本必须拒绝。必须一起重建打包器和标准壳资源。

`ANDROID_SDK_ROOT=/path/to/sdk python3 tests/scripts/check-pvm2-art.py --output target/pvm2-art --serial 明确设备序列号` 生成自有 Java/D8 整包，实际验证未加固基线、加固首次启动、再次启动、覆盖安装及装回基线。默认 46 个方法通过最终产物验证，每次执行 525 项断言，覆盖字段/数组/对象状态、调用、空值和异常、锁竞争、较大方法、字符串空字符/补充平面字符/驻留身份，以及祖先引用和派生接收者下的父类调用。`--min-api 26` 额外保留原生接口默认方法，默认 23 验证 D8 脱糖；`--without-resource-table` 验证无资源表。省略 `--serial` 只构建检查，不能当作执行通过。同一设备重复安装必须复用输出目录内的测试证书。

加载器复制优化的检查为 `shield-stub` 的 `testReleaseUnitTest` 与 `cargo test --manifest-path shield-stub/src/main/rust/Cargo.toml bin_loader`：前者检查完整 ZIP 字节及伪造长度拒绝，后者检查借用密文原地址、v5/v6 全部截断位置和原认证往返。`MOCIKA_RUNTIME_PROFILE=1` 的诊断构建可输出冷解密和缓存命中阶段的 Java/Native 堆分配观测；发布性能对照使用未启用诊断的资源，堆分配数也不等于 PSS 或泄漏结论。

同一显式开关也编入 Native 阶段计时：`MOCIKA_PVM2_PROFILE` 日志按 DEX/方法索引汇总，总调用数每增加 256 次输出一次；不输出业务参数、方法名或解密材料。`acquire_ns` 包含锁等待、`decrypt_ns` 和 `parse_ns`；`execute_ns` 包含 `resolve_ns`，`release_ns` 包含归还锁等待与清理，所以各列不能直接相加。递归调用的外层时间包含内层执行，表按进程汇总并限制为 1024 个方法；顺序阶段与并发阶段需分别解读。诊断计时本身有开销，发布资源必须取消开关重新构建并确认不存在该日志标记。

`MOCIKA_RUNTIME_PROFILE=1 python3 tests/scripts/check-pvm2-runtime.py` 在宿主检查阶段计时、嵌套作用域恢复及原有清理语义；普通命令验证不带探针的代码。检查还用 Java JCE 独立生成 73 组 AES-GCM/CTR 向量，覆盖空输入、块边界和大镜像，验证加解密及原地处理一致，以及错误密钥、nonce、密文、标签被拒绝且失败不写输出。GCM 另检查空密钥指针、输出容量不足和长度加法溢出被拒绝；轮密钥仅在单次调用内复用并清理，不设跨调用缓存。

## Native VMP 构建证据

`LLVM_CONFIG=/path/to/llvm21/bin/llvm-config make test-native-vmp` 构建当前 Pass，并运行
整数与 float/double 标量语义、常量传播阻断、响应文件、预包含、固定种子、同名内部函数和失败保留产物检查。`check-scalars.py` 生成 95 个函数，执行 1,556,480 次对照（包括 8/32/64 位 switch、共享出口和循环），同时检查公开材料恢复边界和 volatile 清理；可通过 `--cc` / `--serial` 在 Android 运行相同语料。
`native-vmp/tests/check-build.py` 可额外接收 `--library` / `--report`，验证实际 Android
ELF 的编译记录、解释器调用、剥离/归档匹配，以及代码/加载头篡改和旧工具记录拒绝。

`native-vmp/tests/check-device.py` 是仓库 `conditional_feature` 整数样本的设备执行检查，
需要明确的设备序列号、对应 ABI 的 NDK Clang、库及其构建报告。它在独立临时目录运行
1000 组返回值对照和 8 线程各 1000 次调用；不安装/卸载应用。构建报告本身始终保留
`execution=not_recorded`，成功的设备执行另写绑定摘要的记录。参数与边界见
[Native VMP 接入说明](../native-vmp/README.md)。

`cargo test -p shield-core native_vmp::tests` 无需 Android/LLVM 环境，覆盖四 ABI 的加载
指纹、符号剥离、截断/篡改、清单与 ABI 冲突、PSO2 输入输出和密钥表绑定，以及 ZIP
依赖按名称去重时仍能拒绝中央目录重复条目。完整核心/CLI 回归使用
`cargo test -p shield-core -p shield-cli`。

2026-10-14 的实际构建回归使用仓库样本，验证 Native 单独 APK、PVM2/PSO2 组合 APK、
最终签名与 7 模块 AAB；四 ABI 均绑定 SDK schema 2 证据。产物和失败检查日志在本地
`target/native-vmp-integration/`，其余构建日志为 `target/native-vmp-integration-*.log`。
这部分是构建/打包验证；后续单机执行记录见下文。

### Native 单机应用回归

仓库 dynamic-feature 样本通过 `-PfixtureApplicationId=dev.mocika.shield.featurefixture.nativevmptest`
设置独立包名。保持 Native SDK 构建参数，生成并安装对应基线/加固 APKS 后，显式启用
应用内检查（要求安装 `conditional_feature`，设备 API 至少 26）：

```bash
adb -s "$ANDROID_SERIAL" shell am start -W \
  -n dev.mocika.shield.featurefixture.nativevmptest/dev.mocika.shield.featurefixture.MainActivity \
  --ez verify_native_vmp true
```

`MocikaFeature` 日志须同时出现 `MOCIKA_DYNAMIC_FEATURE_OK`、`NATIVE_VMP_APP_OK calls=1000`
和 `MOCIKA_INSTALL_ASSET_OK`，并确认进程存活、无异常。`verifyNative` 会实际加载动态
模块中的库，逐项对照 JNI 返回值，失败抛出异常；只成功安装不能记为通过。

2026-10-14 在 HONOR BRP-AN00 / Android 15 / API 35 / 4 KB 上，ARM64、ARM32 独立
Native 探针各通过 9,000 次调用。ARM64 split 基线与 PVM2/Native VMP/PSO2 组合包各通过
3 次冷启动、3 次同进程重入，组合包还通过覆盖安装、清数据和全新安装检查。实际安装的
5 个 split 与 APKS 摘要一致，Native 库与 PSO2 表匹配保护报告。原始证据与启动观测位于
本地 `target/native-vmp-device/acceptance.md`，不代表其他设备或 Play 服务端交付已通过。

## APK 加固与签名

`fixtures/android-smoke-app` 是项目自有的最小 Android 测试夹具，只负责提供包含自定义 `Application` 和启动 `Activity` 的稳定输入 APK，不承载产品示例或业务功能。

`scripts/build-smoke-multidex.sh` 会把独立编译的 `SecondaryMarker` 写入 `classes2.dex`。`scripts/run-protect-e2e.sh` 以这个真实双 DEX APK 为输入，负责无设备回归链路：临时生成测试证书、签名原始 APK、执行加固、再次签名，并验证签名、MSHD 块、壳 Native 库、Manifest 保留、`NATIVE_INTEGRITY` 与各 ABI 壳库字节一致，以及 `check-apk` 结果。输入 Manifest 为 `extractNativeLibs=false` 时额外断言全部 `.so` 使用 `Stored`；为 `true` 时保留原压缩策略，设备回归覆盖解压副本路径。

```bash
make build-stub
bash tests/scripts/run-protect-e2e.sh
```

连接 Android 设备后，可以额外验证未加固双 DEX 基线，以及使用同一证书覆盖安装加固包后的首次解密和缓存命中二次启动：

```bash
RUN_DEVICE_TEST=1 bash tests/scripts/run-protect-e2e.sh
```

普通非 Root 设备可额外执行严格环境策略回归，确认高置信 Root 检测不会误报：

```bash
ENVIRONMENT_POLICY=strict RUN_DEVICE_TEST=1 bash tests/scripts/run-protect-e2e.sh
```

已通过 `adb root` 获得 Root ADB 的 LineageOS 等设备，应要求严格策略拒绝加固包启动：

```bash
ENVIRONMENT_POLICY=strict EXPECT_PROTECTED_REJECTION=1 RUN_DEVICE_TEST=1 \
  bash tests/scripts/run-protect-e2e.sh
```

存在多个在线设备时通过 `ANDROID_SERIAL` 指定目标设备。测试证书只在系统临时目录中生成，脚本退出时自动清理，不向仓库提交任何私钥。日常 CI 不启动模拟器；真实运行时回归由维护者在真机或指定模拟器上按需执行。

## API 29+ 内存 DEX 加载探针

`fixtures/android-memory-loader-probe` 是隔离研究夹具，不进入正式 Stub 或资源包。它把 Application、Activity、Service、Provider 和跨 DEX 依赖编译到两个独立 DEX 资源中，并分别构建反射写入 `LoadedApk.mClassLoader` 与公开 `AppComponentFactory.instantiateClassLoader()` 两种入口进行对照。

连接 API 29 及以上设备后执行：

```bash
bash tests/scripts/run-memory-loader-probe.sh
```

脚本会依次安装两个变体。两者都必须确认主进程与远程 Service 进程分别创建业务加载器，Application、Provider、Activity、Service、Receiver 与第二 DEX 类均正常创建，APK 内 Native 库可以通过业务类加载，并且 GC 后仍可首次访问延迟类；应用私有目录不得生成完整 DEX 文件。

工厂变体先由 `AppComponentFactory` 返回未初始化的稳定代理，确认业务类在获得 Context 前不能加载；随后在壳 Application 的 `attachBaseContext()` 中创建真实内存加载器并挂接代理。测试同时验证重复初始化不改变加载器、两个线程并发首次加载业务类，以及载荷中的原应用工厂收到五类组件实例化回调。该结果只证明最小框架链路可行，不代表正式 Stub Native、DEXB v5 签名绑定解密、原工厂元数据、ARouter、系统共享库、覆盖安装或生产回退已经通过。

当前已通过 API 29 ARM64 4 KB、API 35 ARM64 16 KB、API 36 ARM64 4 KB 模拟器和 API 35 ARM64 真机。探针 Native 库显式生成 SysV/GNU 双哈希表并按 16 KB 最大页大小链接，防止测试资产自身在 16 KB 系统中先于内存 DEX 验证失败。

完成上述框架探针后，可在 API 29 以上设备验证正式 Stub Native 与 DEXB v5 签名绑定解密：

```bash
BUNDLETOOL_JAR=/path/to/bundletool.jar \
  bash tests/scripts/run-memory-loader-dexb-probe.sh
```

该脚本要求已执行 `make build-stub`，并通过 `BUNDLETOOL_JAR` 指定本机 bundletool。它使用项目核心加固流程和临时证书生成真实 DEXB v5 双 DEX 载荷，把正式 `libmocikashield.so` 装入工厂变体，并验证同签名时主进程、远程进程和全部业务生命周期正常且私有目录无 DEX；随后验证同签名外部 Instrumentation、设备 split 集安装和异签名失败关闭。动态特性代码会由 bundletool 合入安装时 master split，脚本会确认代理能够访问该类，同时确认该类仍以明文 DEX 存在。因此这里只证明 split 运行兼容，不能宣称代码 split 已获得保护。所有证书和中间 APK 都只存放在系统临时目录，退出时自动清理。

当前正式 Native/DEXB 链路已通过 API 35 ARM64 真机；其他 API 节点仍沿用框架明文载荷矩阵，不能据此宣称正式解密链路已覆盖全部系统版本。

正式候选资源的系统边界使用独立端到端脚本验证。产物准备脚本会用同一临时证书生成标准资源、正常内存候选和同身份预算超限候选的真实双 DEX 加固包；64 位超限变体只在签名前把候选 Manifest 的 DEX 总量改为 384 MiB 加 1 字节。另一个变体改为 64 MiB 加 1 字节并移除 64 位壳库，在支持 `armeabi-v7a` 的 API 31 以上设备验证真实 32 位进程。两者都不向生产代码加入测试开关。设备脚本检查原组件工厂五类回调和主/远程进程，并按设备系统版本自动断言：API 28～30 使用认证文件缓存且不生成内存状态，API 31 以上生成分进程认证状态且不落盘明文 DEX。

```bash
ANDROID_SERIAL=emulator-5554 bash tests/scripts/run-memory-runtime-e2e.sh
```

API 31 以上还会依次验证真实 32 位进程的 64 MiB 上限、64 位预算超限选择文件路径并写入 `file_ready`、同身份正常候选覆盖后重新选择内存路径并写入 `memory_ready`、清除数据、标准与候选资源双向覆盖迁移、真实 Application 异常后的认证文件回退、文件路径连续失败、主/远程进程状态隔离、状态 MAC 损坏、包装密文损坏和 Android Keystore 条目删除。脚本兼容系统自动重试和等待显式重启两种行为。

连续验证多个设备时，首次执行完成构建后可以设置 `SKIP_BUILD=1` 复用仓库构建产物；每次仍会重新生成临时证书和三种测试包，不在仓库留下密钥或 APK。`prepare-memory-runtime-e2e-apks.sh` 只负责同签名测试产物，`run-memory-runtime-e2e.sh` 只负责编排设备状态和断言。

真实 32 位预算节点已在支持双 Zygote 的 API 35 ARM64 真机通过：测试 APK 移除 64 位壳库后由 `armeabi-v7a` 进程运行。当前 macOS ARM64 环境只有 API 19 的 32 位 ARM 系统镜像，无法用它验证 API 31 内存边界，因此不额外维护不可执行该路径的旧系统模拟器。

性能门禁使用相同的标准/候选双 DEX 产物，预热初始化后分别采集奇数轮稳态冷启动、主/远程进程即时 PSS 和统一整理后的 PSS。默认采集 7 轮并把原始样本保存到 `target/test-results/`：

```bash
ANDROID_SERIAL=device-serial SKIP_BUILD=1 \
  bash tests/scripts/measure-memory-runtime-performance.sh
```

为减小固定顺序带来的温度和后台负载偏差，应在同一设备再执行一次反向顺序，并分别保留结果：

```bash
ANDROID_SERIAL=device-serial SKIP_BUILD=1 VARIANT_ORDER=memory-first \
  PERF_OUTPUT=target/test-results/memory-runtime-performance-reverse.tsv \
  bash tests/scripts/measure-memory-runtime-performance.sh
```

结果只代表当前设备与测试载荷。脚本不向生产 Stub 注入计时日志，不以单轮数据或跨设备绝对数值判断性能。

使用真实、已签名的 AndroidX/ARouter APK 验证原组件工厂恢复和三种安装状态：

```bash
bash tests/scripts/run-memory-loader-arouter-probe.sh \
  /path/to/arouter-signed.apk \
  /path/to/sign-apk.sh
```

签名脚本接口固定为 `<输入 APK> <输出 APK>`。脚本会先用该证书重新签名原始样本，确保未加固基线、认证文件路径和内存加载原型能够同签名覆盖；随后保留样本资源、Manifest 组件、Native 库和 ARouter 路由清单，验证 AndroidX 原组件工厂、正式 DEXB v5 解密及 `/home/main` 路由。当前样本在 API 35 ARM64 真机的文件到内存、内存到文件、再次切回内存、清除数据和全新安装场景均通过。

性能阶段使用不自动路由、不预加载首页类且不开启观测日志的独立 APK，分别采集三种形态的五次冷启动、即时 TOTAL PSS 和统一内存整理后的稳定 PSS 中位数。诊断 APK 单独输出读取、解密、直接缓冲区复制、加载器创建及启动后 GC 快照，并用弱引用确认临时载荷对象是否回收。结果只代表当前设备和样本，不作为跨设备性能承诺。脚本是隔离原型，不生成正式发布资源。

脚本还会构建两个故障注入变体：第一个使内存路径在业务 Application 启动前崩溃，验证下一独立进程进入认证文件回退且后续保持粘性；第二个继续使文件路径失败，验证遗留 `file_pending` 状态会在再次启动时失败关闭。脚本还会同时启动主进程与远程进程，确认两者使用独立认证状态且不会互相误判；随后分别破坏状态记录、删除包装密钥材料和损坏包装密文，确认均在业务类定义前失败关闭。认证记录绑定加密载荷身份和进程身份，HMAC 软件密钥由 Android Keystore 分进程包装。该状态机仍只属于隔离探针，不会写入正式 Stub 或资源包。

## Android 4.4 Native 加载探针

`fixtures/android-api19-native-probe` 只负责验证 NDK r25c、Rust 1.77.2、API 19 构建的生产 `libmocikashield.so` 能够被 Android 4.4 的动态链接器加载，并成功执行 `JNI_OnLoad` 动态注册。它不包含 DEX 解密、Dalvik 注入或业务兼容逻辑。

先启动一个 API 19、`armeabi-v7a` 的模拟器或设备，再执行：

```bash
bash tests/scripts/run-api19-native-probe.sh
```

脚本会重复执行 Native ELF 审计、构建探针 APK、安装并启动，然后检查 `MOCIKA_API19_NATIVE_OK` 日志。存在多个在线设备时通过 `ANDROID_SERIAL` 指定目标设备。

完整 Dalvik 加固回归使用双 DEX 测试 APK，验证 Native 解密、Element 前插、自定义 Application、第二 DEX 类、首次安装、清除数据和同签名覆盖安装：

```bash
ANDROID_SERIAL=emulator-5554 bash tests/scripts/run-api19-protect-e2e.sh
```


### 通用 PVM2 方法保护

`make test-pvm2` 从仓库源码编译打包器，再动态生成多个 DEX 测试精确方法选择、重载、模块边界、非连续索引、完整跳板验证和密文篡改拒绝；无需私人业务 APK 或新增测试框架。`cargo test -p shield-core protection_report` 覆盖清单校验、最终 APK/AAB DEX 比对与报告绑定；宿主检查不能代替 Android 上执行虚拟化方法的语义和性能测试。

### PVM2 运行时生命周期

`make test-pvm2-runtime` 使用 JDK 17、Clang 和 C++20 在 Linux/macOS 上编译生产解释器，运行 ASan/UBSan 缓存并发、明文生命周期、阻断检查，并执行 Java 编译器生成的三种 v6 ISA 镜像。可用 `PVM2_SANITIZER=thread python3 tests/scripts/check-pvm2-runtime.py` 检查竞争。宿主 JVM 不代表 Android ART/设备检测验收；完整性校验单测位于 `shield-stub` 的 `testDebugUnitTest`。
