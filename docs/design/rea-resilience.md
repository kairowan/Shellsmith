# REA 分析抵抗：实施与验证

2026-10-19 修订。本文替代旧方案中未经通用兼容验证的全资源加密、业务 JNI 改名和随机魔数方案。

## 威胁模型

目标项目为 [morluto/rea](https://github.com/morluto/rea)，本轮固定 `rea-agents@6.7.0`。它编排 JADX、Native 分析引擎、资源工具和 adb，并已具备 [Frida 会话与脚本能力](https://github.com/morluto/rea/blob/rea-agents-6.7.0/docs/frida-instrumentation.md)。旧文档“不用 Frida、只能静态分析”的判断已失效。

保持通用离线加固、手机安装即用。软件自动管理本地项目材料，但手机执行所需的引导材料仍随 APK 交付。因此：

- 证书摘要是公开身份信息；更换密码算法、随机文件名或增加加密层数不能产生包外秘密。
- DEXB v6 的 APK 公开材料足以恢复载荷密钥。默认模式不承诺 APK 机密性。
- 解释器与应用同时交付，虚拟化只能提高分析成本。镜像解密、规范化字节码、等价方法重建、恢复原始源码是不同成果。
- 客户端完整性检查可以发现未经适配的修改，但不能在代码可任意修改时构成独立信任根。Android 系统验签与应用内部验签不是同一边界。

不针对工具名称拉黑、不向 AI 植入提示、不制造畸形 DEX，也不把分析器崩溃、工具缺失或超时计为防护通过。

## 已实施

### 收敛 Native 内部诊断

在所有调用共用的日志入口处理发布版 `PLOGE`：保留固定故障码 `P1`，移除方法编号、虚拟操作码、程序计数器、池与解析字段。解释器自己的 RuntimeException 和 SecurityException 分别使用 `P1` / `P2` 通用消息。

开发构建保留详细诊断。业务抛出的异常对象、异常类型、捕获顺序及 finally 行为按原语义传播。加固桌面端的逐方法失败报告保持可用。

同步将 `common/log.h` 纳入 Rust 构建的变更依赖，避免增量构建分发旧日志实现。Native 回归分别编译开发和发布实现，发布实现仍启用测试断言，并检查内部消息不进入二进制。

这项变更减少静态字符串与设备错误日志给分析者提供的线索，不改变密钥保密边界，也不代表阻止 Frida 注入或 Native 反编译。

### 修复离线恢复验收

`ApkRecoveryCheck` 原来只在完整 APK 路径接受镜像 v7/v8，而当前生产为 v9；自检走另一入口，未覆盖该问题。现在两个入口共用版本与结构检查，支持 v7～v9，未知版本必须明确失败。

检查覆盖报告中的全部已验证跳板与镜像，保留三种 ISA、随机映射、非法映射和未知版本反例。它使用仓库已有的公开格式知识，是白盒恢复检查，不能冒称 REA 自身已自动完成同样恢复。

### 建立实际 REA 回归

新增 `tests/scripts/check-rea-resilience.py`，读取授权 APK 与逐方法报告，校验输入/输出哈希后：

1. 使用 REA 搜索加固包内的业务类，要求引擎完整返回。
2. 仅用 APK 内材料执行白盒恢复，核对全部受保护方法的跳板及镜像。
3. 从加固 APK 与恢复 DEX 生成仅供静态分析的未签名包，不借用原包代码，不安装。
4. 使用 REA 对指定抽样方法分别读取原始方法体、恢复后的跳板，核对签名与报告中的保护范围。
5. 统计各 ABI 的已知内部诊断；可要求发布产物没有这些诊断和性能采样标记。

记录工具版本、JADX 哈希、APK 哈希、逐次原始 Evidence 和错误日志。工具失败、部分输出及未知版本返回非零，不能成为“抗还原通过”。`same_decompiled_text=false` 只表示文本不同；语义重建与动态注入默认明确标记未验证。

报告目录权限为仅当前用户可访问，包含业务标识和恢复代码，默认放忽略的 `target/` 下，不自动上传。

## 本轮验收结果

自有 Java/D8 样本，min API 26；对照为 1.8.5 正式产物。结果不代表所有客户 APK 或任意 Native SO。

| 项目 | 1.8.5 | 本轮修改后 |
|---|---|---|
| 所选/已验证 PVM2 方法 | 52 / 46 | 52 / 46 |
| REA 直接搜索业务类 | 0 命中，搜索完整 | 0 命中，搜索完整 |
| 白盒恢复镜像及核对跳板 | 46 / 46 | 46 / 46 |
| 四 ABI 壳库的本轮诊断特征命中 | 每 ABI 12 处 | 每 ABI 0 处 |
| REA 读取恢复 DEX 的三个抽样方法 | VM 调用跳板 | VM 调用跳板 |

两个构建的 46 个规范化指令摘要多重集一致，未观察到 VM 语义多样化增强。三个抽样方法覆盖字符串、嵌套异常和业务调用；不能据此宣称全部方法无法重建。

Native 开发/发布模式均通过 ASan/UBSan、JNI 执行、认证失败、解析失败、异常传播、缓存清理及并发回归。标准四 ABI 和独立 API 19 资源构建通过；本轮设备执行仅在 HONOR Android 15/API 35、arm64、4 KB 页大小上完成：5 个场景各 525 项检查，共 2,625 项，测试包已移除。未将其他平台的编译成功当作设备验证。

完整语义还原、真实 Frida 注入、Native 反编译成本和正式性能分布仍未在本轮验证；本轮没有“防住 REA”或保护代际提升的结论。

## 复现

需要 JDK 17、兼容的 Node 22.19 以上版本、本地 zstd、已构建的配套打包器及壳。研究工具安装到隔离目录，不运行 `rea setup`，不修改个人代理配置：

```bash
npm install --prefix target/rea-resilience/tooling --ignore-scripts --omit=optional \
  --no-audit --no-fund --registry=https://registry.npmjs.org rea-agents@6.7.0
```

按 [REA 的 Android 指南](https://github.com/morluto/rea/blob/rea-agents-6.7.0/docs/android-analysis.md) 下载 `jadx-headless-mcp-0.7.1-all.jar`。脚本强制验证 SHA-256 为 `6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75`。

```bash
make build-stub
make build-cli
python3 tests/scripts/check-pvm2-art.py --min-api 26 --output target/rea-art
python3 tests/scripts/check-rea-resilience.py \
  --rea target/rea-resilience/tooling/node_modules/rea-agents/scripts/rea.mjs \
  --jadx-jar target/rea-resilience/jadx-headless-mcp-0.7.1-all.jar \
  --input-apk target/rea-art/input.apk \
  --protected-apk target/rea-art/protected-signed.apk \
  --report target/rea-art/protected-signed.apk.protection.json \
  --output target/rea-check \
  --class-query CompatibilityActivity \
  --method 'dev.mocika.shield.pvm2regression.CompatibilityActivity.RulesView#text' \
  --method 'dev.mocika.shield.pvm2regression.CompatibilityActivity.RulesView#nested' \
  --method 'dev.mocika.shield.pvm2regression.CompatibilityActivity.RulesView#calls' \
  --require-private-diagnostics
```

`--output` 必须不存在，以防覆盖历史证据。检查其他授权项目时显式指定对应输入、产物、报告与无重载的抽样方法；不能把本样本覆盖率套用到其他 APK。

## 后续优化的准入条件

| 方向 | 复用现有能力与验收要求 |
|---|---|
| PVM2 方法与 Native 覆盖 | 按每个产物报告分母、成功数和跳过原因；二进制 SO 加密不能计为源码 Native VMP。扩展语义必须有原始执行与保护后执行对照。 |
| VM 语义多样化 | 用同一恢复器对多个构建比较规范化结果、恢复步骤与人工成本。现有条件反转试验仍能被复用规范化，不作为增强默认启用。 |
| 动态明文窗口 | 复用已有按需解密、必保方法退出清理、LRU 和实际加载库完整性检查。真实 Frida 测试需单独记录目标、版本、权限与观察结果；普通启动通过不能替代。 |
| assets 与业务 SO | 复用已有精确覆盖与跳过原因报告。模型、数据库、媒体、动态路径和 JNI 导出涉及 SDK/加载契约，不默认改写所有文件。 |
| 包外秘密 | 只作为用户自管服务或离线设备激活的可选模式；需要明确改变首次使用流程。当前默认安装即用模式不能承诺这一性质。 |

验收中保留“仍可静态恢复”的反例；不能因原脚本暂时失效、字节差异变大或特征串减少，就提高保护代际或宣称已防住 REA。
