# 融合项目 Issue 台账

> 本文件记录 Shellsmith 及保护依赖公开问题的处理口径。Issue 的“已关闭”不等同于融合后的代码已经完成回归；真机问题必须留到目标设备复现后关闭。

2026-09-24 已复核 XopProtector、Shellsmith、Swift Confidential 与 Free-RASP-iOS 的相关公开 Issues。下表记录本地处理方式；本地规避不代表上游 GitHub Issue 已关闭，且远端状态可能变化。

## XopProtector

| Issue | 分类 | 融合项目处理方式 | 当前状态 | 现有证据 | 完成条件 |
|---|---|---|---|---|---|
| #14 防破解效果/手机端咨询 | P2 预期管理 | 说明保护只能增加分析成本、不能保证不可破解；手机端不属于当前桌面产品范围 | 已明确边界 | README 安全声明；当前支持平台说明 | 文档保持一致，不做绝对防破解承诺 |
| #13 DJI 遥控器 Android 11 启动闪退 | P0 兼容性 | DJI MSDK、多进程、Native 加载和 Application 时序专项样例 | 未复现 | 仅有兼容性矩阵和单壳契约 | 真实设备安装、启动和主流程通过 |
| #10 华为 7.0 不适配 | P0 兼容性 | 收集完整堆栈和设备信息，增加厂商能力探测与回退 | 未复现 | 尚无设备日志 | Huawei 目标设备回归通过 |
| #3 Android 10 无法启动 | P0 兼容性 | API29 ClassLoader、文件权限和 DEX 顺序专项测试 | 未复现 | 核心单元测试通过，缺真机证据 | Redmi Note 9 及至少一台其他 API29 设备通过 |
| #11 加固后报毒 | P1 发布风险 | 减少固定特征，区分误报与真实风险，补充签名和发布说明 | 已接入待验证 | Stub R8/D8 资源包审计通过；DEXB v6 仅隐藏头部明文 IKM，不代表抗检测或抗运行时提取 | 目标杀软扫描结果、误报申诉记录和回归报告 |
| #12 兼容性咨询 | P1 文档 | 转换为公开兼容性矩阵和样例列表 | 已修复待验证 | `compatibility-matrix.md` 已建立 | 文档与测试矩阵同步 |
| #9 macOS GUI | P2 功能 | 使用 Tauri GUI 和 Universal DMG 发布路径承接 | 已接入待验证 | 前端 typecheck/lint/build 通过 | macOS `.app`/`.dmg` 烟测通过 |
| #8 Android 手机端工具 | P3 产品需求 | 不阻塞桌面稳定版，单独评估移动端架构 | 不在当前范围 | 计划明确不阻塞首版 | 需求评审通过后再排期 |

## Shellsmith

| Issue | 分类 | 融合项目处理方式 | 当前状态 | 现有证据 | 完成条件 |
|---|---|---|---|---|---|
| #129 Windows 找不到 keytool | P1 工具发现 | 除 PATH/JAVA_HOME 外，从已发现的 java.exe 同目录解析 keytool.exe | 已修复待验证 | 新增同目录解析单测；未在 Windows JDK 11 复现 | Windows 11/JDK 11 诊断与证书 Alias 查询通过 |
| #121 Fedora AppImage 窗口空白 | P1 桌面兼容 | Linux 启动时在用户未显式配置时设置 `WEBKIT_DISABLE_DMABUF_RENDERER=1`，规避 WebKitGTK DMABUF 渲染空白 | 已修复待验证 | Tauri 后端编译与测试通过；缺 Fedora 发布包实机 | Fedora 安装/启动、空白窗口回归与日志定位通过 |
| #117 dex2oat 缓存 | P0 回归 | 允许 oat/odex 目录存在，不将系统优化结果误判为污染 | 已修复待验证 | 缓存/运行时单元测试通过 | API26+ 二次启动不重复清缓存 |
| #2 16 KB 页面 | P0 发布兼容 | 检查 ELF LOAD 段、ZIP Stored、16 KB 对齐和所有 ABI | 已修复待验证 | 2026-09-23 使用 CI 固定 NDK r29 完成标准四 ABI 与混淆版重建；API19 使用 r25c/Rust 1.77.2；标准/API19 的 `PT_LOAD` 均通过 16 KB 审计，资源 ZIP 完整性通过 | 16 KB 设备安装和启动通过 |
| #109 uni-app APK | P1 兼容性 | 增加 uni-app/DCloud、资源和动态路由样例 | 未复现 | 兼容矩阵已登记，缺真实样例 | uni-app 主要流程通过 |
| #110 运行后 GDB/lldb attach | P1 安全增强 | 仅作为 Strict 策略可选能力，避免兼容模式误杀 | 已接入待验证 | Strict 在适配器未就绪时失败关闭；缺设备探针 | 可配置、可关闭、跨 ABI 回归通过 |
| #116 手机端加固工具 | P3 产品需求 | 不阻塞桌面版，单独评估移动端构建依赖 | 不在当前范围 | 计划明确不阻塞首版 | 需求评审通过后再排期 |

## Swift Confidential

| Issue | 分类 | Shellsmith 处理方式 | 当前状态 | 现有证据 | 完成条件 |
|---|---|---|---|---|---|
| #12 XCFramework Archive 出现重复产物 | P0 构建兼容 | 只允许把 Swift Confidential 接到应用 target；检测 framework 与 `BUILD_LIBRARY_FOR_DISTRIBUTION` 错误接法并阻断 | 已规避待验证 | 工程预检、已知问题检查和 project.pbxproj 接线单测通过 | 完整 Xcode 下 SwiftUI/UIKit Archive 通过，framework 错误样本被阻断 |

## Free-RASP-iOS

| Issue | 分类 | Shellsmith 处理方式 | 当前状态 | 现有证据 | 完成条件 |
|---|---|---|---|---|---|
| #55 SPM 无法集成 | P0 依赖解析 | 使用精确版本、本地 Package 直接依赖应用 target；Archive 前强制 `-resolvePackageDependencies`，失败关闭并保留诊断 | 已规避待验证 | 生成的 Package 清单可由 SwiftPM 解析；缺完整 Xcode 在线解析 | Xcode 干净缓存解析与 Archive 通过 |
| #17 动态 framework 被嵌入二级 framework 后无法发布 | P0 发布兼容 | 禁止向 framework target 接线，TalsecRuntime 只作为主应用 target 的直接依赖 | 已规避待验证 | target 类型门禁和 pbxproj 接线单测通过 | App Store Connect 上传验证通过 |
| #41 Dopamine 2 RootHide 未检测 | P1 残余风险 | 保留明确警告；`strict` 强制要求 App Attest 服务端地址，并将 RASP 作为风险输入而非唯一判据 | 上游限制 | 配置门禁与报告警告单测通过；freeRASP 为闭源二进制 | 上游修复并在对应越狱设备复测；修复前不得标为已解决 |

## 状态定义

- `未复现`：缺少 APK、设备、日志或构建参数。
- `已定位`：已确认根因，但还没有完整修复。
- `已修复待验证`：已有代码修复，等待设备或发布回归。
- `已验证`：自动化、目标设备和发布产物均通过。
- `不在当前范围`：功能建议或需要单独产品排期。
