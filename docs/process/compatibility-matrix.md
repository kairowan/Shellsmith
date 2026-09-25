# 融合项目兼容性矩阵

## Android 系统和 ABI

| 类别 | 最低覆盖 |
|---|---|
| API | 19、21、23、28、29、31、34、35、36 |
| 系统 | Android 4.4、5、6、9、10、12、14、15、16 |
| ABI | armeabi-v7a、arm64-v8a、x86、x86_64 |
| 页面大小 | 4 KB、16 KB |
| Native 打包 | `extractNativeLibs=true`、`extractNativeLibs=false` |

矩阵脚本只记录真实在线设备，不把历史文档或主机编译成功算成设备通过：

```bash
# 只盘点在线设备；报告不会写入 adb serial
ANDROID_HOME=/path/to/android-sdk \
  MATRIX_MODE=inventory \
  bash tests/scripts/run-device-matrix.sh

# 对每台在线设备运行项目 APK 端到端夹具；要求缺一格即失败
ANDROID_HOME=/path/to/android-sdk \
  MATRIX_MODE=e2e \
  MATRIX_PVM2_STRICT_TEST=1 \
  MATRIX_REQUIRED_APIS=21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36 \
  MATRIX_REQUIRED_ABIS=armeabi-v7a,arm64-v8a,x86,x86_64 \
  MATRIX_REQUIRED_VENDORS=honor,huawei,xiaomi,oppo,vivo,samsung \
  bash tests/scripts/run-device-matrix.sh

# 验证 bundletool 生成的 APKS split 安装；可选 MATRIX_COMPONENT 做启动检查
MATRIX_MODE=apks MATRIX_ARTIFACT=/path/to/protected.apks \
  MATRIX_BUNDLETOOL=/path/to/bundletool.jar \
  MATRIX_PACKAGE=com.example.app \
  bash tests/scripts/run-device-matrix.sh
```

`MATRIX_REQUIRED_*` 是发布门禁，不是声明生成器：缺少设备会返回失败。AAB 的条件/on-demand/fast-follow、功能模块 assets/lib 已有本地 AAB/APKS 结构证据，但尚未完成 Play 与真机生命周期格子；只有 install-time 子集具备现有双机运行证据。

## 应用类型

- 单 DEX、多 DEX。
- Java、Kotlin、协程、Lambda。
- AndroidX Startup、ContentProvider、Remote Service、多进程。
- ARouter、DataBinding、ViewBinding、反射和序列化。
- uni-app/DCloud。
- DJI MSDK。
- Huawei 目标 ROM。
- 大型第三方 Native SDK。
- 无 Native 库的纯 Java/Kotlin APK。
- AAB base module 和 dynamic-feature module。

## 生命周期

- 首次安装和首次启动。
- 二次启动和 warm start。
- 清缓存、清数据和缓存损坏恢复。
- 同签名升级、重签名失败、降级和回滚。
- 进程被杀、后台恢复和多进程启动。
- Debug、Root、模拟器和普通生产环境。

## 保护级别

每个样例至少验证 `Compat` 和 `Balanced`，Strict 只在目标设备明确支持时验证：

- 业务功能一致。
- 启动成功。
- 无新增 P0/P1 崩溃。
- 首次启动时间和 PSS 增量在发布阈值内。
- 失败时按策略降级，不产生半加载状态。

## 当前本机证据（2026-09-24）

| 设备 | API / 系统 | ABI | 页大小 | 本轮状态 |
|---|---|---|---|---|
| HONOR BRP-AN00 | API 35 / Android 15 | arm64-v8a、armeabi-v7a | 4 KB | strict/PVM2 v6 项目双 DEX 夹具通过；PAS2 Java/Native 读取和业务 `.so` 函数区域保护通过；dynamic-feature + install-time Asset Pack AAB 安装 3 个 Split，功能代码与 PAS2 Asset Pack 解密读取均通过 |
| Google Pixel 6a | API 36 / Android 16 | arm64-v8a、armeabi-v7a | 4 KB | 同一 strict APK 端到端链通过；dynamic-feature + install-time Asset Pack AAB 安装 3 个 Split，功能代码与 PAS2 Asset Pack 解密读取均通过 |

其余 Android 5～14、x86/x86_64、16 KB 页和其他厂商格子仍需设备或模拟器实际运行后写入证据。表中“4 ABI 业务 `.so` 已保护”描述 APK 产物结构；本轮两台设备实际执行的 ABI 都是 arm64-v8a，不能据此把 x86/x86_64 运行格子标为通过。

## iOS 工程与设备

| 类别 | 支持或门禁 |
|---|---|
| 输入 | 拥有源码与签名权限的 `.xcodeproj`、`.xcworkspace` |
| 最低系统 | iOS 13；最终下限以应用依赖及锁定包共同要求为准 |
| 工程类型 | SwiftUI、UIKit 应用 target；Objective-C 可接入 RASP，Swift Confidential 只处理 Swift |
| 构建主机 | macOS + 完整 Xcode；Windows/Linux 只做静态检查和配置编辑 |
| 架构 | 导出产物主可执行文件必须包含 arm64 |
| 签名 | Bundle ID、Team ID、Entitlements、Provisioning、codesign 严格检查 |
| 扩展 | Widget、Extension、App Clip 逐 target 配置和签名；当前自动接线仅处理主应用 target |

iOS 发布候选至少覆盖：SwiftUI/UIKit 各一套最小应用、development 与 App Store Connect 导出、真机冷启动/后台恢复、Debug 与 Release 响应差异、截图录屏、调试器、签名异常、越狱/Hook 受控样本、dSYM 上传，以及 App Attest 服务端正常/重放/断网路径。

### 当前本机证据（2026-09-24）

| 项 | 状态 | 证据边界 |
|---|---|---|
| Rust 核心与 Swift 包生成 | 通过 | `shield-ios` 17 项测试通过，生成的 `Package.swift` 可由本机 SwiftPM 解析 |
| CLI、Tauri 后端与 React 前端 | 通过 | Rust 工作区相关测试、TypeScript 生产构建和 ESLint 通过 |
| Xcode Archive / IPA / 真机 | 阻断 | 当前主机只有 Command Line Tools，未安装完整 Xcode；不得将静态测试记为 Archive 或设备通过 |
| freeRASP RootHide | 上游残余风险 | 上游 #41 所述闭源检测漏检不能由 Shellsmith 在外部修补，strict 需结合 App Attest 与服务端风控 |
