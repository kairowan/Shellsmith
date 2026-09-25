# 融合版本发布验收

## 桌面产物

- Linux `AppImage`。
- Linux `.deb`。
- macOS Universal `.dmg`。
- Windows x64 `setup.exe`。
- 每个平台独立 SHA-256 文件。
- 版本号、架构、文件名和 Release 清单一致。

## Android 产物

- 输入 APK 已签名。
- 输出 APK 重新签名后可安装。
- 原签名绑定检查生效。
- `extractNativeLibs` 原值被保留。
- 16 KB ZIP/ELF 检查通过。
- 多 DEX、API19、API29、API31+、API36 样例通过。
- 加固前后主要业务流程一致。
- 缓存损坏、签名变化和协议错误能够明确失败或恢复。
- 首版只接受单一 Shellsmith Stub；检测到 Xop `assets/protector/*` 或 Shellsmith `MSHD`
  载荷时拒绝重复加固，避免两套壳嵌套。

## 安全和 AI 成本评测

- DEXB v6 头部不直接保存 IKM。
- `ai-resistance=off|balanced|high` 分别写入 DEXB v6 的 1/2/3 层压缩标志，运行时逐层认证解压；旧 v6 `flags=0` 必须保持单层兼容。
- 新包默认不使用旧 DEXB v5。
- 关键字符串不集中以明文出现在 DEX 中。
- PVM2/Hollow 的跳过和回退原因可诊断。
- 静态分析恢复关键业务语义的时间和准确率相较未加固基线提高。
- 运行时可直接获得的完整业务代码比例有记录。
- AAB 预检必须逐模块列出 base/dynamic-feature/Asset Pack 的 Manifest、DEX 与交付类型；
  `protect-aab` 必须通过模块变换、重建、upload key 签名和最终 bundletool `validate`。
  install-time dynamic-feature 与 Asset Pack 还需真实 split 探针；条件/on-demand/
  fast-follow 还需 Play 下载、刷新、卸载和升级探针，本地结构证据不得代替 Play 分发验证。
- `FusionPlan` 的 Xop 能力状态必须明确标记为 `xop-contract-only`、
  `xop-pvm2-embedded` 或 `xop-adapter-ready`。`xop-pvm2-embedded` 只代表 PVM2
  解释器共用 Shellsmith Stub/JNI/DEXB 生命周期，不代表 Hollow/Native SO/RASP
  融合已完成。

## 发布门禁

- P0 为零。
- P1 已修复、验证或具有书面降级方案。
- 声明矩阵全绿。
- Release 包安装和启动烟测全绿。
- 文档、版本、变更记录和安全说明同步更新。
