# XopProtector 分支差异审计（2026-10-23）

**状态：** 仅审计，不合并、不改代码、不删除上游目录。本文记录本地分支与 `origin/main` 的真实基线、冲突面和逐项裁决，供后续决定「合入、上游 PR 或归档」。

## 基线

| 项目 | 值 |
|---|---|
| 本地 `HEAD` | `e408b87`（2026-09-19，`增强PVM2 / 支付 True-VMP,适配Android16,增强SO 保护`） |
| `origin/main` | `4a41d0b`（2026-10-20，合并 shadowhook 2.0.1） |
| 本地与远端关系 | 本地 `main` 落后 `origin/main` 5 个提交 |
| `e408b87..origin/main` | 36 个文件，`+5657 / -692` |
| 本地未提交工作区 | 22 个文件，`+1614 / -237` |

## 远端 5 个提交的主题

```text
4a41d0b Merge pull request #21 from ouchangxin/feature/upgrade_shadowhook_2.0.1
08f940f 升级shadowhook框架版本到2.0.1
3cefb55 SO 加载策略调整（L2e 为主），Dobby ARM64 重定位增强，16KB 页对齐
5990c31 更新版本为0.7.2
7b18e91 修改SO冷启动策略，避免 attach 全表 RC4 和体积误判 L2e
```

主要改动集中在 SO 保护与加载链路：`business_so.cpp`、`BusinessSoProtector.java`、Dobby ARM64、`elf_util`、`NativeLibDirRedirect`、`p4-so-ab-matrix.ps1`。这不是一条 PVM2 格式升级线。

## 本地未提交 diff 的冲突面

本地未提交的 22 个文件里，与 `origin/main` 已改动文件重叠、不能直接 rebase 的至少有：

- `build.gradle.kts`
- `native/src/main/cpp/dex/dex_file.cpp`
- `native/src/main/cpp/vm/pvm2_format.cpp`
- `native/src/main/cpp/vm/pvm2_format.h`
- `packer/.../BusinessSoProtector.java`
- `packer/.../PackerMain.java`
- `packer/.../TrueVmpTrampoline.java`
- `packer/.../elf/ReadElf.java`

其余本地改动（`AssetsEncryptor`、`AutoVmpPolicy`、`Pvm2Compiler`、`Pvm2Morph`、`Pvm2Opcodes`、`ResPathObfuscator`、测试和 `settings.gradle.kts`）需要逐项对照，不能按「22 个文件整体 rebase」处理。

## 逐项裁决

| 项目 | 事实 | 裁决 |
|---|---|---|
| 本地 PVM2 v6 | 本地 `pvm2_format.h` 在 V5 后新增 V6；`origin/main` 只到 V5；`third_party/xopprotector` 已支持 V6–V9 | **先做语义对照**：把本地 v6 的寄存器置换、10 字节 handler、三变体 dispatch 与 third_party 的 v6–v9 逐项比较。若只是重复实现，丢弃并在 third_party 补齐仍缺的 dispatch 密钥流；不要先假定是独有能力 |
| `find_class_desc` contextClassLoader | `third_party` 已有 `forName` + `contextClassLoader`，并用 `string_from_utf8` 处理 MUTF-8；本地仍用 `NewStringUTF` | **丢弃本地这条**。third_party 已领先，不存在「third_party 未必有」的问题 |
| `dex_file.cpp` SHA-1 溢出 | `origin/main` 仍是 `size_t bit_len`；本地改为 `uint64_t`，修复 32 位 ABI 下 `len * 8` 溢出；`third_party/xopprotector` 未 vendoring `dex/`，该文件不参与 Shellsmith 主线编译 | **保留为独立上游 PR**，只回 Xop 独立壳线；不要合入 third_party（没有目标文件），也不要把它算作 Shellsmith 主线修复 |
| `build.gradle.kts` 的 `exportShellFiles` | `origin/main` 已对 `build.gradle.kts` 做了 143 行改动 | rebase 后对照远端实现；仅在本地版本确实更稳健且不冲突时保留，否则丢弃 |
| `TrueVmpTrampoline` / `ReadElf` / `PackerMain` / `BusinessSoProtector` | 本地与远端同时改动，语义需要逐段比对 | 按「SO 加载」「True-VMP」「DEX/ELF 读取」拆成独立改动，不整体合并 |
| PVM2 v6 与 third_party v9 的关系 | third_party 是 Shellsmith 的独立演进线，V9 已包含 V6–V8 能力 | 不能把 Xop 本地 v6 当作 third_party 的升级来源；只把 third_party 缺失的语义作为候选 |

## 不做什么

- 不直接 `git rebase` 22 个未提交文件；先 `git fetch`，以 `origin/main` 为基线重新评估。
- 不把 `origin/main` 的 SO 保护改动与本地 PVM2 v6 改动混成一个提交。
- 不把 `dex_file.cpp` 的 SHA-1 修复合入 `third_party/xopprotector`；该目录没有 `dex/`，Shellsmith 主线也不编译它。
- 不在 diff 审计完成前删除或归档 `XopProtector`；本地 HEAD 落后 5 个提交，当前比较基线不是最新上游。

## 下一步

1. `git fetch origin`，确认 `origin/main` 仍为 `4a41d0b` 或更新；以最新远端为基线重跑 diff。
2. 先处理 `dex_file.cpp` 的 SHA-1 修复：独立分支、独立 PR、仅回 Xop 上游。
3. 对本地 PVM2 v6 与 third_party v6–v9 做语义对照，输出「重复 / 缺失 / 冲突」三列清单。
4. 对 `build.gradle.kts`、`TrueVmpTrampoline`、`ReadElf`、`PackerMain`、`BusinessSoProtector` 逐文件裁决。
5. 全部裁决完成后，再决定 Xop 目录是归档、保留为支付 True-VMP 实验线，还是只保留上游 PR。

## 关联

- [第三方 PVM2 运行时](https://github.com/kairowan/Shellsmith/tree/main/third_party/xopprotector)
- [路线图](roadmap.md)
- [Android 代码保护升级方案](../design/android-code-protection-upgrade.md)
