# Mocika Native VMP（源码/LLVM bitcode 接入）

这个目录提供真实的编译期 Native 函数虚拟化路径。它把显式标注函数的 LLVM IR
翻译成自定义寄存器字节码，并把原函数体替换为 `mocika_vmp_exec_i64` 解释器入口。
产物包含 `.mocika.vmp` 段；原函数的基本块和整数运算不再作为原生控制流保留。

它与 APK 后处理阶段的 PSO2 不同：PSO2 只能对已编译 ELF 的安全函数区域做认证静态
加密；Native VMP 必须在业务 Native 源码/bitcode 构建阶段接入。两者可以叠加，先在
业务 CMake 中执行 VMP，再让 `shield protect/protect-aab --profile strict` 对最终 `.so`
执行 PSO2。

## 当前契约

- 编译器和 `opt` 必须为同一 LLVM 主版本；当前锁定 LLVM 21，Android 示例使用
  NDK `29.0.14206865`。
- `MOCIKA_VMP` 标注就是明确的函数白名单。没有标注的函数不会被改写。
- 支持最多 64 位的整数参数/返回值、整数算术与位运算、比较、`select`、整数扩展/
  截断、条件/无条件分支、循环与 PHI。
- 当前不支持指针参数、内存读写、浮点、函数调用、异常、原子/同步和可变参数。
  任何已标注函数出现不支持语义都会让编译失败；不会静默保留原函数并宣称成功。
- 每个函数的虚拟 Opcode 编码默认使用构建期随机种子。设置
  `MOCIKA_VMP_SEED=<固定值>` 可以得到可复现的测试构建，但发布构建不建议固定。
- 运行时限制为每个函数最多 512 个 VM 寄存器。越界会在编译期拒绝。

这是一条可运行的选择性 Native VMP 链路，不是任意 C/C++ 的全语义虚拟机，也不能
用于没有源码/bitcode 的第三方 `.so`。未经过真实设备执行的 ABI/厂商格子仍应标记为
待验证。

## 构建 Pass 并自测

```bash
LLVM_CONFIG=/opt/homebrew/opt/llvm/bin/llvm-config \
  native-vmp/tests/run-self-test.sh
```

自测会：

1. 构建 LLVM Pass；
2. 编译并执行含循环/PHI/分支的等价性样本；
3. 检查生成 IR 已调用解释器并包含 VMP 字节码；
4. 检查带指针参数的已标注函数会失败关闭。

macOS 上不能假设 Google 签名的 NDK Clang 可以直接 `dlopen` 第三方 Pass。CMake
集成使用编译启动器执行“NDK Clang 生成 bitcode → 同版本 `opt` 加载 Pass → NDK
Clang 生成对象文件”，不修改、不重签 NDK 工具。

## 业务 CMake 接入

```cmake
add_library(business SHARED business.c)

include("/path/to/mocika-shield/native-vmp/cmake/MocikaNativeVmp.cmake")
mocika_enable_native_vmp(business
    PLUGIN "/path/to/MocikaNativeVmpPass.dylib"
    LLVM_OPT "/opt/homebrew/opt/llvm/bin/opt")
```

只标注高价值、满足当前语义子集的内部函数；JNI 导出函数可以保留为薄包装：

```c
#include "mocika_native_vmp.h"

MOCIKA_VMP static int protected_score(int value, int rounds) {
    int result = value;
    for (int i = 0; i < rounds; ++i) {
        result = (result * 13 + i) ^ (result >> 3);
    }
    return result;
}
```

不要直接标注带 `JNIEnv *`、对象指针或复杂库调用的 JNI 导出函数；让导出函数调用
一个只使用受支持整数语义的内部函数。完整 Android/Gradle 示例位于
`tests/fixtures/android-dynamic-feature-app/conditional_feature`。

## 已有 LLVM bitcode 接入

输入 `.bc` 已包含 `mocika_vmp` annotation 时，也可以直接运行同一个 Pass：

```bash
/opt/homebrew/opt/llvm/bin/opt \
  -load-pass-plugin=/path/to/MocikaNativeVmpPass.dylib \
  -passes=mocika-native-vmp input.bc -o protected.bc
```

随后用目标 NDK Clang 把 `protected.bc` 与 `runtime/mocika_native_vmp.c` 一起链接。Pass、
`opt` 与产生输入 bitcode 的 Clang 必须使用兼容的 LLVM bitcode 版本；不兼容时应停止
构建，不能退回未虚拟化对象文件。
