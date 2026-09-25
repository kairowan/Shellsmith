# Xop 单壳适配器接入门禁

## 当前状态

Xop PVM2 已以 transform-only 子能力真实嵌入 Shellsmith 单 Stub，启用时
`FusionPlan` 报告 `xop-pvm2-embedded`。这不等于完整
`xop-adapter-ready`：Hollow、Native SO 保护和 Xop Runtime RASP 仍未融入该生命周期。

真实运行链为：

1. Shellsmith 调用 Xop Packer 的 `pvm2-transform`，只改写显式允许的业务方法并生成 PVM2 `code.bin`。
2. 跳板固定调用 `dev.mocika.shield.loader.XopVmBridge`，不注入 Xop
   `ProxyApplication`、`AppComponentFactory` 或第二个 Native 壳。
3. Shellsmith 将变换后 DEX 和 `xop-pvm2.bin` 一起放入证书绑定的 DEXB v6。
4. Shellsmith 唯一 `JNI_OnLoad` 同时注册 DEX 加载入口和 PVM2 bridge；DEXB 解密后先
   初始化静态链入的 Xop 解释器，再加载业务 DEX。

运行时资源必须显式声明 `"xop_pvm2": true`。旧资源包和 API19 兼容资源
默认/明确为 `false`，CLI 会在改写 DEX 前失败关闭，不会生成含跳板但没有解释器的包。

## APK 使用

```bash
shield protect \
  -i app.apk -o app-protected.apk \
  --profile balanced --ai-resistance high \
  --xop-pvm2-packer /path/to/protector-packer.jar \
  --xop-true-vmp-prefix 'Lcom/example/payment/'
```

类前缀必须显式给出，且必须是边界明确的 DEX 类描述符；不做全包自动虚拟化。
PVM2 AES-GCM 密钥从 DEXB IKM 和最终安装证书派生，通过子进程环境传给 Packer，
不出现在 Java 命令行参数中。

## AAB 使用

单 base AAB 的 Shellsmith 引擎使用同样的参数：

```bash
shield protect-aab \
  -i app.aab -o app-protected.aab \
  --xop-pvm2-packer /path/to/protector-packer.jar \
  --xop-true-vmp-prefix 'Lcom/example/payment/' \
  --runtime-cert-sha256 "$PLAY_APP_SIGNING_SHA256" \
  --bundletool /path/to/bundletool-all.jar \
  --aapt2 "$ANDROID_HOME/build-tools/35.0.0/aapt2" \
  --ks upload.jks --key-alias upload
```

install-time/条件/on-demand dynamic-feature 的 DEX 会与 base 共用 PVM2 密钥和全局
DEX 编号；功能模块和三种 delivery 的 Asset Pack 会共用 PAS2/PSO2 密钥并在全部目标
成功后写回。fast-follow/on-demand Asset Pack 必须加 `--play-delivery-adapter` 并由业务
使用 `MocikaPlayDelivery`。本地 bundletool/APKS 结构验证不能代替 Play 内测轨道和
延迟模块真机生命周期验证。

## 独立 Xop 引擎

`protect-xop` 和 `protect-aab --engine xop` 仍保留，用于需要 Xop
Hollow/Native SO/RASP 的独立单壳交付。它们与嵌入式 PVM2 是两种互斥的引擎选择，
不得先用 Xop 打壳再套 Shellsmith。

## 验证证据（2026-09-23）

- Xop `:packer:test :packer:jar` 通过，transform-only 样例生成 v4 PVM2 载荷和 Shellsmith bridge 跳板。
- Shellsmith Rust/Java Stub 构建出 arm64-v8a、armeabi-v7a、x86、x86_64 四 ABI，全部
  PT_LOAD 至少 16 KB 对齐，每个 `.so` 只导出一个 `JNI_OnLoad`。
- C++ runtime 已静态闭包，构建门禁拒绝未解析的 RTTI/异常/new-delete 符号。
- 在 HONOR BRP-AN00、Android API 35、arm64-v8a 上完成安装和启动；被 PVM2
  改写的字符串、整数/浮点、字段、数组、异常、monitor、switch 和 JNI wrapper 样例结果全部正确。

这些证据证明嵌入代码链和一台真机可用，不代表所有厂商 ROM、大型 SDK 或 Play
分发组合都已验证。
