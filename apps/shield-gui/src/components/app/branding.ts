import type { Locale } from "@/lib/i18n";

export const appIconUrl = "/shellsmith-icon.png";
export const appName = "Shellsmith";

export const stepLabels: Record<string, Record<Locale, string>> = {
  CheckTools: { zh: "检查工具", en: "Check tools" },
  Unpack: { zh: "解包 APK", en: "Unpack APK" },
  ModifyManifest: { zh: "修改 Manifest", en: "Modify Manifest" },
  ProcessDex: { zh: "处理 DEX", en: "Process DEX" },
  InjectRuntime: { zh: "注入 Runtime", en: "Inject runtime" },
  Repack: { zh: "重打包", en: "Repack" },
  AlignApk: { zh: "对齐 APK", en: "Align APK" },
  Sign: { zh: "自动签名", en: "Auto sign" },
  PrepareSign: { zh: "准备签名", en: "Prepare signing" },
  SignApk: { zh: "执行签名", en: "Sign APK" },
  VerifySign: { zh: "验证签名", en: "Verify signing" },
  Cleanup: { zh: "清理中间产物", en: "Clean up" },
  InspectBundle: { zh: "检查 AAB 模块", en: "Inspect AAB modules" },
  BuildUniversalApk: { zh: "生成 APK 工作副本", en: "Build APK workspace" },
  RebuildBundle: { zh: "重建 AAB 模块", en: "Rebuild AAB modules" },
  SignAab: { zh: "签署 AAB", en: "Sign AAB" },
  ValidateBundle: { zh: "校验 AAB", en: "Validate AAB" },
  BuildApks: { zh: "生成 APKS", en: "Build APKS" },
};
