import type { I18nKey } from "@/lib/i18n";
import type { UpdateBlockReason } from "@/lib/tauri";

/**
 * 覆盖安装不可用时，按后端探测到的具体原因给出对应说明。
 * 只用一句笼统提示，用户无法判断到底是「没放进应用程序」还是「装的是 deb」。
 */
export function installBlockedKey(reason?: UpdateBlockReason | null): I18nKey {
  switch (reason) {
    case "debug_build":
      return "updateBlockedDebug";
    case "mounted_volume":
      return "updateBlockedMountedVolume";
    case "app_translocation":
      return "updateBlockedTranslocation";
    case "not_app_bundle":
      return "updateBlockedNotAppBundle";
    case "linux_package":
      return "updateBlockedLinuxPackage";
    default:
      return "updateManualHint";
  }
}
