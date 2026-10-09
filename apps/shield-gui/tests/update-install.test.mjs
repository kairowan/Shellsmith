import assert from "node:assert/strict";
import { after, test } from "node:test";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import { createServer } from "vite";

// 复用 Vite 编译实际源码，无需另加测试框架或 JSX 加载器。
const server = await createServer({ server: { middlewareMode: true }, appType: "custom" });
after(() => server.close());
const { installBlockedKey } = await server.ssrLoadModule("/src/lib/update-install.ts");

test("每种阻止一键更新的原因都有专属说明而不是笼统提示", () => {
  assert.equal(installBlockedKey("debug_build"), "updateBlockedDebug");
  assert.equal(installBlockedKey("mounted_volume"), "updateBlockedMountedVolume");
  assert.equal(installBlockedKey("app_translocation"), "updateBlockedTranslocation");
  assert.equal(installBlockedKey("not_app_bundle"), "updateBlockedNotAppBundle");
  assert.equal(installBlockedKey("linux_package"), "updateBlockedLinuxPackage");
});

test("未知或缺失原因回退到通用说明", () => {
  assert.equal(installBlockedKey(undefined), "updateManualHint");
  assert.equal(installBlockedKey(null), "updateManualHint");
  assert.equal(installBlockedKey("未来的新原因"), "updateManualHint");
});

test("弹窗按原因显示说明，并在无法覆盖安装时给出直连安装包入口", () => {
  const dialog = readFileSync(new URL("../src/components/app/update-dialog.tsx", import.meta.url), "utf8");
  assert.match(dialog, /installBlockedKey\(updateInfo\.install_blocked_reason\)/);
  assert.match(dialog, /const manualDownloadUrl = updateInfo\.manual_download_url \|\| updateInfo\.release_url/);
  assert.match(dialog, /!updateInfo\.can_install && manualDownloadUrl/);
  assert.match(dialog, /api\.openUrl\(manualDownloadUrl\)/);
  // 不能同时给出「覆盖安装」和「下载安装包」两个主操作。
  assert.match(dialog, /updateInfo\.can_install && <AppButton/);
  assert.match(dialog, /!updateInfo\.can_install && manualDownloadUrl/);
});

test("新版本推送后启动即弹窗，忽略过的版本只保留顶部横幅", () => {
  const hook = readFileSync(new URL("../src/hooks/use-app-config.ts", import.meta.url), "utf8");
  assert.match(hook, /setUpdateInfo\(result\)/);
  assert.match(hook, /if \(dismissed !== result\.latest_version\) \{\s*setUpdateDialogOpen\(true\);/);
  // 不再按 major/minor 区分是否弹窗。
  assert.doesNotMatch(hook, /update_level !== "major"/);
});

test("弹窗打开时不重复渲染顶部横幅，关闭弹窗后仍保留横幅", () => {
  const app = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.match(app, /\{!updateDialogOpen && \(\s*<UpdateBanner/s);
  assert.match(app, /async function closeUpdateDialog\(\)[\s\S]*?api\.dismissUpdate\(version\)[\s\S]*?setUpdateDialogOpen\(false\)/);
  assert.match(app, /async function dismissUpdateBanner\(\)[\s\S]*?api\.dismissUpdate\(version\)[\s\S]*?setUpdateInfo\(null\)/);
});
