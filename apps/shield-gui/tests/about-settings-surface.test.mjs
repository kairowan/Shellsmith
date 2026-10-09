import assert from "node:assert/strict";
import { after, test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

// 复用 Vite 编译实际组件，直接断言界面上的可见内容而不是源码字符串。
const server = await createServer({ server: { middlewareMode: true }, appType: "custom" });
after(() => server.close());
const { AboutInfoCard } = await server.ssrLoadModule("/src/components/app/about-info-card.tsx");
const { SettingsPage } = await server.ssrLoadModule("/src/pages/settings-page.tsx");

const aboutHtml = renderToStaticMarkup(
  createElement(AboutInfoCard, {
    locale: "zh",
    appInfo: { version: "1.5.1", build_date: "2026-10-09" },
    checking: false,
    message: "",
    onCheckUpdate: () => undefined,
    runtimeInfoRefreshing: false,
    onRefreshRuntimeInfo: () => undefined,
  }),
);

const settingsHtml = renderToStaticMarkup(
  createElement(SettingsPage, {
    locale: "zh",
    setLocale: () => undefined,
    themeMode: "system",
    setThemeMode: () => undefined,
    telemetryEnabled: true,
  }),
);

test("关于页不再显示工具链版本与复制诊断信息", () => {
  for (const text of ["Java", "java", "apktool", "apksigner", "复制诊断信息", "诊断信息"]) {
    assert.ok(!aboutHtml.includes(text), `关于页不应再出现「${text}」`);
  }
});

test("关于页保留版本、构建时间、重新检测环境与检查更新", () => {
  assert.match(aboutHtml, /v1\.5\.1/);
  assert.match(aboutHtml, /2026-10-09/);
  assert.match(aboutHtml, /重新检测环境/);
  assert.match(aboutHtml, /检查更新/);
});

test("设置页不再显示匿名使用统计与应用使用情况分享", () => {
  for (const text of ["匿名使用统计", "允许匿名使用统计", "应用使用情况分享", "参与分享"]) {
    assert.ok(!settingsHtml.includes(text), `设置页不应再出现「${text}」`);
  }
  assert.doesNotMatch(settingsHtml, /type="checkbox"/);
});

test("设置页保留外观与语言设置", () => {
  assert.match(settingsHtml, /外观/);
  assert.match(settingsHtml, /主题/);
  assert.match(settingsHtml, /语言/);
  assert.match(settingsHtml, /中文/);
});

test("设置页提供问题反馈入口且不预展开表单", () => {
  assert.match(settingsHtml, /问题反馈/);
  assert.match(settingsHtml, /提交问题反馈/);
  // 未打开时不渲染表单字段，避免在设置页内出现隐藏的输入控件。
  assert.doesNotMatch(settingsHtml, /一句话标题|复现步骤|反馈类型/);
});
