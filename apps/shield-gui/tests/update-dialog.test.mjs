import assert from "node:assert/strict";
import { after, test } from "node:test";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

// 复用 Vite 编译实际组件，无需另加测试框架或 JSX 加载器。
const server = await createServer({ server: { middlewareMode: true }, appType: "custom" });
after(() => server.close());
const { UpdateReleaseNotes } = await server.ssrLoadModule("/src/components/app/update-dialog.tsx");
const render = (notes) => renderToStaticMarkup(createElement(UpdateReleaseNotes, { notes, onError: assert.fail }));

test("更新说明渲染标题、列表、强调及 GitHub 裸链接，隐藏发布注释", () => {
  const html = render(`<!-- Release notes generated using configuration in .github/release.yml at main -->

### 其他变更
* **新增** iOS 本机依赖缓存
* 修复 \`ShellsmithRuntime\`

**Full Changelog**: https://github.com/kairowan/Shellsmith/compare/v1.4.5...v1.5.0`);
  assert.match(html, /<h3>其他变更<\/h3>/);
  assert.match(html, /<ul>\s*<li><strong>新增<\/strong>/);
  assert.match(html, /<code>ShellsmithRuntime<\/code>/);
  assert.match(html, /<a href="https:\/\/github.com\/kairowan\/Shellsmith\/compare\/v1.4.5\.\.\.v1.5.0">/);
  assert.doesNotMatch(html, /Release notes generated|###|\*\*Full Changelog/);
});

test("GitHub 表格、任务列表和代码块保持结构", () => {
  const html = render("| 功能 | 状态 |\n| --- | --- |\n| 下载 | 已修复 |\n\n- [x] 渐变\n\n```html\n<script>示例</script>\n```");
  assert.match(html, /<table>/);
  assert.match(html, /<td>已修复<\/td>/);
  assert.match(html, /type="checkbox" disabled="" checked=""/);
  assert.match(html, /<pre><code[^>]*>&lt;script&gt;示例&lt;\/script&gt;/);
});

test("不执行原始 HTML，不加载外部图片，不开放非官方或危险链接", () => {
  const html = render(`<script>alert(1)</script>

<img src="https://example.com/track" onerror="alert(1)">

![示意图](https://example.com/track)

[危险](javascript:alert%281%29) [本地](file:///tmp/test) [伪装](https://github.com/kairowan/Shellsmith.evil/) [站外](https://example.com)`);
  assert.doesNotMatch(html, /<script|<img|onerror|href=|src=/);
  assert.match(html, /示意图/);
});

test("进度轨道及两类浏览器填充均为圆角渐变，并保留原生进度语义", () => {
  const css = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");
  const component = readFileSync(new URL("../src/components/app/update-dialog.tsx", import.meta.url), "utf8");
  assert.match(component, /<progress aria-label=.*className="update-progress".*value=.*: undefined/s);
  assert.match(css, /\.update-progress\s*\{[^}]*linear-gradient\(90deg,[^;]+30%[^;]+65%[^;]+100%\)[^}]*rounded-full/s);
  for (const engine of ["webkit-progress-value", "moz-progress-bar"]) {
    assert.match(css, new RegExp(`\\.update-progress::-${engine}\\s*\\{[^}]*border-radius: 9999px;[^}]*background: var\\(--update-gradient\\);`));
  }
  assert.match(css, /\[data-theme="dark"\] \.update-progress/);
  assert.match(css, /prefers-reduced-motion: reduce/);
});
