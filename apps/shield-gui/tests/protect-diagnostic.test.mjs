import assert from "node:assert/strict";
import { after, test } from "node:test";
import { createServer } from "vite";

const server = await createServer({ server: { middlewareMode: true }, appType: "custom", optimizeDeps: { noDiscovery: true, include: [] } });
after(() => server.close());
const { buildProtectDiagnostic, buildPvm2FailureDiagnostic } = await server.ssrLoadModule("/src/lib/protect-diagnostic.ts");
const failure = {
  selected_classes: 2,
  selected_methods: 4,
  reasons: { no_code: 1, initializer: 1, ui_runtime_glue: 1, register_limit: 1 },
};

test("失败摘要显示实际跳过统计且不复制业务标识或未知字段", () => {
  const summary = buildProtectDiagnostic({
    preflight: null, locale: "zh", runtimeMode: "standard", environmentPolicy: "strict",
    protectionProfile: "strict", aiResistance: "high", xopPvm2Configured: true,
    currentStep: "ProcessDex", failed: true,
    pvm2Failure: { ...failure, path: "/Users/private/report.json", descriptor: "Lprivate/Business;",
      reasons: { ...failure.reasons, "private password=secret": 1 } },
  });
  assert.match(summary, /PVM2_ZERO_METHODS/);
  assert.match(summary, /所选方法数: 4/);
  assert.match(summary, /转换成功方法数: 0/);
  assert.match(summary, /ui_runtime_glue .*: 1/);
  assert.match(summary, /register_limit .*: 1/);
  assert.doesNotMatch(summary, /private|Business|password|secret|report\.json/);
  assert.doesNotMatch(summary, /关于.*诊断/);
});

test("AAB 与 APK 复用相同脱敏格式，异常计数不进入分享内容", () => {
  const english = buildPvm2FailureDiagnostic(failure, "en");
  assert.match(english, /Selected methods: 4/);
  assert.match(english, /Transformed methods: 0/);
  for (const count of [-1, NaN, Infinity, "private", Number.MAX_SAFE_INTEGER + 1]) {
    const text = buildPvm2FailureDiagnostic({ ...failure, selected_methods: count }, "zh");
    assert.match(text, /原因统计无效/);
    assert.doesNotMatch(text, /private|NaN|Infinity/);
  }
  assert.match(buildPvm2FailureDiagnostic({ ...failure, selected_methods: 5 }, "zh"), /原因统计无效/);
});

test("普通预检不混入上一任务的失败统计", () => {
  const text = buildProtectDiagnostic({ preflight: null, locale: "zh", runtimeMode: "standard",
    environmentPolicy: "compatible", protectionProfile: "balanced", aiResistance: "balanced",
    xopPvm2Configured: false, currentStep: "", failed: false, pvm2Failure: failure });
  assert.doesNotMatch(text, /PVM2_ZERO_METHODS/);
});

test("兼容限制按方法实际阻断条件统计，不再全部显示为生命周期", () => {
  const text = buildPvm2FailureDiagnostic({ selected_classes: 3, selected_methods: 21,
    reasons: { initializer: 3, compatibility_virtual_contract: 6, compatibility_synchronization: 2,
      compatibility_exception_region: 3, compatibility_non_leaf_instruction: 7 } }, "zh");
  assert.match(text, /所选方法数: 21/);
  assert.match(text, /特殊对象方法或虚方法契约未验证\): 6/);
  assert.match(text, /同步方法\): 2/);
  assert.match(text, /含异常处理区\): 3/);
  assert.match(text, /白名单之外的指令\): 7/);
  assert.doesNotMatch(text, /生命周期|统计无效/);
});
