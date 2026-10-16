import type { ApkCheckResult, Pvm2FailureSummary } from "@/lib/tauri";
import type { Locale } from "@/lib/i18n";

export function buildProtectDiagnostic({
  preflight,
  locale,
  runtimeMode,
  environmentPolicy,
  protectionProfile,
  aiResistance,
  xopPvm2Configured,
  currentStep,
  failed,
  pvm2Failure,
}: {
  preflight: ApkCheckResult | null;
  locale: Locale;
  runtimeMode: "standard" | "android_api19";
  environmentPolicy: "compatible" | "strict";
  protectionProfile: "compat" | "balanced" | "strict";
  aiResistance: "off" | "balanced" | "high";
  xopPvm2Configured: boolean;
  currentStep: string;
  failed: boolean;
  pvm2Failure?: Pvm2FailureSummary | null;
}) {
  const checks = preflight?.checks
    .filter((check) => check.severity !== "ready")
    .map((check) => `- ${check.code}: ${severityLabel(locale, check.severity)}`)
    .join("\n");
  const english = locale === "en";
  return [
    english ? "Protection diagnostic summary — Shellsmith" : "Shellsmith 加固诊断摘要",
    `${english ? "Task status" : "任务状态"}: ${failed ? (english ? "failed" : "失败") : (english ? "preflight" : "预检")}`,
    `${english ? "Target system" : "运行系统"}: ${runtimeMode === "android_api19" ? (english ? "Android 4.4 industrial compatibility" : "Android 4.4 工控兼容") : (english ? "Android 5.0 and above" : "Android 5.0 及以上")}`,
    `${english ? "Environment protection" : "环境保护"}: ${environmentPolicy === "strict" ? (english ? "strict" : "严格保护") : (english ? "standard" : "标准保护")}`,
    `${english ? "Protection profile" : "保护级别"}: ${protectionProfile}`,
    `${english ? "AI resistance" : "AI 分析抵抗"}: ${aiResistance}`,
    `${english ? "Embedded Xop PVM2" : "嵌入式 Xop PVM2"}: ${xopPvm2Configured ? (english ? "configured" : "已配置") : (english ? "not configured" : "未配置")}`,
    `${english ? "Current stage" : "当前阶段"}: ${currentStep || (english ? "not started" : "未开始")}`,
    `${english ? "Preflight verdict" : "预检结论"}: ${verdictLabel(locale, preflight?.verdict)}`,
    checks ? `${english ? "Risk items" : "风险项"}:\n${checks}` : `${english ? "Risk items" : "风险项"}: ${english ? "none" : "无"}`,
    ...(failed && pvm2Failure ? [buildPvm2FailureDiagnostic(pvm2Failure, locale)] : []),
    english
      ? "Note: This summary excludes paths, certificates, passwords, package names, business class names, and raw error text. Include your app version; Settings → Feedback attaches environment diagnostics. Method reports contain business identifiers; redact before sharing."
      : "说明: 本摘要不包含路径、证书、密码、包名、业务类名或原始错误文本。反馈时请补充软件版本；设置 → 问题反馈可附带环境诊断。逐方法报告含业务标识，分享前请手动脱敏。",
  ].join("\n");
}

export function buildPvm2FailureDiagnostic(summary: Pvm2FailureSummary, locale: Locale) {
  const english = locale === "en";
  const labels: Record<keyof Pvm2FailureSummary["reasons"], [string, string]> = {
    no_code: ["无 DEX 方法体（Native/抽象方法）", "No DEX body (native/abstract)"],
    initializer: ["构造器/静态初始化器", "Initializer"],
    ui_runtime_glue: ["界面/生命周期兼容规则", "UI/lifecycle compatibility"],
    data_resource_runtime_glue: ["数据/资源框架兼容规则", "Data/resource compatibility"],
    compiler_generated_bridge: ["编译器生成桥接/合成方法", "Compiler-generated bridge/synthetic method"],
    playback_compatibility: ["媒体/辅助类兼容规则", "Media/helper compatibility"],
    nullable_receiver: ["接收者非空语义无法证明", "Nullable receiver"],
    unsupported_opcode: ["不支持的指令", "Unsupported opcode"],
    register_limit: ["寄存器超限", "Register limit"],
    code_size_limit: ["方法大小超限", "Code size limit"],
    exception_mapping: ["异常处理映射不支持", "Exception mapping"],
    control_flow: ["控制流不支持", "Control flow"],
    type: ["类型不支持", "Unsupported type"],
    not_attempted: ["未进入转换", "Not attempted"],
    other: ["其他原因", "Other"],
  };
  const code = `${english ? "Failure code" : "失败代码"}: PVM2_ZERO_METHODS`;
  const counts = [summary.selected_classes, summary.selected_methods];
  const reasons = Object.keys(labels) as (keyof typeof labels)[];
  // 白名单重建分享文本；不能把运行日志、报告路径或未知原因字符串拼进摘要。
  const values = reasons.map((reason) => summary.reasons?.[reason] ?? 0);
  if (![...counts, ...values].every((n) => Number.isSafeInteger(n) && n >= 0)
    || summary.selected_classes > summary.selected_methods
    || values.reduce((a, b) => a + b, 0) !== summary.selected_methods) {
    return `${code}\n${english ? "Reason counts unavailable" : "原因统计无效，无法展示数量"}`;
  }
  return [code,
    `${english ? "Classes in method inventory" : "方法清单涉及类数"}: ${summary.selected_classes}`,
    `${english ? "Selected methods" : "所选方法数"}: ${summary.selected_methods}`,
    `${english ? "Transformed methods" : "转换成功方法数"}: 0`,
    ...reasons.flatMap((reason, i) => values[i] > 0 ? [`- ${reason} (${labels[reason][english ? 1 : 0]}): ${values[i]}`] : []),
  ].join("\n");
}

function verdictLabel(locale: Locale, verdict: ApkCheckResult["verdict"] | undefined) {
  const english = locale === "en";
  if (verdict === "blocked") return english ? "blocked" : "必须阻止";
  if (verdict === "warning") return english ? "compatibility risk" : "存在兼容风险";
  if (verdict === "ready") return english ? "passed" : "通过";
  return english ? "incomplete" : "未完成";
}

function severityLabel(locale: Locale, severity: "ready" | "warning" | "blocked") {
  const english = locale === "en";
  if (severity === "blocked") return english ? "blocked" : "必须阻止";
  if (severity === "warning") return english ? "risk" : "存在风险";
  return english ? "passed" : "通过";
}
