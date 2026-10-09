import { useEffect, useMemo, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { ExternalLink, LoaderCircle, MessageSquarePlus, Send, X } from "lucide-react";
import { AppButton, SelectInput, StatusMessage, TextInput } from "@/components/app/common";
import { t, type I18nKey, type Locale } from "@/lib/i18n";
import {
  api,
  type FeedbackDraft,
  type FeedbackImpact,
  type FeedbackModule,
  type FeedbackPlatform,
  type FeedbackReceipt,
  type FeedbackRequest,
} from "@/lib/tauri";

const MODULES: FeedbackModule[] = [
  "android",
  "ios",
  "sign",
  "certificates",
  "java",
  "update",
  "gui",
  "build",
  "docs",
  "other",
];
const PLATFORMS: FeedbackPlatform[] = [
  "windows",
  "macos",
  "linux",
  "android_runtime",
  "ios",
  "agnostic",
];
const IMPACTS: FeedbackImpact[] = ["blocking", "slower", "nice_to_have"];

const MODULE_KEY: Record<FeedbackModule, I18nKey> = {
  android: "feedbackModuleAndroid",
  ios: "feedbackModuleIos",
  sign: "feedbackModuleSign",
  certificates: "feedbackModuleCertificates",
  java: "feedbackModuleJava",
  update: "feedbackModuleUpdate",
  gui: "feedbackModuleGui",
  build: "feedbackModuleBuild",
  docs: "feedbackModuleDocs",
  other: "feedbackModuleOther",
};

const PLATFORM_KEY: Record<FeedbackPlatform, I18nKey> = {
  windows: "feedbackPlatformWindows",
  macos: "feedbackPlatformMacos",
  linux: "feedbackPlatformLinux",
  android_runtime: "feedbackPlatformAndroidRuntime",
  ios: "feedbackPlatformIos",
  agnostic: "feedbackPlatformAgnostic",
};

const IMPACT_KEY: Record<FeedbackImpact, I18nKey> = {
  blocking: "feedbackImpactBlocking",
  slower: "feedbackImpactSlower",
  nice_to_have: "feedbackImpactNice",
};

/** Bug 与需求建议共用一套表单，标签按类型切换；必填校验以后端为准。 */
function emptyFeedbackRequest(): FeedbackRequest {
  return {
    kind: "bug",
    module: "android",
    title: "",
    primary: "",
    expected: "",
    observed: "",
    impact: null,
    platforms: [],
    alternatives: "",
    extra: "",
    logs: "",
    includeEnvironment: true,
  };
}

export function FeedbackDialog({
  locale,
  open,
  onClose,
}: {
  locale: Locale;
  open: boolean;
  onClose: () => void;
}) {
  const [form, setForm] = useState<FeedbackRequest>(emptyFeedbackRequest);
  const [draft, setDraft] = useState<FeedbackDraft | null>(null);
  const [receipt, setReceipt] = useState<FeedbackReceipt | null>(null);
  const [preparing, setPreparing] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");

  const isFeature = form.kind === "feature";
  const busy = preparing || sending;

  useEffect(() => {
    if (!open) {
      // 关闭后清空，避免下次打开残留上一次的反馈内容与预览。
      setForm(emptyFeedbackRequest());
      setDraft(null);
      setReceipt(null);
      setError("");
      setPreparing(false);
      setSending(false);
    }
  }, [open]);

  const moduleOptions = useMemo(
    () => MODULES.map((value) => ({ value, label: t(locale, MODULE_KEY[value]) })),
    [locale],
  );

  function update(patch: Partial<FeedbackRequest>) {
    setForm((current) => ({ ...current, ...patch }));
  }

  async function prepare() {
    if (busy) return;
    setPreparing(true);
    setError("");
    try {
      setDraft(await api.prepareFeedback(form));
    } catch (failure) {
      setError(String(failure));
    } finally {
      setPreparing(false);
    }
  }

  async function submit() {
    if (!draft || busy) return;
    setSending(true);
    setError("");
    try {
      setReceipt(await api.submitFeedback(draft.payload));
      setDraft(null);
    } catch (failure) {
      setError(String(failure));
    } finally {
      setSending(false);
    }
  }

  function openInBrowser(url: string) {
    void api.openUrl(url).catch((failure) => setError(String(failure)));
  }

  return (
    <Dialog.Root open={open} onOpenChange={(value) => { if (!value && !busy) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/55" />
        <Dialog.Content className="app-panel fixed left-1/2 top-1/2 z-50 max-h-[88vh] w-[min(720px,calc(100vw-32px))] -translate-x-1/2 -translate-y-1/2 overflow-auto p-6">
          <Dialog.Title className="flex items-center gap-2 pr-8 text-lg font-semibold">
            <MessageSquarePlus className="h-5 w-5" />
            {t(locale, "feedbackTitle")}
          </Dialog.Title>
          <Dialog.Description className="mt-3 text-sm leading-6 text-muted-foreground">
            {t(locale, "feedbackIntro")}
          </Dialog.Description>

          {receipt ? (
            <div className="mt-5 space-y-4">
              <StatusMessage kind="success">{t(locale, "feedbackSent")}</StatusMessage>
              <p className="font-mono text-sm">#{receipt.number}</p>
              <div className="flex flex-wrap justify-end gap-2">
                <AppButton variant="secondary" onClick={() => openInBrowser(receipt.url)}>
                  <ExternalLink className="h-4 w-4" />
                  {t(locale, "feedbackOpenIssue")}
                </AppButton>
                <AppButton disabled={busy} onClick={onClose}>{t(locale, "feedbackClose")}</AppButton>
              </div>
            </div>
          ) : draft ? (
            <div className="mt-5 space-y-4">
              <div>
                <p className="text-sm font-semibold">{t(locale, "feedbackPreview")}</p>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">{t(locale, "feedbackPreviewHint")}</p>
              </div>
              <div className="rounded-xl border p-3">
                <p className="text-xs text-muted-foreground">{t(locale, "feedbackIssueTitle")}</p>
                <p className="mt-1 break-words text-sm font-medium">{draft.issue_title}</p>
              </div>
              <pre className="scrollbar-none max-h-[38vh] overflow-auto whitespace-pre-wrap break-words rounded-xl border bg-muted/30 p-3 text-xs leading-5">{draft.body}</pre>
              {draft.fallback_truncated && (
                <StatusMessage kind="warning">{t(locale, "feedbackFallbackTruncated")}</StatusMessage>
              )}
              {error && <StatusMessage kind="error">{error}</StatusMessage>}
              <div className="flex flex-wrap justify-end gap-2">
                <AppButton variant="secondary" disabled={busy} onClick={() => { setDraft(null); setError(""); }}>
                  {t(locale, "feedbackBack")}
                </AppButton>
                <AppButton variant="secondary" disabled={busy} onClick={() => openInBrowser(draft.fallback_url)}>
                  <ExternalLink className="h-4 w-4" />
                  {t(locale, "feedbackOpenInBrowser")}
                </AppButton>
                <AppButton disabled={busy} onClick={() => void submit()}>
                  {sending ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                  {sending ? t(locale, "feedbackSending") : t(locale, "feedbackConfirmSend")}
                </AppButton>
              </div>
            </div>
          ) : (
            <div className="mt-5 space-y-4">
              <div className="flex flex-wrap gap-2" role="tablist" aria-label={t(locale, "feedbackKind")}>
                {(["bug", "feature"] as const).map((kind) => (
                  <button
                    key={kind}
                    type="button"
                    role="tab"
                    aria-selected={form.kind === kind}
                    className={`rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${form.kind === kind ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}
                    onClick={() => update({ kind, impact: kind === "bug" ? null : form.impact, platforms: kind === "bug" ? [] : form.platforms })}
                  >
                    {t(locale, kind === "bug" ? "feedbackKindBug" : "feedbackKindFeature")}
                  </button>
                ))}
              </div>

              <Field label={t(locale, "feedbackModule")}>
                <SelectInput value={form.module} disabled={busy} onChange={(event) => update({ module: event.target.value as FeedbackModule })}>
                  {moduleOptions.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </SelectInput>
              </Field>

              <Field label={t(locale, "feedbackTitleLabel")}>
                <TextInput
                  value={form.title}
                  disabled={busy}
                  maxLength={120}
                  placeholder={t(locale, "feedbackTitlePlaceholder")}
                  onChange={(event) => update({ title: event.target.value })}
                />
              </Field>

              <Field label={t(locale, isFeature ? "feedbackScenario" : "feedbackSteps")} hint={t(locale, isFeature ? "feedbackScenarioHint" : "feedbackStepsHint")}>
                <TextArea value={form.primary} disabled={busy} onChange={(value) => update({ primary: value })} />
              </Field>

              <Field label={t(locale, isFeature ? "feedbackProblem" : "feedbackObserved")} hint={t(locale, isFeature ? "feedbackProblemHint" : "feedbackObservedHint")}>
                <TextArea value={form.observed} disabled={busy} onChange={(value) => update({ observed: value })} />
              </Field>

              <Field label={t(locale, isFeature ? "feedbackProposal" : "feedbackExpected")} hint={t(locale, isFeature ? "feedbackProposalHint" : "feedbackExpectedHint")}>
                <TextArea value={form.expected} disabled={busy} onChange={(value) => update({ expected: value })} />
              </Field>

              {isFeature && (
                <>
                  <Field label={t(locale, "feedbackImpact")}>
                    <SelectInput
                      value={form.impact ?? ""}
                      disabled={busy}
                      onChange={(event) => update({ impact: (event.target.value || null) as FeedbackImpact | null })}
                    >
                      <option value="">{t(locale, "feedbackImpact")}</option>
                      {IMPACTS.map((impact) => (
                        <option key={impact} value={impact}>{t(locale, IMPACT_KEY[impact])}</option>
                      ))}
                    </SelectInput>
                  </Field>
                  <Field label={t(locale, "feedbackPlatforms")} hint={t(locale, "feedbackPlatformsHint")}>
                    <div className="flex flex-wrap gap-3">
                      {PLATFORMS.map((platform) => (
                        <label key={platform} className="flex items-center gap-2 text-sm">
                          <input
                            type="checkbox"
                            className="h-4 w-4"
                            disabled={busy}
                            checked={form.platforms.includes(platform)}
                            onChange={(event) => update({
                              platforms: event.target.checked
                                ? [...form.platforms, platform]
                                : form.platforms.filter((value) => value !== platform),
                            })}
                          />
                          <span>{t(locale, PLATFORM_KEY[platform])}</span>
                        </label>
                      ))}
                    </div>
                  </Field>
                </>
              )}

              {!isFeature && (
                <label className="flex items-start gap-3 text-sm">
                  <input
                    type="checkbox"
                    className="mt-0.5 h-4 w-4 accent-primary"
                    disabled={busy}
                    checked={form.includeEnvironment}
                    onChange={(event) => update({ includeEnvironment: event.target.checked })}
                  />
                  <span>
                    <b>{t(locale, "feedbackIncludeEnvironment")}</b>
                    <span className="mt-1 block text-xs leading-5 text-muted-foreground">{t(locale, "feedbackIncludeEnvironmentHint")}</span>
                  </span>
                </label>
              )}

              {isFeature && (
                <Field label={t(locale, "feedbackAlternatives")}>
                  <TextArea value={form.alternatives} disabled={busy} onChange={(value) => update({ alternatives: value })} />
                </Field>
              )}

              <Field label={t(locale, "feedbackExtra")}>
                <TextArea value={form.extra} disabled={busy} onChange={(value) => update({ extra: value })} />
              </Field>

              {!isFeature && (
                <Field label={t(locale, "feedbackLogs")} hint={t(locale, "feedbackLogsHint")}>
                  <TextArea value={form.logs} disabled={busy} onChange={(value) => update({ logs: value })} />
                </Field>
              )}

              {error && <StatusMessage kind="error">{error}</StatusMessage>}
              <div className="flex flex-wrap justify-end gap-2">
                <AppButton variant="secondary" disabled={busy} onClick={onClose}>{t(locale, "feedbackClose")}</AppButton>
                <AppButton disabled={busy} onClick={() => void prepare()}>
                  {preparing ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                  {t(locale, "feedbackPreview")}
                </AppButton>
              </div>
            </div>
          )}

          <button
            type="button"
            className="absolute right-4 top-4 rounded-sm p-1 text-muted-foreground"
            aria-label={t(locale, "feedbackClose")}
            disabled={busy}
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </button>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium">{label}</span>
      <span className="mt-2 block">{children}</span>
      {hint && <span className="mt-1 block text-xs leading-5 text-muted-foreground">{hint}</span>}
    </label>
  );
}

function TextArea({
  value,
  disabled,
  onChange,
}: {
  value: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <textarea
      value={value}
      disabled={disabled}
      rows={4}
      className="scrollbar-none w-full rounded-xl border border-border/80 bg-background/90 px-3.5 py-2.5 text-sm text-foreground placeholder:text-muted-foreground shadow-sm"
      onChange={(event) => onChange(event.target.value)}
    />
  );
}
