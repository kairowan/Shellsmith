import type React from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FolderOpen, RotateCcw, Square } from "lucide-react";
import { AppButton, DropZone, SelectedApkCard, SelectInput, StatusMessage, TextInput } from "@/components/app/common";
import { ProtectProgressPanel } from "@/components/app/protect-progress-panel";
import { notifyError, notifySuccess } from "@/lib/notify";
import {
  dirname,
  isAab,
  joinPath,
  normalizeAabFilename,
  protectedAabFilename,
  protectedApksFilename,
  validateAabOutputFilename,
} from "@/lib/path";
import { t, type Locale } from "@/lib/i18n";
import {
  api,
  onTauriEvent,
  openDirectoryDialog,
  openFileDialog,
  type AabInspection,
  type BuildInfo,
  type CertificateRecord,
  type DragDropPayload,
  type TaskSnapshot,
} from "@/lib/tauri";

type AabState = "idle" | "prechecking" | "running" | "done" | "failed";

export function AabProtectPage({
  active,
  locale,
  certificates,
  defaultCertificate,
  certificatesLoaded,
  buildInfo,
  runtimeInfoLoaded,
  onOpenCertificates,
}: {
  active: boolean;
  locale: Locale;
  certificates: CertificateRecord[];
  defaultCertificate: CertificateRecord | null;
  certificatesLoaded: boolean;
  buildInfo: BuildInfo | null;
  runtimeInfoLoaded: boolean;
  onOpenCertificates: () => void;
}) {
  const [input, setInput] = useState("");
  const [outputDirectory, setOutputDirectory] = useState("");
  const [outputFilename, setOutputFilename] = useState("");
  const [inspection, setInspection] = useState<AabInspection | null>(null);
  const [state, setState] = useState<AabState>("idle");
  const [error, setError] = useState("");
  const [warning, setWarning] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const [selectedCertificateId, setSelectedCertificateId] = useState("");
  const [runtimeCertSha256, setRuntimeCertSha256] = useState("");
  const [allowUploadCertBinding, setAllowUploadCertBinding] = useState(true);
  const [playDeliveryAdapter, setPlayDeliveryAdapter] = useState(false);
  const [generateApks, setGenerateApks] = useState(true);
  const [profile, setProfile] = useState<"balanced" | "strict">("strict");
  const [prefixesText, setPrefixesText] = useState("");
  const [currentStep, setCurrentStep] = useState("");
  const [currentDetail, setCurrentDetail] = useState("");
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [finishedAt, setFinishedAt] = useState<number | null>(null);
  const taskId = useRef<string | null>(null);
  const checkSequence = useRef(0);

  useEffect(() => {
    if (!certificatesLoaded) return;
    setSelectedCertificateId((current) => certificates.some((item) => item.id === current)
      ? current
      : defaultCertificate?.id ?? certificates[0]?.id ?? "");
  }, [certificates, certificatesLoaded, defaultCertificate]);

  const output = input && outputFilename
    ? joinPath(outputDirectory || dirname(input), normalizeAabFilename(outputFilename))
    : "";
  const apksOutput = generateApks && input
    ? joinPath(outputDirectory || dirname(input), protectedApksFilename(input))
    : null;
  const prefixes = useMemo(
    () => prefixesText.split(/[,\s]+/).map((value) => value.trim()).filter(Boolean),
    [prefixesText],
  );
  const prefixValid = prefixes.every((prefix) => prefix.length >= 6 && prefix.startsWith("L") && (prefix.endsWith("/") || prefix.endsWith(";")) && !prefix.includes(".."));
  const certificate = certificates.find((item) => item.id === selectedCertificateId) ?? null;
  const filenameError = validateAabOutputFilename(outputFilename);
  const runtimeCertValid = allowUploadCertBinding || /^[0-9a-fA-F:]{64,95}$/.test(runtimeCertSha256.trim());
  const toolsReady = Boolean(buildInfo?.bundletool_bundled && buildInfo?.aapt2_bundled && buildInfo?.xop_pvm2_packer_bundled);
  const multiModule = (inspection?.modules.length ?? 0) > 1;
  const locked = state === "running" || state === "prechecking";
  const startDisabled = locked || !runtimeInfoLoaded || !toolsReady || !inspection || !certificate
    || Boolean(filenameError) || !runtimeCertValid || !prefixValid
    || (profile === "strict" && prefixes.length === 0) || (multiModule && profile !== "strict");

  const runPreflight = useCallback(async (path: string) => {
    const sequence = ++checkSequence.current;
    setState("prechecking");
    setInspection(null);
    setError("");
    try {
      const result = await api.checkAab(path);
      if (sequence !== checkSequence.current) return;
      setInspection(result);
      if (result.application_id) {
        setPrefixesText(`L${result.application_id.replace(/\./g, "/")}/`);
      }
      if (result.modules.length > 1) setProfile("strict");
      setState("idle");
    } catch (cause) {
      if (sequence !== checkSequence.current) return;
      const message = String(cause);
      setError(message);
      setState("failed");
      notifyError(message);
    }
  }, []);

  const handleSelected = useCallback((path: string) => {
    if (locked) return;
    if (!isAab(path)) {
      const message = t(locale, "onlyAab");
      setWarning(message);
      notifyError(message);
      return;
    }
    setInput(path);
    setOutputDirectory(dirname(path));
    setOutputFilename(protectedAabFilename(path));
    setInspection(null);
    setWarning("");
    setError("");
    setPrefixesText("");
    setCurrentStep("");
    setCurrentDetail("");
    setStartedAt(null);
    setFinishedAt(null);
    void runPreflight(path);
  }, [locale, locked, runPreflight]);

  const browse = useCallback(async () => {
    const path = await openFileDialog("AAB", ["aab"]);
    if (path) handleSelected(path);
  }, [handleSelected]);

  useEffect(() => {
    if (!active) { setDragActive(false); return; }
    const unlisten = Promise.all([
      onTauriEvent<DragDropPayload>("tauri://drag-drop", (payload) => {
        setDragActive(false);
        const path = payload.paths?.[0];
        if (path) handleSelected(path);
      }),
      onTauriEvent<void>("tauri://drag-enter", () => setDragActive(true)),
      onTauriEvent<void>("tauri://drag-leave", () => setDragActive(false)),
    ]);
    return () => { void unlisten.then((items) => items.forEach((fn) => fn())); };
  }, [active, handleSelected]);

  useEffect(() => {
    const unlisten = onTauriEvent<TaskSnapshot>("task-state", (task) => {
      if (task.kind !== "protect" || task.task_id !== taskId.current) return;
      setCurrentStep(task.current_step);
      setCurrentDetail(task.logs.at(-1)?.message ?? "");
      setStartedAt(task.started_at_ms);
      setFinishedAt(task.finished_at_ms ?? null);
      if (task.status === "failed" || task.status === "cancelled") {
        setError(task.error ?? t(locale, "failed"));
        setState("failed");
      }
    });
    return () => { void unlisten.then((fn) => fn()); };
  }, [locale]);

  async function chooseOutputDirectory() {
    const directory = await openDirectoryDialog(outputDirectory || dirname(input));
    if (directory) setOutputDirectory(directory);
  }

  async function start() {
    if (startDisabled || !certificate || !inspection) return;
    if (await api.checkFileExists(output) && !window.confirm(t(locale, "confirmOverwriteOutput"))) return;
    if (apksOutput && await api.checkFileExists(apksOutput) && !window.confirm(t(locale, "confirmOverwriteOutput"))) return;
    taskId.current = crypto.randomUUID();
    setState("running");
    setError("");
    setCurrentStep("CheckTools");
    setCurrentDetail("");
    setStartedAt(Date.now());
    setFinishedAt(null);
    try {
      await api.protectAab({
        taskId: taskId.current,
        input,
        output,
        apksOutput,
        certificateId: certificate.id,
        runtimeCertSha256: allowUploadCertBinding ? null : runtimeCertSha256.trim(),
        allowUploadCertBinding,
        playDeliveryAdapter,
        environmentPolicy: "compatible",
        protectionProfile: profile,
        aiResistance: profile === "strict" ? "high" : "balanced",
        xopTrueVmpPrefixes: profile === "strict" ? prefixes : [],
      });
      setFinishedAt(Date.now());
      setState("done");
      notifySuccess(t(locale, "aabProtectCompleted"));
    } catch (cause) {
      const message = String(cause);
      setError(message);
      setState("failed");
      notifyError(message);
    }
  }

  function reset() {
    checkSequence.current += 1;
    taskId.current = null;
    setInput("");
    setOutputDirectory("");
    setOutputFilename("");
    setInspection(null);
    setState("idle");
    setError("");
    setWarning("");
    setPrefixesText("");
    setCurrentStep("");
    setStartedAt(null);
    setFinishedAt(null);
  }

  const steps = [
    "CheckTools", "InspectBundle", "BuildUniversalApk", "Unpack", "ModifyManifest",
    "ProcessDex", "InjectRuntime", "Repack", "AlignApk", "SignApk", "RebuildBundle",
    "SignAab", "ValidateBundle", ...(generateApks ? ["BuildApks"] : []),
  ];

  return (
    <section className="min-h-full px-6 py-8 sm:px-8 lg:px-10 lg:py-9">
      {!input ? (
        <div className="mx-auto w-full max-w-5xl">
          <header className="max-w-3xl">
            <h1 className="text-[28px] font-semibold tracking-tight">{t(locale, "aabProtectTitle")}</h1>
            <p className="mt-2 text-[14px] leading-6 text-muted-foreground">{t(locale, "aabProtectDesc")}</p>
          </header>
          <div className="mt-7">
            <DropZone locale={locale} active={dragActive} title={t(locale, "dropAab")} subtitle={t(locale, "onlyAab")} ariaLabel={t(locale, "selectAab")} onBrowse={() => void browse()} />
          </div>
          {warning && <div className="mt-5"><StatusMessage kind="warning">{warning}</StatusMessage></div>}
          {runtimeInfoLoaded && !toolsReady && <div className="mt-5"><StatusMessage kind="error">{t(locale, "aabToolsMissing")}</StatusMessage></div>}
        </div>
      ) : (
        <div className="mx-auto w-full max-w-6xl">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div><h1 className="text-[28px] font-semibold">{t(locale, "aabProtectTitle")}</h1><p className="mt-1 text-sm text-muted-foreground">{inspection?.application_id ?? input}</p></div>
            {state === "running" ? (
              <AppButton variant="danger" onClick={() => void api.cancelProtect()}><Square className="h-4 w-4" />{t(locale, "cancel")}</AppButton>
            ) : (state === "done" || state === "failed") && (
              <AppButton variant="secondary" onClick={reset}><RotateCcw className="h-4 w-4" />{t(locale, "protectAnother")}</AppButton>
            )}
          </div>

          <div className="mt-8 grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
            <div className="space-y-4">
              <SelectedApkCard locale={locale} path={input} output={output} disabled={locked} selectedLabel={t(locale, "selectedAab")} changeLabel={t(locale, "changeAab")} onChange={() => void browse()} />
              <div className="rounded-[14px] border bg-card p-4">
                <label className="field-label" htmlFor="aab-output-name">{t(locale, "outputFilename")}</label>
                <TextInput id="aab-output-name" className="mt-2 font-mono" value={outputFilename} disabled={locked} onChange={(event) => setOutputFilename(event.target.value)} />
                {filenameError && <p className="mt-2 text-xs text-destructive">{t(locale, filenameError === "empty" ? "outputFilenameRequired" : "outputFilenameInvalid")}</p>}
                <div className="mt-3 flex items-center justify-between gap-3 rounded-xl bg-muted/50 p-3">
                  <div className="min-w-0"><div className="text-xs font-medium text-muted-foreground">{t(locale, "saveLocation")}</div><div className="path-text mt-1">{outputDirectory}</div></div>
                  <AppButton size="sm" variant="secondary" disabled={locked} onClick={() => void chooseOutputDirectory()}><FolderOpen className="h-4 w-4" />{t(locale, "change")}</AppButton>
                </div>
              </div>

              {state === "prechecking" && <StatusMessage kind="info">{t(locale, "prechecking")}</StatusMessage>}
              {inspection && (
                <div className="rounded-[14px] border border-success/30 bg-success/5 p-4">
                  <div className="font-medium text-success">{t(locale, "aabPreflightPassed")}</div>
                  <div className="mt-3 grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
                    <Summary label={t(locale, "aabModules")} value={String(inspection.modules.length)} />
                    <Summary label={t(locale, "aabDexEntries")} value={String(inspection.dex_entries)} />
                    <Summary label={t(locale, "aabApplicationId")} value={inspection.application_id ?? "-"} />
                  </div>
                  <div className="mt-3 text-xs text-muted-foreground">{inspection.modules.join(" · ")}</div>
                </div>
              )}
              {state === "done" && <StatusMessage kind="success" action={<AppButton size="sm" variant="secondary" onClick={() => void api.showInFolder(output)}><FolderOpen className="h-4 w-4" />{t(locale, "showInFolder")}</AppButton>}>{t(locale, "aabProtectCompleted")}</StatusMessage>}
              {error && <StatusMessage kind="error"><b>{t(locale, "errorDetail")}：</b>{error}</StatusMessage>}
            </div>

            {state === "running" || state === "done" ? (
              <ProtectProgressPanel locale={locale} state={state} currentStep={currentStep} currentDetail={currentDetail} steps={steps} showProgress startedAt={startedAt} finishedAt={finishedAt} />
            ) : (
              <aside className="rounded-[14px] border bg-card p-5">
                <h2 className="text-base font-semibold">{t(locale, "aabProtectionPlan")}</h2>
                <div className="mt-5 space-y-5">
                  <Field label={t(locale, "protectionProfile")}>
                    <SelectInput value={profile} disabled={locked} onChange={(event) => setProfile(event.target.value as "balanced" | "strict")}>
                      <option value="strict">{t(locale, "aabStrictProfile")}</option>
                      <option value="balanced" disabled={multiModule}>{t(locale, "aabBalancedProfile")}</option>
                    </SelectInput>
                  </Field>
                  <Field label={t(locale, "signConfig")}>
                    <SelectInput value={selectedCertificateId} disabled={locked || !certificates.length} onChange={(event) => setSelectedCertificateId(event.target.value)}>
                      {!certificates.length && <option value="">{t(locale, "noCertificates")}</option>}
                      {certificates.map((item) => <option key={item.id} value={item.id}>{item.name}{item.is_default ? ` · ${t(locale, "defaultCertificate")}` : ""}</option>)}
                    </SelectInput>
                    {!certificates.length && <AppButton className="mt-2 w-full" size="sm" variant="secondary" onClick={onOpenCertificates}>{t(locale, "navCertificates")}</AppButton>}
                  </Field>
                  {profile === "strict" && (
                    <Field label={t(locale, "aabPvmPrefixes")} hint={t(locale, "aabPvmPrefixesHint")}>
                      <TextInput className="font-mono" value={prefixesText} disabled={locked} placeholder="Lcom/acme/app/" onChange={(event) => setPrefixesText(event.target.value)} />
                      {(!prefixValid || !prefixes.length) && <p className="mt-2 text-xs text-warning">{t(locale, prefixes.length ? "xopPvm2PrefixInvalid" : "xopPvm2StrictRequired")}</p>}
                    </Field>
                  )}
                  <Field label={t(locale, "aabRuntimeBinding")}>
                    <CheckRow checked={allowUploadCertBinding} disabled={locked} label={t(locale, "aabLocalUploadBinding")} hint={t(locale, "aabLocalUploadBindingHint")} onChange={setAllowUploadCertBinding} />
                    {!allowUploadCertBinding && <div className="mt-3"><TextInput className="font-mono" value={runtimeCertSha256} disabled={locked} placeholder="AA:BB:…" onChange={(event) => setRuntimeCertSha256(event.target.value)} /><p className="mt-2 text-xs text-muted-foreground">{t(locale, "aabPlayCertificateHint")}</p></div>}
                  </Field>
                  <CheckRow checked={playDeliveryAdapter} disabled={locked} label={t(locale, "aabPlayDeliveryAdapter")} hint={t(locale, "aabPlayDeliveryAdapterHint")} onChange={setPlayDeliveryAdapter} />
                  <CheckRow checked={generateApks} disabled={locked} label={t(locale, "aabGenerateApks")} hint={t(locale, "aabGenerateApksHint")} onChange={setGenerateApks} />
                  {!toolsReady && runtimeInfoLoaded && <StatusMessage kind="error">{t(locale, "aabToolsMissing")}</StatusMessage>}
                  <AppButton className="w-full" disabled={startDisabled} onClick={() => void start()}>{t(locale, "startAabProtect")}</AppButton>
                </div>
              </aside>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <div><div className="mb-2 text-sm font-medium">{label}</div>{children}{hint && <p className="mt-2 text-xs leading-5 text-muted-foreground">{hint}</p>}</div>;
}

function CheckRow({ checked, disabled, label, hint, onChange }: { checked: boolean; disabled: boolean; label: string; hint: string; onChange: (value: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-border/70 p-3 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring">
      <input type="checkbox" className="mt-1 h-4 w-4 accent-primary" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
      <span><span className="block text-sm font-medium">{label}</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">{hint}</span></span>
    </label>
  );
}

function Summary({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><div className="text-xs text-muted-foreground">{label}</div><div className="mt-1 truncate font-medium" title={value}>{value}</div></div>;
}
