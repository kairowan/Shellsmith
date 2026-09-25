import { useEffect, useMemo, useState } from "react";
import { FolderOpen, LoaderCircle, Play, RotateCcw, Search, Square } from "lucide-react";
import { AppButton, SelectInput, StatusMessage, TextInput } from "@/components/app/common";
import { t, type Locale } from "@/lib/i18n";
import { notifyError, notifySuccess } from "@/lib/notify";
import {
  api,
  onTauriEvent,
  openDirectoryDialog,
  openFileDialog,
  type IosCheck,
  type IosProjectInspection,
  type IosProtectionReport,
  type TaskSnapshot,
} from "@/lib/tauri";

type Profile = "compat" | "balanced" | "strict";

export function IosProtectPage({ active, locale }: { active: boolean; locale: Locale }) {
  const [project, setProject] = useState("");
  const [scheme, setScheme] = useState("");
  const [configuration, setConfiguration] = useState("Release");
  const [teamId, setTeamId] = useState("");
  const [bundleIds, setBundleIds] = useState("");
  const [entrypoint, setEntrypoint] = useState("");
  const [output, setOutput] = useState("");
  const [profile, setProfile] = useState<Profile>("balanced");
  const [confidentialConfig, setConfidentialConfig] = useState("");
  const [watcherMail, setWatcherMail] = useState("");
  const [appAttestEndpoint, setAppAttestEndpoint] = useState("");
  const [exportOptions, setExportOptions] = useState("");
  const [exportMethod, setExportMethod] = useState("development");
  const [allowProvisioningUpdates, setAllowProvisioningUpdates] = useState(false);
  const [inspection, setInspection] = useState<IosProjectInspection | null>(null);
  const [report, setReport] = useState<IosProtectionReport | null>(null);
  const [checking, setChecking] = useState(false);
  const [running, setRunning] = useState(false);
  const [step, setStep] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const unlisten = onTauriEvent<TaskSnapshot>("task-state", (task) => {
      if (task.kind !== "ios_protect") return;
      setRunning(task.status === "running");
      setStep(task.current_step);
      if (task.error) setError(task.error);
    });
    return () => { void unlisten.then((fn) => fn()); };
  }, []);

  const checks = useMemo(() => [
    ...(inspection?.checks ?? []),
    ...(report?.checks ?? []),
  ].filter((check, index, items) => items.findIndex((item) => item.code === check.code && item.message === check.message) === index), [inspection, report]);
  const buildBlocked = !inspection?.xcode.available || inspection.checks.some((check) => check.severity === "blocked" && check.code !== "xcode");
  const profileReady = profile === "compat" || Boolean(confidentialConfig.trim() && watcherMail.trim());
  const strictReady = profile !== "strict" || /^https:\/\/\S+$/.test(appAttestEndpoint.trim());
  const formReady = Boolean(project && scheme.trim() && /^[A-Z0-9]{10}$/.test(teamId.trim()) && bundleIds.trim() && output && profileReady && strictReady);

  async function chooseProject() {
    const path = await openFileDialog("Xcode", ["xcodeproj", "xcworkspace"]);
    if (!path) return;
    setProject(path);
    setInspection(null);
    setReport(null);
    setError("");
  }

  async function runCheck() {
    if (!project) return;
    setChecking(true);
    setError("");
    try {
      const result = await api.checkIosProject(project, scheme.trim() || null);
      setInspection(result);
      if (!scheme && result.schemes.length === 1) setScheme(result.schemes[0]);
      const app = result.targets.find((target) => target.product_type === "com.apple.product-type.application") ?? result.targets[0];
      if (app?.team_id && !teamId) setTeamId(app.team_id);
      if (app?.bundle_id && !bundleIds) setBundleIds(app.bundle_id);
    } catch (reason) {
      const message = String(reason);
      setError(message);
      notifyError(message);
    } finally {
      setChecking(false);
    }
  }

  async function start() {
    if (!formReady || buildBlocked || running) return;
    setRunning(true);
    setReport(null);
    setError("");
    try {
      const result = await api.protectIosProject({
        taskId: crypto.randomUUID(),
        project,
        scheme: scheme.trim(),
        configuration: configuration.trim() || "Release",
        teamId: teamId.trim(),
        bundleIds: bundleIds.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean),
        entrypoint: entrypoint.trim() || null,
        output,
        profile,
        confidentialConfig: profile === "compat" ? null : confidentialConfig,
        watcherMail: profile === "compat" ? null : watcherMail.trim(),
        isProd: true,
        appAttestEndpoint: profile === "strict" ? appAttestEndpoint.trim() : null,
        exportOptions: exportOptions || null,
        exportMethod,
        allowProvisioningUpdates,
        dryRun: false,
      });
      setReport(result);
      setInspection(result.inspection);
      notifySuccess(t(locale, "iosProtectCompleted"));
    } catch (reason) {
      const message = String(reason);
      setError(message);
      notifyError(message);
    } finally {
      setRunning(false);
    }
  }

  function reset() {
    setProject("");
    setInspection(null);
    setReport(null);
    setError("");
    setStep("");
  }

  if (!active) return null;

  return (
    <section className="min-h-full px-6 pb-8 sm:px-8 lg:px-10 lg:pb-9">
      <div className="mx-auto w-full max-w-6xl">
        <header className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-3xl">
            <h1 className="text-[28px] font-semibold tracking-tight">{t(locale, "iosProtectTitle")}</h1>
            <p className="mt-2 text-[14px] leading-6 text-muted-foreground">{t(locale, "iosProtectDesc")}</p>
          </div>
          {project && !running && <AppButton variant="secondary" onClick={reset}><RotateCcw className="h-4 w-4" />{t(locale, "reset")}</AppButton>}
          {running && <AppButton variant="danger" onClick={() => void api.cancelIosProtect()}><Square className="h-4 w-4" />{t(locale, "cancel")}</AppButton>}
        </header>

        <div className="mt-7 grid gap-5 lg:grid-cols-[minmax(0,1fr)_360px]">
          <div className="space-y-4">
            <Panel title={t(locale, "iosProject") }>
              <PathChooser value={project} placeholder={t(locale, "iosProjectNotSelected")} button={t(locale, "chooseIosProject")} disabled={running} onChoose={() => void chooseProject()} />
              <div className="mt-4 grid gap-4 sm:grid-cols-2">
                <Field label="Scheme"><TextInput value={scheme} disabled={running} onChange={(event) => setScheme(event.target.value)} placeholder="App" /></Field>
                <Field label={t(locale, "iosConfiguration")}><TextInput value={configuration} disabled={running} onChange={(event) => setConfiguration(event.target.value)} /></Field>
                <Field label="Apple Team ID"><TextInput value={teamId} disabled={running} onChange={(event) => setTeamId(event.target.value.toUpperCase())} placeholder="ABCDE12345" maxLength={10} /></Field>
                <Field label="Bundle ID"><TextInput value={bundleIds} disabled={running} onChange={(event) => setBundleIds(event.target.value)} placeholder="com.example.app" /></Field>
              </div>
              <Field className="mt-4" label={t(locale, "iosEntrypoint")} hint={t(locale, "iosEntrypointHint")}><TextInput value={entrypoint} disabled={running} onChange={(event) => setEntrypoint(event.target.value)} placeholder="App/App.swift" /></Field>
              <AppButton className="mt-4" variant="secondary" disabled={!project || checking || running} onClick={() => void runCheck()}>
                {checking ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}{t(locale, "checkIosProject")}
              </AppButton>
            </Panel>

            {checks.length > 0 && <CheckList locale={locale} checks={checks} />}
            {inspection && !inspection.xcode.available && <StatusMessage kind="warning">{t(locale, "iosXcodeRequired")} {inspection.xcode.diagnostic}</StatusMessage>}
            {step && running && <StatusMessage kind="info">{t(locale, "currentStep")}：{step}</StatusMessage>}
            {error && <StatusMessage kind="error">{error}</StatusMessage>}
            {report?.ipa && <StatusMessage kind="success" action={<AppButton size="sm" variant="secondary" onClick={() => void api.showInFolder(report.ipa!)}><FolderOpen className="h-4 w-4" />{t(locale, "showInFolder")}</AppButton>}>{t(locale, "iosProtectCompleted")}</StatusMessage>}
          </div>

          <aside className="space-y-4">
            <Panel title={t(locale, "iosProtectionPlan")}>
              <Field label={t(locale, "protectionProfile")}>
                <SelectInput value={profile} disabled={running} onChange={(event) => setProfile(event.target.value as Profile)}>
                  <option value="compat">{t(locale, "protectionCompat")}</option>
                  <option value="balanced">{t(locale, "protectionBalanced")}</option>
                  <option value="strict">{t(locale, "iosProtectionStrict")}</option>
                </SelectInput>
              </Field>
              {profile !== "compat" && <>
                <Field className="mt-4" label="confidential.yml"><PathChooser value={confidentialConfig} placeholder={t(locale, "notSelected")} button={t(locale, "chooseFile")} disabled={running} onChoose={async () => { const value = await openFileDialog("YAML", ["yml", "yaml"]); if (value) setConfidentialConfig(value); }} /></Field>
                <Field className="mt-4" label="freeRASP watcherMail"><TextInput type="email" value={watcherMail} disabled={running} onChange={(event) => setWatcherMail(event.target.value)} placeholder="security@example.com" /></Field>
              </>}
              {profile === "strict" && <Field className="mt-4" label="App Attest Endpoint" hint={t(locale, "appAttestHint")}><TextInput value={appAttestEndpoint} disabled={running} onChange={(event) => setAppAttestEndpoint(event.target.value)} placeholder="https://api.example.com/attest" /></Field>}
              <Field className="mt-4" label={t(locale, "iosExportMethod")}>
                <SelectInput value={exportMethod} disabled={running} onChange={(event) => setExportMethod(event.target.value)}>
                  <option value="development">development</option>
                  <option value="ad-hoc">ad-hoc</option>
                  <option value="app-store-connect">app-store-connect</option>
                  <option value="enterprise">enterprise</option>
                </SelectInput>
              </Field>
              <Field className="mt-4" label="ExportOptions.plist"><PathChooser value={exportOptions} placeholder={t(locale, "iosAutomaticExportOptions")} button={t(locale, "chooseFile")} disabled={running} onChoose={async () => { const value = await openFileDialog("Property List", ["plist"]); if (value) setExportOptions(value); }} /></Field>
              <label className="mt-4 flex items-start gap-3 text-sm">
                <input type="checkbox" className="mt-0.5 h-4 w-4 accent-primary" checked={allowProvisioningUpdates} disabled={running} onChange={(event) => setAllowProvisioningUpdates(event.target.checked)} />
                <span><b>{t(locale, "iosAllowProvisioning")}</b><span className="mt-1 block text-xs leading-5 text-muted-foreground">{t(locale, "iosAllowProvisioningHint")}</span></span>
              </label>
            </Panel>
            <Panel title={t(locale, "saveLocation")}>
              <PathChooser value={output} placeholder={t(locale, "directoryNotSelected")} button={t(locale, "chooseDirectory")} disabled={running} onChoose={async () => { const value = await openDirectoryDialog(output || undefined); if (value) setOutput(value); }} />
            </Panel>
            <AppButton className="w-full" disabled={!formReady || buildBlocked || running} onClick={() => void start()}><Play className="h-4 w-4" />{t(locale, "startIosProtect")}</AppButton>
          </aside>
        </div>
      </div>
    </section>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="rounded-[14px] border bg-card p-5"><h2 className="text-sm font-semibold">{title}</h2><div className="mt-4">{children}</div></div>;
}

function Field({ label, hint, className = "", children }: { label: string; hint?: string; className?: string; children: React.ReactNode }) {
  return <label className={`block ${className}`}><span className="field-label">{label}</span><span className="mt-2 block">{children}</span>{hint && <span className="mt-2 block text-xs leading-5 text-muted-foreground">{hint}</span>}</label>;
}

function PathChooser({ value, placeholder, button, disabled, onChoose }: { value: string; placeholder: string; button: string; disabled: boolean; onChoose: () => void | Promise<void> }) {
  return <div><div className="path-text min-h-10 rounded-xl border bg-muted/40 p-3">{value || placeholder}</div><AppButton className="mt-2 w-full" variant="secondary" disabled={disabled} onClick={() => void onChoose()}><FolderOpen className="h-4 w-4" />{button}</AppButton></div>;
}

function CheckList({ locale, checks }: { locale: Locale; checks: IosCheck[] }) {
  return <Panel title={t(locale, "iosInspectionResult")}><div className="space-y-2">{checks.map((check) => <div key={`${check.code}-${check.message}`} className="rounded-xl border p-3"><div className="flex items-start justify-between gap-3"><div className="text-sm font-medium">{check.message}</div><span className={`rounded-full px-2 py-0.5 text-[11px] ${check.severity === "blocked" ? "bg-destructive/10 text-destructive" : check.severity === "warning" ? "bg-warning/10 text-warning" : "bg-success/10 text-success"}`}>{t(locale, check.severity === "blocked" ? "blocked" : check.severity === "warning" ? "warning" : "ready")}</span></div>{check.reference && <button type="button" className="mt-2 text-xs text-primary hover:underline" onClick={() => void api.openUrl(check.reference!)}>{t(locale, "viewReference")}</button>}</div>)}</div></Panel>;
}
