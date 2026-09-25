import { FolderKey, FolderOpen, Play, Settings2 } from "lucide-react";
import { AppButton, SelectInput, TextInput } from "@/components/app/common";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import type { AiResistance, EnvironmentPolicy, ProtectionProfile, RuntimeMode } from "@/hooks/use-protect-workflow";
import { t, tf, type Locale } from "@/lib/i18n";
import type { CertificateRecord } from "@/lib/tauri";

export function ProtectConfigurationPanel({
  locale,
  disabled,
  startDisabled,
  sharingControl,
  runtimeMode,
  runtimeModeGuidance,
  environmentPolicy,
  protectionProfile,
  aiResistance,
  usingRecommendedProtection,
  xopPvm2PackerPath,
  xopTrueVmpPrefixesText,
  xopTrueVmpPrefixes,
  xopPvm2BuiltInAvailable,
  xopPvm2JavaReady,
  xopPvm2MinJavaMajor,
  signAfterProtect,
  selectedCertificateId,
  certificates,
  outputDirectoryMode,
  fixedOutputDirectory,
  onRuntimeModeChange,
  onEnvironmentPolicyChange,
  onProtectionProfileChange,
  onAiResistanceChange,
  onXopPvm2PackerPathChange,
  onUseBuiltInXopPvm2Packer,
  onXopTrueVmpPrefixesTextChange,
  onChooseXopPvm2Packer,
  onSignAfterProtectChange,
  onCertificateChange,
  onOutputDirectoryModeChange,
  onChooseDirectory,
  onOpenCertificates,
  onRestoreRecommended,
  onStart,
}: {
  locale: Locale;
  disabled: boolean;
  startDisabled: boolean;
  sharingControl: React.ReactNode;
  runtimeMode: RuntimeMode;
  runtimeModeGuidance?: string;
  environmentPolicy: EnvironmentPolicy;
  protectionProfile: ProtectionProfile;
  aiResistance: AiResistance;
  usingRecommendedProtection: boolean;
  xopPvm2PackerPath: string;
  xopTrueVmpPrefixesText: string;
  xopTrueVmpPrefixes: string[];
  xopPvm2BuiltInAvailable: boolean;
  xopPvm2JavaReady: boolean;
  xopPvm2MinJavaMajor: number;
  signAfterProtect: boolean;
  selectedCertificateId: string;
  certificates: CertificateRecord[];
  outputDirectoryMode: "source" | "fixed";
  fixedOutputDirectory: string;
  onRuntimeModeChange: (value: RuntimeMode) => void;
  onEnvironmentPolicyChange: (value: EnvironmentPolicy) => void;
  onProtectionProfileChange: (value: ProtectionProfile) => void;
  onAiResistanceChange: (value: AiResistance) => void;
  onXopPvm2PackerPathChange: (value: string) => void;
  onUseBuiltInXopPvm2Packer: () => void;
  onXopTrueVmpPrefixesTextChange: (value: string) => void;
  onChooseXopPvm2Packer: () => void;
  onSignAfterProtectChange: (value: boolean) => void;
  onCertificateChange: (value: string) => void;
  onOutputDirectoryModeChange: (value: "source" | "fixed") => void;
  onChooseDirectory: () => void;
  onOpenCertificates: () => void;
  onRestoreRecommended: () => void;
  onStart: () => void;
}) {
  const invalidPvmPrefix = xopTrueVmpPrefixes.some((prefix) => prefix.length < 6 || !prefix.startsWith("L") || (!prefix.endsWith("/") && !prefix.endsWith(";")) || prefix.includes(".."));
  const customPvmPacker = Boolean(xopPvm2PackerPath.trim());
  const pvmPackerAvailable = customPvmPacker || xopPvm2BuiltInAvailable;
  const pvmReady = pvmPackerAvailable && xopTrueVmpPrefixes.length > 0 && !invalidPvmPrefix && xopPvm2JavaReady && runtimeMode === "standard";
  return (
    <aside className="rounded-[14px] border bg-card p-5">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold">{t(locale, "protectPlan")}</h2>
        <Sheet>
          <SheetTrigger asChild>
            <AppButton size="sm" variant="ghost" disabled={disabled}>
              <Settings2 className="h-4 w-4" />
              {t(locale, "modifySettings")}
            </AppButton>
          </SheetTrigger>
          <SheetContent className="w-full overflow-y-auto sm:max-w-md">
            <SheetHeader>
              <SheetTitle>{t(locale, "protectSettings")}</SheetTitle>
              <SheetDescription>{t(locale, "protectSettingsHint")}</SheetDescription>
            </SheetHeader>
            <div className="mt-7 space-y-6">
              <SettingSelect label={t(locale, "targetSystem")} value={runtimeMode} onChange={(value) => onRuntimeModeChange(value as RuntimeMode)} hint={runtimeMode === "android_api19" ? t(locale, "runtimeAndroid44Hint") : t(locale, "runtimeStandardHint")} guidance={runtimeModeGuidance}>
                <option value="standard">{t(locale, "runtimeStandard")}</option>
                <option value="android_api19">{t(locale, "runtimeAndroid44")}</option>
              </SettingSelect>
              <SettingSelect label={t(locale, "environmentPolicy")} value={environmentPolicy} onChange={(value) => onEnvironmentPolicyChange(value as EnvironmentPolicy)} hint={environmentPolicy === "strict" ? t(locale, "environmentStrictHint") : t(locale, "environmentCompatibleHint")}>
                <option value="compatible">{t(locale, "environmentCompatible")}</option>
                <option value="strict">{t(locale, "environmentStrict")}</option>
              </SettingSelect>
              <SettingSelect label={t(locale, "protectionProfile")} value={protectionProfile} onChange={(value) => onProtectionProfileChange(value as ProtectionProfile)} hint={t(locale, "protectionProfileHint")}>
                <option value="compat">{t(locale, "protectionCompat")}</option>
                <option value="balanced">{t(locale, "protectionBalanced")}</option>
                <option value="strict">{t(locale, "protectionStrict")}</option>
              </SettingSelect>
              <SettingSelect label={t(locale, "aiResistance")} value={aiResistance} onChange={(value) => onAiResistanceChange(value as AiResistance)} hint={t(locale, "aiResistanceHint")}>
                <option value="off">{t(locale, "aiResistanceOff")}</option>
                <option value="balanced">{t(locale, "aiResistanceBalanced")}</option>
                <option value="high">{t(locale, "aiResistanceHigh")}</option>
              </SettingSelect>
              <div className="rounded-xl border p-4">
                <div className="text-sm font-medium">{t(locale, "xopPvm2")}</div>
                <p className="mt-2 text-xs leading-5 text-muted-foreground">{t(locale, "xopPvm2Hint")}</p>
                <label className="field-label mt-4 block" htmlFor="xop-pvm2-packer">{t(locale, "xopPvm2Packer")}</label>
                <TextInput
                  id="xop-pvm2-packer"
                  className="mt-2 font-mono"
                  value={customPvmPacker ? xopPvm2PackerPath : xopPvm2BuiltInAvailable ? t(locale, "xopPvm2BuiltInValue") : ""}
                  readOnly={!customPvmPacker && xopPvm2BuiltInAvailable}
                  onChange={(event) => onXopPvm2PackerPathChange(event.target.value)}
                />
                <p className="mt-2 text-xs leading-5 text-muted-foreground">{t(locale, customPvmPacker ? "xopPvm2CustomSelected" : xopPvm2BuiltInAvailable ? "xopPvm2BuiltInReady" : "xopPvm2BuiltInMissing")}</p>
                <AppButton className="mt-2 w-full" variant="secondary" onClick={onChooseXopPvm2Packer}>
                  <FolderOpen className="h-4 w-4" />{t(locale, "chooseXopPvm2Packer")}
                </AppButton>
                {customPvmPacker && <AppButton className="mt-2 w-full" variant="ghost" onClick={onUseBuiltInXopPvm2Packer}>{t(locale, "useBuiltInXopPvm2Packer")}</AppButton>}
                <label className="field-label mt-4 block" htmlFor="xop-vmp-prefixes">{t(locale, "xopTrueVmpPrefixes")}</label>
                <TextInput
                  id="xop-vmp-prefixes"
                  className="mt-2 font-mono"
                  value={xopTrueVmpPrefixesText}
                  placeholder="L<你的实际包路径>/business/"
                  onChange={(event) => onXopTrueVmpPrefixesTextChange(event.target.value)}
                />
                <p className="mt-2 text-xs leading-5 text-muted-foreground">{t(locale, "xopTrueVmpPrefixesHint")}</p>
                {invalidPvmPrefix && <p className="mt-2 text-xs leading-5 text-warning">{t(locale, "xopPvm2PrefixInvalid")}</p>}
                {!xopPvm2JavaReady && xopTrueVmpPrefixes.length > 0 && <p className="mt-2 text-xs leading-5 text-warning">{tf(locale, "xopPvm2JavaRequired", { min: xopPvm2MinJavaMajor })}</p>}
                {runtimeMode === "android_api19" && <p className="mt-2 text-xs leading-5 text-warning">{t(locale, "xopPvm2Api19Unavailable")}</p>}
                {runtimeMode === "standard" && protectionProfile === "strict" && (!pvmPackerAvailable || xopTrueVmpPrefixes.length === 0) && <p className="mt-2 text-xs leading-5 text-warning">{t(locale, "xopPvm2StrictRequired")}</p>}
              </div>
              <div className="rounded-xl border p-4">
                <label className="flex items-center justify-between gap-4 text-sm font-medium">
                  <span>{t(locale, "signAfterProtect")}</span>
                  <input type="checkbox" className="h-4 w-4 accent-primary" checked={signAfterProtect} onChange={(event) => onSignAfterProtectChange(event.target.checked)} />
                </label>
                {signAfterProtect && (
                  <div className="mt-4 space-y-3">
                    <SettingSelect label={t(locale, "selectCertificate")} value={selectedCertificateId} onChange={onCertificateChange}>
                      {certificates.length === 0 ? <option value="">{t(locale, "noCertificates")}</option> : certificates.map((item) => (
                        <option key={item.id} value={item.id}>{item.is_default ? `${item.name} · ${t(locale, "defaultCertificate")}` : item.name}</option>
                      ))}
                    </SettingSelect>
                    {certificates.length === 0 && (
                      <AppButton className="w-full" variant="secondary" onClick={onOpenCertificates}>
                        <FolderKey className="h-4 w-4" />{t(locale, "navCertificates")}
                      </AppButton>
                    )}
                  </div>
                )}
              </div>
              <SettingSelect label={t(locale, "saveLocation")} value={outputDirectoryMode} onChange={(value) => onOutputDirectoryModeChange(value as "source" | "fixed")}>
                <option value="source">{t(locale, "sourceDirectory")}</option>
                <option value="fixed">{t(locale, "fixedDirectory")}</option>
              </SettingSelect>
              {outputDirectoryMode === "fixed" && (
                <div>
                  <div className="path-text mb-2 rounded-xl border bg-muted/40 p-3">{fixedOutputDirectory || t(locale, "directoryNotSelected")}</div>
                  <AppButton className="w-full" variant="secondary" onClick={onChooseDirectory}>
                    <FolderOpen className="h-4 w-4" />{t(locale, "chooseDirectory")}
                  </AppButton>
                </div>
              )}
              <AppButton className="w-full" variant="ghost" onClick={onRestoreRecommended}>
                {t(locale, "restoreRecommended")}
              </AppButton>
            </div>
          </SheetContent>
        </Sheet>
      </div>
      <dl className="mt-5 space-y-3 text-sm">
        <Summary label={t(locale, "targetSystem")} value={runtimeMode === "android_api19" ? t(locale, "runtimeAndroid44") : t(locale, "runtimeStandard")} hint={runtimeMode === "android_api19" ? t(locale, "runtimeAndroid44Summary") : t(locale, "runtimeStandardSummary")} guidance={runtimeModeGuidance} />
        <Summary label={t(locale, "environmentPolicy")} value={environmentPolicy === "strict" ? t(locale, "environmentStrict") : t(locale, "environmentCompatible")} hint={environmentPolicy === "strict" ? t(locale, "environmentStrictSummary") : t(locale, "environmentCompatibleSummary")} />
        <Summary label={t(locale, "protectionProfile")} value={t(locale, protectionProfile === "compat" ? "protectionCompat" : protectionProfile === "strict" ? "protectionStrict" : "protectionBalanced")} />
        <Summary label={t(locale, "aiResistance")} value={t(locale, aiResistance === "off" ? "aiResistanceOff" : aiResistance === "high" ? "aiResistanceHigh" : "aiResistanceBalanced")} />
        <Summary label={t(locale, "xopPvm2")} value={pvmReady ? t(locale, "enabled") : t(locale, "disabled")} guidance={invalidPvmPrefix ? t(locale, "xopPvm2PrefixInvalid") : protectionProfile === "strict" && (!pvmReady || runtimeMode !== "standard") ? t(locale, "xopPvm2StrictRequired") : undefined} />
        <Summary label={t(locale, "resourcePathProtection")} value={protectionProfile === "strict" && pvmReady ? t(locale, "resourcePathProtectionEnabled") : t(locale, "resourcePathProtectionDisabled")} hint={protectionProfile === "strict" && pvmReady ? t(locale, "resourcePathProtectionHint") : undefined} />
        <Summary label={t(locale, "resourceIdProtection")} value={protectionProfile === "strict" && pvmReady ? t(locale, "resourcePathProtectionEnabled") : t(locale, "resourcePathProtectionDisabled")} hint={protectionProfile === "strict" && pvmReady ? t(locale, "resourceIdProtectionHint") : undefined} />
        <Summary label={t(locale, "assetsPas2Protection")} value={protectionProfile === "strict" && pvmReady ? t(locale, "resourcePathProtectionEnabled") : t(locale, "resourcePathProtectionDisabled")} hint={protectionProfile === "strict" && pvmReady ? t(locale, "assetsPas2ProtectionHint") : undefined} />
        <Summary label={t(locale, "signAfterProtect")} value={signAfterProtect ? t(locale, "enabled") : t(locale, "disabled")} />
      </dl>
      {!usingRecommendedProtection && (
        <div className="mt-4 rounded-xl border border-warning/35 bg-warning/8 p-3">
          <p className="text-xs leading-5 text-muted-foreground">{t(locale, "customProtectionSettingsHint")}</p>
          <AppButton className="mt-2 w-full" variant="secondary" disabled={disabled} onClick={onRestoreRecommended}>
            {t(locale, "useRecommendedProtection")}
          </AppButton>
        </div>
      )}
      <div className="mt-4">{sharingControl}</div>
      <AppButton className="mt-3 w-full" disabled={startDisabled} onClick={onStart}>
        <Play className="h-4 w-4" />{t(locale, "startProtect")}
      </AppButton>
    </aside>
  );
}

function SettingSelect({ label, value, onChange, hint, guidance, children }: { label: string; value: string; onChange: (value: string) => void; hint?: string; guidance?: string; children: React.ReactNode }) {
  return <div><label className="field-label">{label}</label><SelectInput className="mt-2" value={value} onChange={(event) => onChange(event.target.value)}>{children}</SelectInput>{hint && <p className="mt-2 text-xs leading-5 text-muted-foreground">{hint}</p>}{guidance && <p className="mt-2 text-xs leading-5 text-warning">{guidance}</p>}</div>;
}

function Summary({ label, value, hint, guidance }: { label: string; value: string; hint?: string; guidance?: string }) {
  return <div className="border-b pb-3 last:border-b-0 last:pb-0"><div className="flex items-start justify-between gap-3"><dt className="text-muted-foreground">{label}</dt><dd className="text-right font-medium">{value}</dd></div>{hint && <p className="mt-1.5 text-xs leading-5 text-muted-foreground">{hint}</p>}{guidance && <p className="mt-2 text-xs leading-5 text-warning">{guidance}</p>}</div>;
}
