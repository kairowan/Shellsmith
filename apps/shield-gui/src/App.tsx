import { useEffect, useState } from "react";
import { FolderKey, Info, LoaderCircle, PencilLine, Settings, ShieldCheck } from "lucide-react";
import { Toaster } from "sonner";
import { AppSidebarHeader, UpdateBanner } from "@/components/app/common";
import { UpdateDialog } from "@/components/app/update-dialog";
import { ErrorReportDialog } from "@/components/app/error-report-dialog";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarSeparator,
} from "@/components/ui/sidebar";
import { useAppConfigState, useAutoUpdateNotice } from "@/hooks/use-app-config";
import { useAppliedThemeMode } from "@/hooks/use-applied-theme-mode";
import { useCertificatesState } from "@/hooks/use-certificates";
import { useRuntimeInfo } from "@/hooks/use-runtime-info";
import { t } from "@/lib/i18n";
import { notifyError } from "@/lib/notify";
import { api, onTauriEvent, type BuildInfo, type TaskKind, type TaskSnapshot } from "@/lib/tauri";
import { AboutPage } from "@/pages/about-page";
import { AabProtectPage } from "@/pages/aab-protect-page";
import { CertificatesPage } from "@/pages/certificates-page";
import { ProtectPage } from "@/pages/protect-page";
import { IosProtectPage } from "@/pages/ios-protect-page";
import { SettingsPage } from "@/pages/settings-page";
import { SignPage } from "@/pages/sign-page";

type Page = "protect" | "sign" | "certificates" | "settings" | "about";

export function App() {
  const [page, setPage] = useState<Page>("protect");
  const [protectPlatform, setProtectPlatform] = useState<"android" | "ios">("android");
  const [androidPackageType, setAndroidPackageType] = useState<"apk" | "aab">("apk");
  const {
    locale,
    setLocale,
    themeMode,
    setThemeMode,
    configLoaded,
    telemetryEnabled,
    setTelemetryEnabled,
    protectDefaults,
    setProtectDefaults,
  } = useAppConfigState();
  const certificatesState = useCertificatesState();
  const { updateInfo, setUpdateInfo, majorDialogOpen, setMajorDialogOpen } = useAutoUpdateNotice();
  const { buildInfo, runtimeInfoLoaded, runtimeInfoRefreshing, refreshRuntimeInfo } = useRuntimeInfo();
  const [runningTasks, setRunningTasks] = useState<Partial<Record<TaskKind, boolean>>>({});

  useEffect(() => {
    const unlisten = onTauriEvent<TaskSnapshot>("task-state", (task) => {
      setRunningTasks((current) => ({ ...current, [task.kind]: task.status === "running" }));
    });
    return () => { void unlisten.then((fn) => fn()); };
  }, []);

  useAppliedThemeMode(themeMode);

  const primaryNavItems = [
    { key: "protect" as const, icon: ShieldCheck, label: t(locale, "navProtect") },
    { key: "sign" as const, icon: PencilLine, label: t(locale, "navSign") },
    { key: "certificates" as const, icon: FolderKey, label: t(locale, "navCertificates") },
  ];
  const utilityNavItems = [
    { key: "settings" as const, icon: Settings, label: t(locale, "navSettings") },
    { key: "about" as const, icon: Info, label: t(locale, "navAbout") },
  ];

  async function dismissUpdate(version?: string) {
    if (version) {
      await api.dismissUpdate(version).catch(() => undefined);
    }
    setUpdateInfo(null);
  }

  return (
    <SidebarProvider>
      <div className="flex h-dvh w-full overflow-hidden bg-background text-foreground">
        <Sidebar
          collapsible="icon"
          className="border-r border-sidebar-border/70 bg-sidebar"
        >
          <AppSidebarHeader locale={locale} />
          <SidebarContent className="scrollbar-none px-0 py-3 group-data-[collapsible=icon]:items-center">
            <SidebarGroup className="px-2 py-0 group-data-[collapsible=icon]:items-center">
              <SidebarGroupContent>
                <SidebarMenu className="gap-2 group-data-[collapsible=icon]:items-center">
                  {primaryNavItems.map((item) => (
                    <NavItem
                      key={item.key}
                      page={page}
                      item={item}
                      running={item.key === "protect" ? Boolean(runningTasks.protect || runningTasks.ios_protect) : item.key === "sign" ? runningTasks.sign : false}
                      onSelect={() => setPage(item.key)}
                    />
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>
          <SidebarFooter className="gap-0 px-0 pb-5 pt-2 group-data-[collapsible=icon]:items-center">
            <div className="px-4 group-data-[collapsible=icon]:px-3">
              <SidebarSeparator className="mx-0 opacity-80" />
            </div>
            <SidebarMenu className="gap-2 px-2 pt-3 group-data-[collapsible=icon]:items-center">
              {utilityNavItems.map((item) => (
                <NavItem
                  key={item.key}
                  page={page}
                  item={item}
                  onSelect={() => setPage(item.key)}
                />
              ))}
            </SidebarMenu>
          </SidebarFooter>
        </Sidebar>

        <SidebarInset className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <UpdateBanner
            locale={locale}
            updateInfo={updateInfo}
            onDismiss={() => void dismissUpdate(updateInfo?.latest_version ?? undefined)}
            onUpdate={() => setMajorDialogOpen(true)}
          />
          <div className="scrollbar-none min-h-0 flex-1 overflow-auto">
            <div className={page === "protect" ? undefined : "hidden"} aria-hidden={page !== "protect"}>
              <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-3 px-6 pt-6 sm:px-8 lg:px-10">
                <div className="inline-flex rounded-xl border bg-muted/40 p-1" role="tablist" aria-label={t(locale, "targetSystem")}>
                  {(["android", "ios"] as const).map((platform) => (
                    <button
                      key={platform}
                      type="button"
                      role="tab"
                      aria-selected={protectPlatform === platform}
                      className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${protectPlatform === platform ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}
                      onClick={() => setProtectPlatform(platform)}
                    >
                      {t(locale, platform === "android" ? "protectAndroid" : "protectIos")}
                    </button>
                  ))}
                </div>
                {protectPlatform === "android" && (
                  <div className="inline-flex rounded-xl border bg-muted/40 p-1" role="tablist" aria-label="Android package type">
                    {(["apk", "aab"] as const).map((kind) => (
                      <button
                        key={kind}
                        type="button"
                        role="tab"
                        aria-selected={androidPackageType === kind}
                        className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${androidPackageType === kind ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}
                        onClick={() => setAndroidPackageType(kind)}
                      >
                        {t(locale, kind === "apk" ? "androidApkTab" : "androidAabTab")}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className={protectPlatform === "android" && androidPackageType === "apk" ? undefined : "hidden"} aria-hidden={protectPlatform !== "android" || androidPackageType !== "apk"}>
                <ProtectPage
                active={page === "protect" && protectPlatform === "android" && androidPackageType === "apk"}
                  locale={locale}
                  certificates={certificatesState.certificates}
                  defaultCertificate={certificatesState.defaultCertificate}
                  certificatesLoaded={certificatesState.loaded}
                  buildInfo={buildInfo}
                  runtimeInfoLoaded={runtimeInfoLoaded}
                  configLoaded={configLoaded}
                  protectDefaults={protectDefaults}
                  onProtectDefaultsChange={(defaults) => {
                    setProtectDefaults(defaults);
                    void api.saveProtectDefaults(defaults).catch(() => notifyError(t(locale, "protectSettingsSaveFailed")));
                  }}
                  onOpenCertificates={() => setPage("certificates")}
                />
              </div>
              <div className={protectPlatform === "android" && androidPackageType === "aab" ? undefined : "hidden"} aria-hidden={protectPlatform !== "android" || androidPackageType !== "aab"}>
                <AabProtectPage
                  active={page === "protect" && protectPlatform === "android" && androidPackageType === "aab"}
                  locale={locale}
                  certificates={certificatesState.certificates}
                  defaultCertificate={certificatesState.defaultCertificate}
                  certificatesLoaded={certificatesState.loaded}
                  buildInfo={buildInfo}
                  runtimeInfoLoaded={runtimeInfoLoaded}
                  onOpenCertificates={() => setPage("certificates")}
                />
              </div>
              <IosProtectPage active={page === "protect" && protectPlatform === "ios"} locale={locale} />
            </div>
            <div className={page === "sign" ? undefined : "hidden"} aria-hidden={page !== "sign"}>
              <SignPage
                active={page === "sign"}
                locale={locale}
                certificates={certificatesState.certificates}
                certificatesLoaded={certificatesState.loaded}
                buildInfo={buildInfo}
                runtimeInfoLoaded={runtimeInfoLoaded}
                onOpenCertificates={() => setPage("certificates")}
              />
            </div>
            {page === "certificates" && (
              <CertificatesPage
                locale={locale}
                runtimeInfoLoaded={runtimeInfoLoaded}
                certificatesState={certificatesState}
              />
            )}
            {page === "settings" && (
              <SettingsPage
                locale={locale}
                setLocale={setLocale}
                themeMode={themeMode}
                setThemeMode={setThemeMode}
                telemetryEnabled={telemetryEnabled}
                setTelemetryEnabled={setTelemetryEnabled}
              />
            )}
            {page === "about" && (
              <AboutPage
                locale={locale}
                setUpdateInfo={setUpdateInfo}
                buildInfo={buildInfo}
                runtimeInfoRefreshing={runtimeInfoRefreshing}
                onRefreshRuntimeInfo={() => void refreshRuntimeInfo()}
              />
            )}
          </div>
        </SidebarInset>

        <UpdateDialog
          locale={locale}
          open={majorDialogOpen}
          updateInfo={updateInfo}
          taskRunning={Boolean(runningTasks.protect || runningTasks.ios_protect || runningTasks.sign)}
          onClose={() => setMajorDialogOpen(false)}
        />
        <ErrorReportDialog telemetryEnabled={telemetryEnabled} />
        <Toaster
          position="top-right"
          richColors
          closeButton
          toastOptions={{
            classNames: {
              toast: "font-sans",
              title: "text-sm font-medium",
              description: "text-xs",
            },
          }}
        />
      </div>
    </SidebarProvider>
  );
}

export type RuntimeInfoProps = {
  buildInfo: BuildInfo | null;
  runtimeInfoLoaded: boolean;
};

function NavItem({
  page,
  item,
  onSelect,
  running,
}: {
  page: Page;
  item: {
    key: Page;
    icon: React.ComponentType<{ className?: string }>;
    label: string;
  };
  onSelect: () => void;
  running?: boolean;
}) {
  const Icon = item.icon;

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        type="button"
        size="lg"
        isActive={page === item.key}
        tooltip={item.label}
        className="h-12 rounded-[14px] px-3.5 text-[14px] font-medium shadow-none transition-[background-color,color,transform] duration-200 data-[active=true]:bg-sidebar-accent data-[active=true]:text-sidebar-accent-foreground group-data-[collapsible=icon]:!mx-auto group-data-[collapsible=icon]:!size-12 group-data-[collapsible=icon]:!justify-center group-data-[collapsible=icon]:!gap-0 group-data-[collapsible=icon]:!p-0"
        onClick={onSelect}
      >
        <Icon className="h-[22px] w-[22px] shrink-0" />
        <span className="min-w-0 flex-1 truncate transition-[opacity,transform,width] duration-200 group-data-[collapsible=icon]:hidden">
          {item.label}
        </span>
        {running && <LoaderCircle className="h-4 w-4 shrink-0 animate-spin text-primary group-data-[collapsible=icon]:hidden" />}
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}
