import { Download, Loader2, RotateCcw } from "lucide-react";
import { appIconUrl, appName } from "@/components/app/branding";
import { AppButton, SummaryRow } from "@/components/app/common";
import { t, type Locale } from "@/lib/i18n";

type AppInfo = {
  version: string;
  build_date: string;
};

export function AboutInfoCard({
  locale,
  appInfo,
  checking,
  message,
  onCheckUpdate,
  runtimeInfoRefreshing,
  onRefreshRuntimeInfo,
}: {
  locale: Locale;
  appInfo: AppInfo;
  checking: boolean;
  message: string;
  onCheckUpdate: () => void;
  runtimeInfoRefreshing: boolean;
  onRefreshRuntimeInfo: () => void;
}) {
  return (
    <div className="mx-auto flex w-full max-w-[620px] flex-col items-center text-center">
      <img src={appIconUrl} alt={appName} className="h-[72px] w-[72px] rounded-[20px]" />
      <h1 className="mt-5 text-[30px] font-semibold tracking-tight">{appName}</h1>
      <div className="mt-2 rounded-full border border-border/70 bg-muted/45 px-3 py-1 text-xs font-semibold text-muted-foreground">
        v{appInfo.version}
      </div>

      <div className="mt-8 w-full max-w-[460px] border-y border-border/60 py-2 text-left">
        <SummaryRow
          label={t(locale, "build")}
          value={appInfo.build_date || t(locale, "unknown")}
          muted={!appInfo.build_date}
        />
      </div>

      <div className="mt-6 flex flex-col items-center gap-3">
        <div className="flex flex-wrap justify-center gap-3">
          <AppButton variant="secondary" onClick={onRefreshRuntimeInfo} disabled={runtimeInfoRefreshing}>
            {runtimeInfoRefreshing ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCcw className="h-4 w-4" />}
            {runtimeInfoRefreshing ? t(locale, "checkingEnvironment") : t(locale, "refreshEnvironment")}
          </AppButton>
          <AppButton variant="secondary" onClick={onCheckUpdate} disabled={checking}>
            {checking ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            {checking ? t(locale, "checkingUpdate") : t(locale, "checkUpdate")}
          </AppButton>
        </div>
        {message && <p className="text-sm text-muted-foreground">{message}</p>}
      </div>
    </div>
  );
}
