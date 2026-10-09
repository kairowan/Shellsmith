import { AboutInfoCard } from "@/components/app/about-info-card";
import { useAboutPage } from "@/hooks/use-about-page";
import type { Locale } from "@/lib/i18n";
import { type UpdateCheckResult } from "@/lib/tauri";

export function AboutPage({
  locale,
  setUpdateInfo,
  runtimeInfoRefreshing,
  onRefreshRuntimeInfo,
}: {
  locale: Locale;
  setUpdateInfo: (result: UpdateCheckResult | null) => void;
  runtimeInfoRefreshing: boolean;
  onRefreshRuntimeInfo: () => void;
}) {
  const { appInfo, checking, message, checkUpdate } = useAboutPage({
    locale,
    setUpdateInfo,
  });

  return (
    <section className="mx-auto flex min-h-full w-full items-center justify-center px-8 py-12">
      <AboutInfoCard
        locale={locale}
        appInfo={appInfo}
        checking={checking}
        message={message}
        onCheckUpdate={checkUpdate}
        runtimeInfoRefreshing={runtimeInfoRefreshing}
        onRefreshRuntimeInfo={onRefreshRuntimeInfo}
      />
    </section>
  );
}
