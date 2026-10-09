import { memo, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Download, LoaderCircle } from "lucide-react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { AppButton } from "@/components/app/common";
import { t, type Locale } from "@/lib/i18n";
import { api, type UpdateCheckResult, type UpdateProgress } from "@/lib/tauri";

// 下载进度更新时无需重复解析同一份更新说明。
export const UpdateReleaseNotes = memo(function UpdateReleaseNotes({ notes, onError }: {
  notes: string;
  onError: (message: string) => void;
}) {
  return <div className="release-notes my-4 max-h-56 overflow-auto rounded-lg border p-3 text-sm leading-6">
    <Markdown
      remarkPlugins={[remarkGfm]}
      skipHtml
      components={{
        // ponytail: 沿用桌面端官方仓库链接白名单；外部图片只显示替代文本，不自动加载。
        a: ({ href, children }) => href && /^https:\/\/github\.com\/kairowan\/Shellsmith(?:\/|$)/.test(href)
          ? <a href={href} onClick={(event) => {
            event.preventDefault();
            void api.openUrl(href).catch((failure) => onError(String(failure)));
          }}>{children}</a>
          : <span>{children}</span>,
        img: ({ alt }) => <span>{alt}</span>,
      }}
    >{notes}</Markdown>
  </div>;
});

export function UpdateDialog({ locale, open, updateInfo, taskRunning, onClose }: {
  locale: Locale;
  open: boolean;
  updateInfo: UpdateCheckResult | null;
  taskRunning: boolean;
  onClose: () => void;
}) {
  const [progress, setProgress] = useState<UpdateProgress | null>(null);
  const [error, setError] = useState("");
  const installing = useRef(false);
  const busy = progress !== null;
  if (!updateInfo?.latest_version) return null;
  const version = updateInfo.latest_version;

  function close() {
    if (installing.current) return;
    setError("");
    onClose();
  }

  async function install() {
    if (installing.current || taskRunning) return;
    installing.current = true;
    setError("");
    setProgress({ phase: "checking", downloaded: 0, total: null });
    try {
      await api.installUpdate(version, setProgress);
    } catch (failure) {
      setError(String(failure));
    } finally {
      installing.current = false;
      setProgress(null);
    }
  }

  const phaseLabel = progress && t(locale, {
    checking: "updateChecking",
    downloading: "updateDownloading",
    verifying: "updateVerifying",
    installing: "updateInstalling",
  }[progress.phase] as "updateChecking" | "updateDownloading" | "updateVerifying" | "updateInstalling");

  return <Dialog.Root open={open} onOpenChange={(value) => { if (!value) close(); }}>
    <Dialog.Portal>
      <Dialog.Overlay className="fixed inset-0 z-50 bg-black/55" />
      <Dialog.Content
        className="app-panel fixed left-1/2 top-1/2 z-50 max-h-[85vh] w-[min(600px,calc(100vw-32px))] -translate-x-1/2 -translate-y-1/2 overflow-auto p-6"
        onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }}
        onInteractOutside={(event) => { if (busy) event.preventDefault(); }}
      >
        <Dialog.Title className="flex items-center gap-2 text-lg font-semibold"><Download className="h-5 w-5" />{t(locale, "updateAvailable")} v{version}</Dialog.Title>
        <Dialog.Description className="mt-3 text-sm leading-6 text-muted-foreground">{t(locale, "updateInstallHint")}</Dialog.Description>
        {updateInfo.notes && <UpdateReleaseNotes notes={updateInfo.notes} onError={setError} />}
        {!updateInfo.can_install && <p className="my-3 text-sm text-muted-foreground">{t(locale, "updateManualHint")}</p>}
        {taskRunning && <p role="status" className="my-3 text-sm text-amber-600">{t(locale, "updateTaskBusy")}</p>}
        {progress && <div className="my-4 space-y-2">
          <p role="status" className="flex items-center gap-2 text-sm"><LoaderCircle className="h-4 w-4 animate-spin" />{phaseLabel}</p>
          {progress.phase === "downloading" && <>
            <progress aria-label={t(locale, "updateDownloading")} className="update-progress" max={progress.total || 1} value={progress.total ? Math.min(progress.downloaded, progress.total) : undefined} />
            <p className="text-xs text-muted-foreground">{(progress.downloaded / 1048576).toFixed(1)} MB{progress.total ? ` / ${(progress.total / 1048576).toFixed(1)} MB` : ""}</p>
          </>}
        </div>}
        {error && <p role="alert" className="my-3 break-words text-sm text-destructive">{error}</p>}
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <AppButton variant="secondary" disabled={busy} onClick={close}>{t(locale, "ignore")}</AppButton>
          {updateInfo.release_url && <AppButton variant="secondary" disabled={busy} onClick={() => void api.openUrl(updateInfo.release_url!)}>{t(locale, "viewRelease")}</AppButton>}
          {updateInfo.can_install && <AppButton disabled={busy || taskRunning} onClick={() => void install()}>{t(locale, "installUpdate")}</AppButton>}
        </div>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}
