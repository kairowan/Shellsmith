package com.yqsh.protector.packer;

import java.io.File;

/**
 * Public library entry for APK protection (desktop UI, scripts, CLI).
 */
public final class Protector {

    public ProtectResult protect(ProtectOptions options) throws Exception {
        return protect(options, ProtectProgressListener.NONE);
    }

    public ProtectResult protect(ProtectOptions options, ProtectProgressListener listener)
            throws Exception {
        if (options == null) {
            throw new IllegalArgumentException("options is required");
        }
        if (options.inputApk == null || !options.inputApk.isFile()) {
            throw new IllegalArgumentException("input APK not found: " + options.inputApk);
        }
        if (options.outputApk == null) {
            throw new IllegalArgumentException("outputApk is required");
        }
        if (options.shellDir == null) {
            throw new IllegalArgumentException("shellDir is required");
        }
        if (options.raspAction < 0 || options.raspAction > 2) {
            throw new IllegalArgumentException("raspAction must be 0, 1, or 2");
        }

        ProtectProgressListener sink = listener != null ? listener : ProtectProgressListener.NONE;
        JsonProgressEmitter json = null;
        if (options.jsonProgress) {
            json = new JsonProgressEmitter(System.out, sink);
            sink = json;
        }

        PackerMain packer = new PackerMain();
        packer.applyOptions(options);
        packer.setProgressListener(sink);

        try {
            sink.onPhase("start", "Protecting " + options.inputApk.getName(), 0);
            ProtectResult result = packer.protect(
                    options.inputApk, options.outputApk, options.shellDir, options.signConfig);
            sink.onPhase("done", "Protected APK ready", 100);
            if (json != null) {
                json.emitDone(
                        result.outputApk.getAbsolutePath(),
                        result.sizeReportFile != null
                                ? result.sizeReportFile.getAbsolutePath() : "");
            }
            return result;
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            if (json != null) {
                json.emitError(msg);
            }
            sink.onLog("error", msg);
            throw e;
        }
    }
}
