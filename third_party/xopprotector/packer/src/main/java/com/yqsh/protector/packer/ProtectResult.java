package com.yqsh.protector.packer;

import java.io.File;

/** Outcome of a successful {@link Protector#protect} run. */
public final class ProtectResult {
    public final File outputApk;
    public final File sizeReportFile;
    public final boolean signed;

    public ProtectResult(File outputApk, File sizeReportFile, boolean signed) {
        this.outputApk = outputApk;
        this.sizeReportFile = sizeReportFile;
        this.signed = signed;
    }
}
