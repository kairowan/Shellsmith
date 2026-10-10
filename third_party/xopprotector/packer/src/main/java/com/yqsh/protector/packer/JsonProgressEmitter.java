package com.yqsh.protector.packer;

import java.io.PrintStream;

/**
 * Writes one NDJSON object per line to stdout for machine consumers (WPF UI).
 * Human-readable lines continue to go through {@link ProtectProgressListener} / stderr as needed.
 */
final class JsonProgressEmitter implements ProtectProgressListener {
    private final PrintStream out;
    private final ProtectProgressListener delegate;

    JsonProgressEmitter(PrintStream out, ProtectProgressListener delegate) {
        this.out = out;
        this.delegate = delegate != null ? delegate : ProtectProgressListener.NONE;
    }

    @Override
    public void onPhase(String id, String message, int percent) {
        delegate.onPhase(id, message, percent);
        out.println(obj("phase",
                "\"id\":" + q(id)
                        + ",\"message\":" + q(message)
                        + ",\"percent\":" + percent));
        out.flush();
    }

    @Override
    public void onLog(String level, String message) {
        delegate.onLog(level, message);
        out.println(obj("log",
                "\"level\":" + q(level == null ? "info" : level)
                        + ",\"message\":" + q(message)));
        out.flush();
    }

    void emitDone(String outputPath, String sizeReportPath) {
        out.println(obj("done",
                "\"output\":" + q(outputPath)
                        + ",\"sizeReport\":" + q(sizeReportPath == null ? "" : sizeReportPath)));
        out.flush();
    }

    void emitError(String message) {
        out.println(obj("error", "\"message\":" + q(message)));
        out.flush();
    }

    private static String obj(String type, String fields) {
        return "{\"type\":" + q(type) + "," + fields + "}";
    }

    private static String q(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
