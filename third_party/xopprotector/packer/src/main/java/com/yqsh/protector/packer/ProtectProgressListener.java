package com.yqsh.protector.packer;

/**
 * Progress / log sink for library callers and the desktop UI bridge.
 * Implementations must be thread-safe if used from worker threads.
 */
public interface ProtectProgressListener {
    void onPhase(String id, String message, int percent);

    void onLog(String level, String message);

    default void onWarn(String message) {
        onLog("warn", message);
    }

    /** No-op listener. */
    ProtectProgressListener NONE = new ProtectProgressListener() {
        @Override
        public void onPhase(String id, String message, int percent) {
        }

        @Override
        public void onLog(String level, String message) {
        }
    };
}
