package com.yqsh.protector.packer;

import java.util.Locale;
import java.util.Set;

/**
 * Runtime-sensitive methods/classes that must stay on ART. Media implementations
 * depend on seek/state semantics, while UI adapters and resource helpers depend
 * on nullable receivers, callbacks and platform resource lookup behavior.
 */
final class PlaybackCompatibility {
    private static final Set<String> ALWAYS_ART = Set.of(
            "seekTo",
            "setSeekTo",
            "getSeekTo",
            "setSeekPosition",
            "getSeekPosition",
            "setPendingSeekPosition",
            "getPendingSeekPosition",
            "setDataSource",
            "setDataSourceFile",
            "getCurrentPosition",
            "getDuration");
    private static final Set<String> MEDIA_METHODS = Set.of(
            "start", "resume", "pause", "stop", "reset", "release", "replay",
            "prepare", "prepareAsync", "onSeekTo", "commitSeek", "handlePlayerSeek",
            "handlePlayerSeekBar", "normalizeSeekPosition", "calculateSeekTo",
            "setMDataSource", "getMDataSource", "onReadFile", "onProcessAudio");

    private PlaybackCompatibility() {}

    static boolean keepOnArt(String owner, String method) {
        if (method == null) return false;
        if (ALWAYS_ART.contains(method)) return true;
        // Kotlin/R8 synthetic accessors retain the operation in their name,
        // for example access$commitSeek and prepareSeekPosition.
        String methodLower = method.toLowerCase(Locale.US);
        if (methodLower.contains("seek") || methodLower.contains("datasource")) return true;
        if (owner == null) return false;
        String lower = owner.toLowerCase(Locale.US);
        // Keep the whole media pipeline on ART. Splitting stateful decoders
        // between PVM2 and ART is more fragile than skipping a few methods.
        if (lower.contains("/audio/")
                || lower.contains("/player/")
                || lower.contains("/decoder/")
                || lower.contains("/media/")
                || lower.contains("/playback/")
                || lower.contains("/helper/")
                || lower.contains("/helpers/")
                || lower.contains("/hepler/")
                || lower.contains("player")
                || lower.contains("datasource")
                || lower.contains("track")
                || lower.contains("/wave")
                || lower.contains("seek")) {
            return true;
        }
        return MEDIA_METHODS.contains(method) && lower.contains("/sound/");
    }
}
