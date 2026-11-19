package dev.mocika.shield.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Build;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import org.json.JSONObject;

/** 协议 2 的有界证据；只描述自身进程观察，不猜测工具名称或调试命令。 */
final class ByosRiskEvidence {
    static JSONObject capture(Context context, RuntimeSecurity.Detection detection, boolean resource) throws Exception {
        JSONObject evidence = new JSONObject().put("schema", "1").put("signal", detection.signal)
                .put("source", detection.source).put("observed", detection.observed)
                .put("confidence", detection.confidence).put("observation_type", "state_sample")
                .put("app_id", clean(context.getPackageName())).put("os_api", Integer.toString(Build.VERSION.SDK_INT))
                .put("os_version", clean(Build.VERSION.RELEASE)).put("device_model", clean(Build.MODEL))
                .put("payload", resource ? "resource_group" : "dex");
        if (!resource) evidence.put("dexb_version", "7");
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            evidence.put("app_version", clean(info.versionName))
                    .put("app_version_code", Long.toString(Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode))
                    .put("debuggable", Boolean.toString((info.applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0));
        } catch (Exception unavailable) { evidence.put("app_metadata", "unavailable"); }
        if (Build.VERSION.SDK_INT >= 28) evidence.put("process_name", clean(android.app.Application.getProcessName()));
        digest(evidence);
        return evidence;
    }

    private static String clean(String value) {
        if (value == null || !StandardCharsets.UTF_8.newEncoder().canEncode(value) || value.getBytes(StandardCharsets.UTF_8).length > 128
                || value.matches("(?s).*[\\x00-\\x1f\\x7f].*")) return "unavailable";
        return value;
    }

    static byte[] digest(JSONObject evidence) throws Exception {
        if (evidence == null || evidence.length() < 1 || evidence.length() > 32
                || !"1".equals(evidence.opt("schema"))) throw new SecurityException("K04");
        ArrayList<String> keys = new ArrayList<>();
        for (Iterator<String> it = evidence.keys(); it.hasNext();) keys.add(it.next());
        Collections.sort(keys);
        StringBuilder canonical = new StringBuilder("shellsmith-risk-evidence-v1");
        for (String key : keys) {
            Object raw = evidence.get(key);
            if (!key.matches("[a-z][a-z0-9_]{0,47}") || !(raw instanceof String)) throw new SecurityException("K04");
            String value = (String) raw;
            if (!StandardCharsets.UTF_8.newEncoder().canEncode(value) || value.getBytes(StandardCharsets.UTF_8).length > 256 || value.matches("(?s).*[\\x00-\\x1f\\x7f].*"))
                throw new SecurityException("K04");
            canonical.append('\n').append(key).append('=').append(value);
        }
        byte[] bytes = canonical.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 2048) throw new SecurityException("K04");
        return ByosRiskEvents.hash(bytes);
    }
}
