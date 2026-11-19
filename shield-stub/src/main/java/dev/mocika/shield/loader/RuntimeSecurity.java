package dev.mocika.shield.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;

/** 负责在每次进程启动时执行环境安全检查，不参与 DEX 缓存与类加载。 */
final class RuntimeSecurity {
    static final class Detection {
        final String code, signal, source, observed, confidence;
        final long at = System.currentTimeMillis() / 1000;
        Detection(String c, String s, String from, String value, String level) {
            code = c; signal = s; source = from; observed = value; confidence = level;
        }
    }
    interface RiskObserver { void detected(Detection detection); }
    private static volatile RiskObserver riskObserver;
    private static volatile boolean remoteRevoked;

    static void subscribeRisk(RiskObserver observer) { riskObserver = observer; }

    static void detected(String code) {
        detected(new Detection(code, "runtime.aggregate", "runtime_detector", "detected", "unknown"));
    }

    private static void detected(Detection detection) {
        RiskObserver observer = riskObserver;
        if (observer != null) try { observer.detected(detection); } catch (RuntimeException ignored) { }
    }

    static void observedSignals(int signals) {
        if (riskObserver == null) return;
        if ((signals & SIGNAL_ANTI_DEBUG) != 0 && (signals & (7 << 8)) == 0) detected("debugger");
        if ((signals & SIGNAL_ROOT) != 0 && (signals & (15 << 15)) == 0) detected("root");
        if ((signals & SIGNAL_SUSPECT) != 0 && (signals & (15 << 11)) == 0) detected("runtimeSuspect");
        evidence(signals, 8, "debugger", "android.native_tracer", "/proc/self/status", "TracerPid_nonzero", "high");
        evidence(signals, 9, "debugger", "android.frida_mapping", "/proc/self/maps", "known_frida_signature", "high");
        evidence(signals, 10, "debugger", "android.frida_thread", "/proc/self/task", "specific_thread_signature", "medium");
        evidence(signals, 11, "runtimeSuspect", "android.frida_port", "/proc/net/tcp_or_tcp6", "known_local_port", "low");
        evidence(signals, 12, "runtimeSuspect", "android.frida_file", "filesystem_metadata", "known_path_exists", "low");
        evidence(signals, 13, "runtimeSuspect", "android.hook_mapping", "/proc/self/maps", "known_hook_signature", "medium");
        evidence(signals, 14, "runtimeSuspect", "android.glib_thread", "/proc/self/task", "generic_glib_thread", "low");
        evidence(signals, 15, "root", "android.su_executable", "filesystem_metadata", "known_su_path_executable", "medium");
        evidence(signals, 16, "root", "android.privileged_uid", "/proc/self/status", "effective_uid_zero", "high");
        evidence(signals, 17, "root", "android.adb_root", "service.adb.root", "1", "high");
        evidence(signals, 18, "root", "android.root_framework_trace", "process_maps_or_mounts", "known_root_signature", "medium");
        if ((signals & 8) != 0) detected(new Detection("runtimeManipulation", "android.vm_gate_blocked", "native_runtime_gate", "blocked", "high"));
    }

    private static void evidence(int signals, int bit, String code, String id, String source, String value, String confidence) {
        if ((signals & (1 << bit)) != 0) detected(new Detection(code, id, source, value, confidence));
    }

    static boolean remoteAccessRevoked() { return remoteRevoked; }

    static void revokeRemoteAccess() {
        remoteRevoked = true;
        // 当前进程不自动解锁；管理员恢复后重新启动并成功取钥，避免旧收据与在途取钥相互覆盖。
        try { block(); } catch (LinkageError unavailable) { Log.w(TAG, "R_GATE_UNAVAILABLE"); }
    }

    private static final String TAG = "RuntimeSecurity";

    private static final int SIGNAL_ANTI_DEBUG = 1;
    private static final int SIGNAL_ROOT = 1 << 1;
    /**
     * 低置信可疑信号（Frida 端口监听、临时目录残留、Hook 映射名）。
     * 部分定制 ROM 与加固测试机会产生假阳性，因此只记录不阻断。
     */
    private static final int SIGNAL_SUSPECT = 1 << 2;
    private static final String POLICY_KEY = "dev.mocika.shield.ENV_POLICY";

    private RuntimeSecurity() {
    }

    static void checkEnvironment(Context context) {
        try {
            NativeIntegrity.verify(context);
            ByosRiskEvents.initialize(context);
            MocikaUi.initialize(context);
            boolean strict = isStrictPolicy(context);
            Ld.y(strict ? 2 : 1);
            int signals = Ld.r();
            observedSignals(signals);
            reportSuspect(signals);
            enforceSafe(shouldReject(signals, strict));
        } catch (Exception error) {
            block();
            if (error instanceof SecurityException) throw (SecurityException) error;
            throw new SecurityException("S03", error);
        }
    }

    static void block() { Ld.y(0); }

    static String observeResources() {
        if (remoteRevoked) return "authorization_revoked";
        if (android.os.Debug.isDebuggerConnected()) {
            detected(new Detection("debugger", "android.java_debugger_connected", "android.os.Debug.isDebuggerConnected", "true", "high"));
            return "debugger";
        }
        try {
            int signals = Ld.r();
            observedSignals(signals);
            return signals == 0 ? "clear" : "runtime_signal";
        } catch (RuntimeException | LinkageError unavailable) {
            return "unavailable";
        }
    }

    /** 可疑信号写入日志供诊断，不改变启动结果。 */
    private static void reportSuspect(int signals) {
        if ((signals & SIGNAL_SUSPECT) != 0) {
            Log.w(TAG, "S02");
        }
    }

    static boolean shouldReject(int signals, boolean strict) {
        // 远程撤销已限制保护入口，不再把该执行门状态转成前台强杀；独立环境策略仍生效。
        return (signals & SIGNAL_ANTI_DEBUG) != 0 || ((signals & 8) != 0 && !remoteRevoked)
                || (strict && (signals & SIGNAL_ROOT) != 0);
    }

    static boolean isStrictPolicy(Context context) {
        try {
            ApplicationInfo info = context.getPackageManager().getApplicationInfo(
                    context.getPackageName(), PackageManager.GET_META_DATA);
            return info.metaData != null && "strict".equals(info.metaData.getString(POLICY_KEY));
        } catch (Exception ignored) {
            return false;
        }
    }

    static void enforceSafe(boolean unsafe) {
        if (unsafe) {
            throw new SecurityException("S01");
        }
    }
}
