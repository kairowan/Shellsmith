package dev.mocika.shield.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;

/** 负责在每次进程启动时执行环境安全检查，不参与 DEX 缓存与类加载。 */
final class RuntimeSecurity {

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
            MocikaUi.initialize(context);
            boolean strict = isStrictPolicy(context);
            Ld.y(strict ? 2 : 1);
            int signals = Ld.r();
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
        if (android.os.Debug.isDebuggerConnected()) return "debugger";
        try {
            return Ld.r() == 0 ? "clear" : "runtime_signal";
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
        return (signals & (SIGNAL_ANTI_DEBUG | 8)) != 0
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
