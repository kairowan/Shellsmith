package dev.mocika.shield.loader;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.app.Dialog;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.ContentObserver;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** 加固器注入的界面保护桥；只暴露 DEX 改写需要的系统调用代理。 */
public final class MocikaUi implements Application.ActivityLifecycleCallbacks {
    private static final String PREFIX = "dev.mocika.shield.UI_";
    private static final int SECURE = WindowManager.LayoutParams.FLAG_SECURE;
    private static final int UNKNOWN = -1;
    private static final long CHECK_INTERVAL = 5000;
    private static MocikaUi instance;
    private final Context context;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Set<Activity> started = new HashSet<>();
    private final Set<String> exemptions;
    private final boolean secure;
    private final boolean recheck;
    private final boolean strict;
    private final String adbPolicy;
    private long lastCheck = -CHECK_INTERVAL;
    private int lastAdbState = Integer.MIN_VALUE;
    private boolean observing;
    private final ContentObserver observer = new ContentObserver(handler) {
        @Override public void onChange(boolean selfChange) { checkForeground(true); }
    };
    private final Runnable periodic = new Runnable() {
        @Override public void run() {
            if (started.isEmpty()) return;
            checkForeground(false);
            handler.postDelayed(this, CHECK_INTERVAL);
        }
    };

    private MocikaUi(Context context, Bundle metadata) {
        this.context = context;
        secure = metadata.getBoolean(PREFIX + "SECURE_SCREEN", false);
        recheck = metadata.getBoolean(PREFIX + "RECHECK", false);
        adbPolicy = metadata.getString(PREFIX + "ADB_POLICY", "off");
        if (!"off".equals(adbPolicy) && !"report".equals(adbPolicy) && !"block".equals(adbPolicy)) {
            throw new SecurityException("U00");
        }
        exemptions = new HashSet<>(Arrays.asList(metadata.getString(PREFIX + "SCREEN_EXEMPT", "").split(",")));
        strict = RuntimeSecurity.isStrictPolicy(context);
    }

    static void initialize(Context context) {
        try {
            ApplicationInfo info = context.getPackageManager().getApplicationInfo(
                    context.getPackageName(), PackageManager.GET_META_DATA);
            Bundle metadata = info.metaData;
            if (metadata == null || !metadata.containsKey(PREFIX + "VERSION")) return;
            if (metadata.getInt(PREFIX + "VERSION", 0) != 1) throw new SecurityException("U00");
            instance = new MocikaUi(context, metadata);
            if (instance.checkAdb()) throw new SecurityException("U01");
        } catch (PackageManager.NameNotFoundException e) {
            throw new SecurityException("U00", e);
        }
    }

    static void install(Application application) {
        if (instance != null) application.registerActivityLifecycleCallbacks(instance);
    }

    private boolean checkAdb() {
        if ("off".equals(adbPolicy)) return false;
        int usb = readSetting(Settings.Global.ADB_ENABLED);
        // ponytail: 无线调试在 API 30 起按 AOSP 设置适配；OEM 不暴露时为未知，不推断已关闭。
        int wifi = Build.VERSION.SDK_INT >= 30 ? readSetting("adb_wifi_enabled") : 0;
        int state = combineAdb(usb, wifi);
        if (lastAdbState != state) {
            Log.i("RuntimeSecurity", state == 1 ? "U_ADB_ON" : state == 0 ? "U_ADB_OFF" : "U_ADB_UNKNOWN");
            lastAdbState = state;
        }
        return rejectAdb(adbPolicy, state);
    }

    private int readSetting(String key) {
        try {
            int value = Settings.Global.getInt(context.getContentResolver(), key);
            return value == 0 || value == 1 ? value : UNKNOWN;
        } catch (Settings.SettingNotFoundException | SecurityException e) {
            return UNKNOWN;
        }
    }

    static int combineAdb(int usb, int wifi) {
        return usb == 1 || wifi == 1 ? 1 : usb == 0 && wifi == 0 ? 0 : UNKNOWN;
    }

    static boolean rejectAdb(String policy, int state) {
        return "block".equals(policy) && state != 0;
    }

    private void checkForeground(boolean force) {
        if (started.isEmpty()) return;
        long now = SystemClock.elapsedRealtime();
        if (!force && now - lastCheck < CHECK_INTERVAL) return;
        lastCheck = now;
        boolean reject = checkAdb();
        if (recheck) {
            int signals = Ld.r();
            RuntimeSecurity.observedSignals(signals);
            reject |= RuntimeSecurity.shouldReject(signals, strict);
        }
        if (reject) {
            RuntimeSecurity.block();
            Log.w("RuntimeSecurity", "U02");
            for (Activity activity : new HashSet<>(started)) activity.finishAffinity();
            // 受控结束当前业务进程，不用遮罩冒充视图树/后台业务已经关闭。
            android.os.Process.killProcess(android.os.Process.myPid());
        }
    }

    private static boolean protects(Window window) {
        MocikaUi current = instance;
        if (current == null || !current.secure || window == null) return false;
        Context owner = window.getContext();
        for (int i = 0; i < 16 && owner != null; i++) {
            if (owner instanceof Activity) return !current.exemptions.contains(owner.getClass().getName());
            if (!(owner instanceof ContextWrapper)) break;
            Context next = ((ContextWrapper) owner).getBaseContext();
            if (next == owner) break;
            owner = next;
        }
        return true;
    }

    private static void protect(Window window) {
        if (protects(window)) window.addFlags(SECURE);
    }

    public static void show(Dialog dialog) {
        protect(dialog.getWindow());
        dialog.show();
        protect(dialog.getWindow());
    }

    public static AlertDialog show(AlertDialog.Builder builder) {
        // 保留 Builder 子类的 show() 虚分派；返回后、下一帧绘制前设置窗口标记。
        AlertDialog dialog = builder.show();
        if (dialog != null) protect(dialog.getWindow());
        return dialog;
    }

    public static void setFlags(Window window, int flags, int mask) {
        if (protects(window)) { flags |= SECURE; mask |= SECURE; }
        window.setFlags(flags, mask);
    }

    public static void clearFlags(Window window, int flags) {
        if (protects(window)) flags &= ~SECURE;
        window.clearFlags(flags);
    }

    public static void setAttributes(Window window, WindowManager.LayoutParams attributes) {
        if (protects(window)) attributes.flags |= SECURE;
        window.setAttributes(attributes);
    }

    @Override public void onActivityPreCreated(Activity activity, Bundle state) { protect(activity.getWindow()); }
    @Override public void onActivityCreated(Activity activity, Bundle state) { protect(activity.getWindow()); }
    @Override public void onActivityStarted(Activity activity) {
        boolean first = started.isEmpty();
        started.add(activity);
        protect(activity.getWindow());
        if (first && (!"off".equals(adbPolicy) || recheck)) {
            if (!"off".equals(adbPolicy)) {
                try {
                    context.getContentResolver().registerContentObserver(Settings.Global.getUriFor(Settings.Global.ADB_ENABLED), false, observer);
                    if (Build.VERSION.SDK_INT >= 30) context.getContentResolver().registerContentObserver(Settings.Global.getUriFor("adb_wifi_enabled"), false, observer);
                    observing = true;
                } catch (SecurityException e) {
                    // 周期复查保留，即使系统不允许观察设置也不声称已监听。
                    stopObserving();
                    Log.w("RuntimeSecurity", "U_OBSERVER_UNAVAILABLE");
                }
            }
            checkForeground(true);
            handler.postDelayed(periodic, CHECK_INTERVAL);
        }
    }
    @Override public void onActivityResumed(Activity activity) { protect(activity.getWindow()); checkForeground(false); }
    @Override public void onActivityPaused(Activity activity) { }
    @Override public void onActivityStopped(Activity activity) {
        started.remove(activity);
        if (started.isEmpty()) {
            handler.removeCallbacks(periodic);
            if (observing) stopObserving();
        }
    }
    @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) { }
    @Override public void onActivityDestroyed(Activity activity) { onActivityStopped(activity); }

    private void stopObserving() {
        try { context.getContentResolver().unregisterContentObserver(observer); }
        catch (SecurityException ignored) { Log.w("RuntimeSecurity", "U_OBSERVER_UNAVAILABLE"); }
        finally { observing = false; }
    }
}
