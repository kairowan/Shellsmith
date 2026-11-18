package dev.mocika.shield.loader;

import android.content.Context;
import android.os.Debug;
import android.os.Build;
import android.os.Looper;
import android.os.SystemClock;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.json.JSONObject;

/** 业务应用在工作线程首次打开资源时申请短期授权。 */
public final class MocikaProtectedResources {
    private static final String ROOT = "shellsmith-resources/";
    private static final ConcurrentHashMap<String, Group> GROUPS = new ConcurrentHashMap<>();
    private static final ScheduledExecutorService EXPIRY = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread worker = new Thread(task, "shellsmith-resource-expiry");
        worker.setDaemon(true);
        return worker;
    });

    private MocikaProtectedResources() {}

    public static InputStream open(Context context, String id) throws IOException {
        return open(context, id, false, unused -> {});
    }

    public static InputStream open(Context context, String id, boolean blockDebugger,
            Consumer<String> event) throws IOException {
        return open(context, id, blockDebugger, event, Collections.emptySet(), null);
    }

    public static InputStream openObserved(Context context, String id, Set<String> blockDebuggerGroups,
            Consumer<Map<String, String>> observer) throws IOException {
        return open(context, id, false, unused -> {}, blockDebuggerGroups, observer);
    }

    public static byte[] readRange(Context context, String id, long offset, int count) throws IOException {
        return readRangeObserved(context, id, offset, count, Collections.emptySet(), null);
    }

    public static byte[] readRangeObserved(Context context, String id, long offset, int count,
            Set<String> blockDebuggerGroups, Consumer<Map<String, String>> observer) throws IOException {
        try (ProtectedResourceStream stream = open(context, id, false, unused -> {}, blockDebuggerGroups, observer)) {
            return stream.readRange(offset, count);
        }
    }

    public static void observeEnvironment(Consumer<Map<String, String>> observer) {
        report(observer, "lifecycle", null, newId(), null, RuntimeSecurity.observeResources());
    }

    private static ProtectedResourceStream open(Context context, String id, boolean blockDebugger,
            Consumer<String> event, Set<String> blockDebuggerGroups,
            Consumer<Map<String, String>> observer) throws IOException {
        if (Looper.myLooper() == Looper.getMainLooper()) throw new IOException("须在工作线程读取业务资源");
        if (id == null || !id.matches("[a-z0-9_-]{1,64}")) throw new IOException("业务资源 ID 无效");
        if (Debug.isDebuggerConnected()) {
            event.accept("debugger_observed");
            if (blockDebugger) {
                event.accept("local_policy_denied");
                throw new IOException("业务资源读取被本地策略拒绝");
            }
        }
        String readId = observer == null ? null : newId();
        String authorizationId = null;
        String resourceGroup = null;
        String phase = "index";
        try {
            JSONObject index = readIndex(context);
            JSONObject resource = index.getJSONObject("resources").getJSONObject(id);
            String group = resource.getString("group");
            String build = index.getString("build_id");
            String token = index.getJSONObject("groups").getString(group);
            String module = resource.optString("module", "");
            if (!build.matches("[0-9a-f]{32}") || !group.matches("[a-z0-9_-]{1,64}")) throw new IOException("资源索引无效");
            resourceGroup = group;
            boolean block = blockDebugger || blockDebuggerGroups.contains(group);
            if (observer != null || (!blockDebugger && block)) {
                String signal = RuntimeSecurity.observeResources();
                report(observer, "environment", group, readId, null, signal);
                if (block && "debugger".equals(signal)) {
                    report(observer, "read", group, readId, null, "local_policy_denied");
                    throw new SecurityException("local_policy_denied");
                }
            }
            byte[] identity = new byte[16];
            for (int i = 0; i < identity.length; i++) {
                identity[i] = (byte) Integer.parseInt(build.substring(i * 2, i * 2 + 2), 16);
            }
            Group state = GROUPS.computeIfAbsent(token, unused -> new Group());
            ProtectedResourceStream result;
            String authorizationResult;
            synchronized (state) {
                if (state.lease == null || !state.lease.active()) {
                    if (state.lease != null) Arrays.fill(state.lease.key, (byte) 0);
                    long started = SystemClock.elapsedRealtime();
                    phase = "authorization";
                    authorizationId = readId;
                    byte[] key = ByosKeyClient.fetchOnWorker(context, index.getString("server_url"), token,
                            Ld.getSignatureSha256(context), build, group, authorizationId);
                    state.lease = new Lease(key, started + 60_000, authorizationId);
                    authorizationResult = "granted";
                    Lease scheduled = state.lease;
                    EXPIRY.schedule(() -> {
                        synchronized (state) {
                            Arrays.fill(scheduled.key, (byte) 0);
                            if (state.lease == scheduled) state.lease = null;
                        }
                    }, Math.max(0, scheduled.until - SystemClock.elapsedRealtime()), TimeUnit.MILLISECONDS);
                } else authorizationResult = "cached";
                Lease lease = state.lease;
                authorizationId = lease.traceId;
                phase = "read";
                result = ProtectedResourceStream.open(openCiphertext(context, module, ROOT + id + ".ssr"),
                        identity, group, id, resource.getLong("version"), lease.key,
                        () -> lease.active() && (!block || !Debug.isDebuggerConnected()));
            }
            report(observer, "authorization", group, readId, authorizationId, authorizationResult);
            if (observer != null) {
                String trace = authorizationId;
                result.observeResult(stateName -> report(observer, "read", group, readId, trace, stateName));
            }
            try {
                event.accept("resource_opened");
            } catch (RuntimeException observerError) {
                result.close();
                throw observerError;
            }
            return result;
        } catch (Exception error) {
            if ("local_policy_denied".equals(error.getMessage())) {
                throw new IOException("业务资源读取被本地策略拒绝");
            }
            if (error instanceof InterruptedException) Thread.currentThread().interrupt();
            SecurityException failure = ByosKeyClient.failure(error);
            String code = failure.getMessage();
            String outcome = "K03_403".equals(code) ? "denied"
                    : "K03_429".equals(code) ? "rate_limited"
                    : code.matches("K03_5[0-9]{2}") ? "server_unavailable"
                    : code.matches("K1[02345]") && "authorization".equals(phase) ? "transport_error"
                    : "unavailable";
            report(observer, phase, resourceGroup, readId, authorizationId, outcome);
            if ("K03_403".equals(failure.getMessage())) event.accept("authorization_denied");
            else event.accept("resource_unavailable");
            throw new IOException("业务资源暂不可用", failure);
        }
    }

    private static InputStream openCiphertext(Context context, String module, String path) throws IOException {
        if (module.isEmpty()) return context.getAssets().open(path);
        if (!module.matches("[A-Za-z][A-Za-z0-9_]{0,49}")) throw new IOException("无效的资源模块");
        // 安装时交付的资源可能已经进入 AssetManager。其他模块在安装完成后才可读取。
        try { return context.getAssets().open(path); } catch (FileNotFoundException ignored) {}
        if (Build.VERSION.SDK_INT >= 26) {
            try {
                return context.createContextForSplit(module).getAssets().open(path);
            } catch (android.content.pm.PackageManager.NameNotFoundException | FileNotFoundException ignored) {}
        }
        return MocikaPlayDelivery.openProtectedResource(context, module, path);
    }

    private static String newId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private static void report(Consumer<Map<String, String>> observer, String phase, String group,
            String readId, String authorizationId, String result) {
        if (observer == null) return;
        Map<String, String> event = new LinkedHashMap<>();
        event.put("version", "1");
        event.put("source", "android");
        event.put("phase", phase);
        event.put("read_id", readId);
        event.put("result", result);
        if (group != null) event.put("group", group);
        if (authorizationId != null) event.put("authorization_id", authorizationId);
        try { observer.accept(Collections.unmodifiableMap(event)); } catch (RuntimeException ignored) {
            // 诊断回调不改变资源授权和读取结果。
        }
    }

    private static JSONObject readIndex(Context context) throws Exception {
        try (InputStream file = context.getAssets().open(ROOT + "index.json")) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int count;
            while ((count = file.read(buffer)) != -1) {
                if (output.size() + count > 256 * 1024) throw new IOException("资源索引过大");
                output.write(buffer, 0, count);
            }
            JSONObject index = new JSONObject(new String(output.toByteArray(), StandardCharsets.UTF_8));
            if (index.getInt("version") != 1) throw new IOException("资源索引版本无效");
            return index;
        }
    }

    private static final class Group {
        Lease lease;
    }

    private static final class Lease {
        final byte[] key;
        final long until;
        final String traceId;

        Lease(byte[] key, long until, String traceId) {
            this.key = key;
            this.until = until;
            this.traceId = traceId;
        }

        boolean active() {
            return SystemClock.elapsedRealtime() < until;
        }
    }
}
