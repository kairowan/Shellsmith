package dev.mocika.shield.loader;

import android.content.Context;
import android.os.Debug;
import android.os.Looper;
import android.os.SystemClock;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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
        if (Looper.myLooper() == Looper.getMainLooper()) throw new IOException("须在工作线程读取业务资源");
        if (id == null || !id.matches("[a-z0-9_-]{1,64}")) throw new IOException("业务资源 ID 无效");
        if (Debug.isDebuggerConnected()) {
            event.accept("debugger_observed");
            if (blockDebugger) {
                event.accept("local_policy_denied");
                throw new IOException("业务资源读取被本地策略拒绝");
            }
        }
        try {
            JSONObject index = readIndex(context);
            JSONObject resource = index.getJSONObject("resources").getJSONObject(id);
            String group = resource.getString("group");
            String build = index.getString("build_id");
            String token = index.getJSONObject("groups").getString(group);
            if (!build.matches("[0-9a-f]{32}") || !group.matches("[a-z0-9_-]{1,64}")) throw new IOException("资源索引无效");
            byte[] identity = new byte[16];
            for (int i = 0; i < identity.length; i++) {
                identity[i] = (byte) Integer.parseInt(build.substring(i * 2, i * 2 + 2), 16);
            }
            Group state = GROUPS.computeIfAbsent(token, unused -> new Group());
            InputStream result;
            synchronized (state) {
                if (state.lease == null || !state.lease.active()) {
                    if (state.lease != null) Arrays.fill(state.lease.key, (byte) 0);
                    long started = SystemClock.elapsedRealtime();
                    byte[] key = ByosKeyClient.fetchOnWorker(context, index.getString("server_url"), token,
                            Ld.getSignatureSha256(context), build, group);
                    state.lease = new Lease(key, started + 60_000);
                    Lease scheduled = state.lease;
                    EXPIRY.schedule(() -> {
                        synchronized (state) {
                            Arrays.fill(scheduled.key, (byte) 0);
                            if (state.lease == scheduled) state.lease = null;
                        }
                    }, Math.max(0, scheduled.until - SystemClock.elapsedRealtime()), TimeUnit.MILLISECONDS);
                }
                Lease lease = state.lease;
                result = ProtectedResourceStream.open(context.getAssets().open(ROOT + id + ".ssr"),
                        identity, group, id, resource.getLong("version"), lease.key,
                        () -> lease.active() && (!blockDebugger || !Debug.isDebuggerConnected()));
            }
            try {
                event.accept("resource_opened");
            } catch (RuntimeException observerError) {
                result.close();
                throw observerError;
            }
            return result;
        } catch (Exception error) {
            if (error instanceof InterruptedException) Thread.currentThread().interrupt();
            SecurityException failure = ByosKeyClient.failure(error);
            if ("K03_403".equals(failure.getMessage())) event.accept("authorization_denied");
            else event.accept("resource_unavailable");
            throw new IOException("业务资源暂不可用", failure);
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

        Lease(byte[] key, long until) {
            this.key = key;
            this.until = until;
        }

        boolean active() {
            return SystemClock.elapsedRealtime() < until;
        }
    }
}
