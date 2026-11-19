package dev.mocika.shield.loader;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.util.Log;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

/** 队列只保存公开事件和必要证明状态；安装私钥始终留在 AndroidKeyStore。 */
final class ByosRiskEvents {
    private static final String PREFS = "shellsmith_risk_v1";
    private static final Map<String, Session> sessions = new LinkedHashMap<>();
    private static ScheduledExecutorService worker;
    private static long nextChallengeAt;
    private static final SecureRandom random = new SecureRandom();

    private static SharedPreferences preferences(Context context) throws Exception {
        return context.getSharedPreferences(preferenceName(context), Context.MODE_PRIVATE);
    }

    private static String preferenceName(Context context) throws Exception {
        String process;
        if (android.os.Build.VERSION.SDK_INT >= 28) process = android.app.Application.getProcessName();
        else try (java.io.InputStream input = new java.io.FileInputStream("/proc/self/cmdline")) {
            byte[] bytes = new byte[256]; int size = input.read(bytes);
            if (size <= 0) throw new SecurityException();
            int end = 0; while (end < size && bytes[end] != 0) end++;
            process = new String(bytes, 0, end, StandardCharsets.UTF_8);
        }
        if (process == null || process.isEmpty()) throw new SecurityException();
        // 原生 SharedPreferences 不跨进程合并；按稳定进程名隔离队列，安装身份仍使用同一 Keystore 密钥。
        String name = context.getPackageName().equals(process) ? PREFS
                : PREFS + "_" + hex(hash(process.getBytes(StandardCharsets.UTF_8))).substring(0, 16);
        return name;
    }

    private static String authorizationId(String endpoint, String installation) throws Exception {
        return hex(hash((endpoint + "\n" + installation).getBytes(StandardCharsets.UTF_8)));
    }

    private static synchronized long authorizationVersion(Context context, String endpoint, String installation) throws Exception {
        long latest = context.getSharedPreferences(preferenceName(context) + "_auth", Context.MODE_PRIVATE)
                .getLong(authorizationId(endpoint, installation), -1);
        for (Session session : sessions.values()) if (session.endpoint.equals(endpoint) && session.installation.equals(installation))
            latest = Math.max(latest, session.authorizationVersion);
        // ponytail: 迁移扫描最多 64 个旧范围；队列仍各自保存，版本不再按 token/资源组隔离。
        for (Object raw : preferences(context).getAll().values()) {
            JSONObject saved = new JSONObject(raw.toString());
            String binding = saved.optString("binding");
            if (binding.startsWith(endpoint + "\n") && binding.endsWith("\n" + installation))
                latest = Math.max(latest, saved.optLong("authorization_version", -1));
        }
        return latest;
    }

    private static synchronized boolean rememberAuthorizationVersion(Context context, String endpoint, String installation, long version) throws Exception {
        if (version < 0) return true;
        long latest = Math.max(version, authorizationVersion(context, endpoint, installation));
        for (Session session : sessions.values()) if (session.endpoint.equals(endpoint) && session.installation.equals(installation))
            session.authorizationVersion = latest;
        boolean saved = context.getSharedPreferences(preferenceName(context) + "_auth", Context.MODE_PRIVATE)
                .edit().putLong(authorizationId(endpoint, installation), latest).commit();
        if (!saved) diagnostic("R_STORAGE");
        return saved;
    }

    static boolean enabled(Context context) {
        try {
            android.os.Bundle metadata = context.getPackageManager().getApplicationInfo(
                    context.getPackageName(), PackageManager.GET_META_DATA).metaData;
            return metadata != null && "byos".equals(metadata.getString("dev.mocika.shield.KEY_SOURCE"))
                    && metadata.getInt("dev.mocika.shield.RISK_PROTOCOL", 0) == 1;
        } catch (Exception ignored) { return false; }
    }

    static synchronized void initialize(Context context) {
        if (enabled(context)) {
            try {
                if (preferences(context).getAll().isEmpty()) return;
                java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
                try (java.io.InputStream input = context.getAssets().open("shellsmith-risk-v1.json")) {
                    byte[] buffer = new byte[1024]; int count;
                    while ((count = input.read(buffer)) != -1) {
                        if (bytes.size() + count > 65536) throw new SecurityException();
                        bytes.write(buffer, 0, count);
                    }
                }
                JSONObject config = new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
                if (!"byos".equals(config.getString("key_source")) || config.getInt("risk_protocol") != 1) return;
                String endpoint = config.getString("server_url"); ByosKeyClient.endpoint(endpoint);
                while (endpoint.endsWith("/")) endpoint = endpoint.substring(0, endpoint.length() - 1);
                JSONArray scopes = config.getJSONArray("scopes");
                if (scopes.length() > 64) return;
                KeyPair key;
                try (AutoCloseable startup = ByosProof.startupContext(context)) {
                    key = ByosProof.deviceKey(context, endpoint, Ld.getSignatureSha256(context));
                }
                String installation = hex(hash(key.getPublic().getEncoded()));
                if (!rememberAuthorizationVersion(context, endpoint, installation, authorizationVersion(context, endpoint, installation))) return;
                java.util.Set<String> allowed = new java.util.HashSet<>();
                for (int i = 0; i < scopes.length(); i++) {
                    JSONObject scope = scopes.getJSONObject(i);
                    allowed.add(hex(hash(String.join("\n", endpoint, scope.getString("token_id"),
                            scope.getString("build_id"), scope.getString("resource_group"), installation).getBytes(StandardCharsets.UTF_8))));
                }
                SharedPreferences prefs = preferences(context);
                for (String id : prefs.getAll().keySet()) if (!allowed.contains(id)) prefs.edit().remove(id).commit();
                for (int i = 0; i < scopes.length(); i++) {
                    JSONObject scope = scopes.getJSONObject(i);
                    resume(context, endpoint, scope.getString("token_id"), scope.getString("build_id"),
                            scope.getString("resource_group"), key);
                }
            } catch (Exception | LinkageError ignored) { diagnostic("R_STATE"); }
            return;
        }
        RuntimeSecurity.subscribeRisk(null);
        if (worker != null) worker.shutdownNow();
        worker = null;
        sessions.clear();
        java.io.File[] files = new java.io.File(context.getApplicationInfo().dataDir, "shared_prefs")
                .listFiles((directory, name) -> name.matches("shellsmith_risk_v1(?:_[0-9a-f]{16})?(?:_auth)?\\.xml"));
        if (files != null) for (java.io.File file : files) context.getSharedPreferences(
                file.getName().substring(0, file.getName().length() - 4), Context.MODE_PRIVATE).edit().clear().apply();
    }

    static void resume(Context c, String e, String t, String b, String g, KeyPair k) {
        activate(c, e, t, b, g, k, false);
    }

    static synchronized void authorized(Context c, String e, String t, String b, String g, KeyPair k, JSONObject response) throws Exception {
        if (!enabled(c) || k == null) return;
        JSONObject capability = response.optJSONObject("risk_events_v2");
        if (response.has("risk_events_v2") && !response.isNull("risk_events_v2") && capability == null) throw new SecurityException("K04");
        long version = capability == null ? -1 : version(capability, "authorization_version");
        if (RuntimeSecurity.remoteAccessRevoked()) throw new SecurityException("K17");
        String installation = hex(hash(k.getPublic().getEncoded()));
        if (capability != null && version < authorizationVersion(c, e, installation)) throw new SecurityException("K04");
        if (!rememberAuthorizationVersion(c, e, installation, version)) throw new IllegalStateException("R_STORAGE");
        String binding = String.join("\n", e, t, b == null ? "" : b, g == null ? "" : g, installation);
        activate(c, e, t, b, g, k, true);
        Session current = sessions.get(hex(hash(binding.getBytes(StandardCharsets.UTF_8))));
        if (current != null) {
            current.protocol = capability == null ? 1 : 2;
            current.authorizationVersion = Math.max(current.authorizationVersion, version);
            worker.execute(current::save);
        }
    }

    private static long version(JSONObject object, String key) throws Exception {
        Object value = object.opt(key);
        if (!(value instanceof Integer || value instanceof Long) || ((Number) value).longValue() < 0) throw new SecurityException("K04");
        return ((Number) value).longValue();
    }

    private static synchronized void activate(Context c, String endpoint, String token, String build,
            String group, KeyPair key, boolean granted) {
        if (!enabled(c) || key == null || Thread.currentThread().isInterrupted()) return;
        try {
            String installation = hex(hash(key.getPublic().getEncoded()));
            sessions.values().removeIf(session -> !session.installation.equals(installation));
            if (sessions.isEmpty() && worker != null) {
                RuntimeSecurity.subscribeRisk(null); worker.shutdownNow(); worker = null;
            }
            String binding = String.join("\n", endpoint, token, build == null ? "" : build,
                    group == null ? "" : group, installation);
            String id = hex(hash(binding.getBytes(StandardCharsets.UTF_8)));
            if (sessions.containsKey(id)) return;
            SharedPreferences prefs = preferences(c);
            for (Map.Entry<String, ?> old : prefs.getAll().entrySet()) {
                JSONObject saved = new JSONObject(old.getValue().toString());
                if (!saved.optString("binding").endsWith("\n" + installation)) prefs.edit().remove(old.getKey()).commit();
            }
            JSONObject state = new JSONObject(prefs.getString(id, "{}"));
            if (!binding.equals(state.optString("binding"))) {
                if (!granted) return;
                state = new JSONObject().put("binding", binding).put("queue", new JSONArray());
                // ponytail: 最多 64 个授权范围、每范围 16 条；大规模资源组需改为共享有界数据库。
                if (prefs.getAll().size() >= 64) { diagnostic("R_QUEUE_FULL"); return; }
                if (!prefs.edit().putString(id, state.toString()).commit()) { diagnostic("R_STORAGE"); return; }
            }
            Session session = new Session(c, endpoint, token, build, group, installation, key, prefs, id, state);
            sessions.put(id, session);
            if (worker == null) {
                worker = Executors.newSingleThreadScheduledExecutor(task -> {
                    Thread thread = new Thread(task, "shellsmith-risk"); thread.setDaemon(true); return thread;
                });
                RuntimeSecurity.subscribeRisk(detection -> {
                    synchronized (ByosRiskEvents.class) {
                        if (worker != null) worker.execute(() -> detected(detection));
                    }
                });
                // 进程存活期间复查；不注册常驻服务、不唤醒已退出应用。
                worker.scheduleWithFixedDelay(() -> {
                    try { RuntimeSecurity.observeResources(); } catch (RuntimeException | LinkageError ignored) { }
                }, 1, 30, TimeUnit.SECONDS);
            }
            worker.execute(() -> session.flush());
        } catch (Exception ignored) { diagnostic("R_STATE"); }
    }

    private static void detected(RuntimeSecurity.Detection detection) {
        if (!detection.code.matches("[A-Za-z][A-Za-z0-9_]{0,63}")) return;
        java.util.List<Session> active;
        synchronized (ByosRiskEvents.class) { active = new java.util.ArrayList<>(sessions.values()); }
        for (Session session : active) session.enqueue(detection);
    }

    static byte[] hash(byte[] value) throws Exception { return MessageDigest.getInstance("SHA-256").digest(value); }
    static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return result.toString();
    }
    static byte[] eventDigest(String endpoint, JSONObject event) throws Exception {
        int protocol = event.getInt("protocol");
        if ((protocol != 1 && protocol != 2) || (protocol == 1 && event.has("evidence"))) throw new SecurityException("K04");
        String canonical = String.join("\n", protocol == 1 ? "shellsmith-risk-event-v1" : "shellsmith-risk-event-v2", endpoint, Integer.toString(protocol), event.getString("platform"),
                event.getString("token_id"), event.getString("build_id"), event.getString("resource_group"),
                event.getString("installation_id"), event.getString("event_id"),
                Long.toString(event.getLong("detected_at")), event.getString("detection_code"),
                event.getString("detector_version"));
        if (protocol == 2) canonical += "\n" + hex(ByosRiskEvidence.digest(event.getJSONObject("evidence")));
        return hash(canonical.getBytes(StandardCharsets.UTF_8));
    }
    static byte[] challengeDigest(byte[] event, long timestamp, String requestId) throws Exception {
        return hash(String.join("\n", "shellsmith-risk-challenge-v1", hex(event),
                Long.toString(timestamp), requestId).getBytes(StandardCharsets.UTF_8));
    }
    static byte[] reportDigest(byte[] event, String challenge) throws Exception {
        return hash(String.join("\n", "shellsmith-risk-report-v1", hex(event), challenge).getBytes(StandardCharsets.UTF_8));
    }
    private static String randomUrl() { byte[] value = new byte[32]; random.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static void diagnostic(String code) { Log.w("RuntimeSecurity", code); }

    private static final class Session {
        final Context context;
        final String endpoint, token, build, group, installation, id;
        final KeyPair key;
        final SharedPreferences prefs;
        final JSONObject state;
        final JSONArray queue;
        long next;
        int failures;
        boolean scheduled;
        volatile int protocol;
        volatile long authorizationVersion;
        Session(Context c, String e, String t, String b, String g, String i, KeyPair k, SharedPreferences p, String id,
                JSONObject state) throws Exception {
            context = c.getApplicationContext() == null ? c : c.getApplicationContext();
            endpoint = e; token = t; build = b == null ? "" : b; group = g == null ? "" : g;
            installation = i; key = k; prefs = p; this.id = id; this.state = state;
            queue = state.getJSONArray("queue");
            protocol = state.optInt("protocol", 1);
            authorizationVersion = state.optLong("authorization_version", -1);
            authorizationVersion = Math.max(authorizationVersion, ByosRiskEvents.authorizationVersion(c, e, i));
            if (protocol != 1 && protocol != 2) throw new SecurityException("K04");
            if (queue.length() > 16) throw new SecurityException();
        }
        boolean save() {
            try { state.put("protocol", protocol).put("authorization_version", authorizationVersion); }
            catch (Exception error) { diagnostic("R_STORAGE"); return false; }
            boolean saved = prefs.edit().putString(id, state.toString()).commit();
            if (!saved) diagnostic("R_STORAGE"); return saved; }
        void enqueue(RuntimeSecurity.Detection detection) {
            try {
                long now = System.currentTimeMillis() / 1000;
                for (int n = 0; n < queue.length(); n++) {
                    JSONObject event = queue.getJSONObject(n).getJSONObject("event");
                    if (detection.code.equals(event.getString("detection_code"))
                            && (protocol == 1 || detection.signal.equals(event.optJSONObject("evidence") == null ? "" : event.getJSONObject("evidence").optString("signal")))) return;
                }
                if (queue.length() >= 16) { diagnostic("R_QUEUE_FULL"); return; }
                byte[] eventId = new byte[16]; random.nextBytes(eventId);
                int wireProtocol = protocol;
                JSONObject event = new JSONObject().put("protocol", wireProtocol).put("platform", "android")
                        .put("token_id", token).put("build_id", build).put("resource_group", group)
                        .put("installation_id", installation).put("event_id", hex(eventId)).put("detected_at", wireProtocol == 1 ? now : detection.at)
                        .put("detection_code", detection.code).put("detector_version", wireProtocol == 1 ? "1" : "2");
                if (wireProtocol == 2) event.put("evidence", ByosRiskEvidence.capture(context, detection, !group.isEmpty()));
                queue.put(new JSONObject().put("event", event));
                if (!save()) schedule(60);
                else if (!scheduled) flush();
            } catch (Exception ignored) { diagnostic("R_STATE"); }
        }
        String sign(byte[] digest) throws Exception {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(key.getPrivate()); signature.update(digest);
            return Base64.getEncoder().encodeToString(signature.sign());
        }
        void flush() {
            scheduled = false;
            if (queue.length() == 0) return;
            long now = System.currentTimeMillis() / 1000;
            if (now < next) { schedule(next - now); return; }
            JSONObject current = null;
            try {
                for (int i = queue.length() - 1; i >= 0; i--) {
                    if (now - queue.getJSONObject(i).getJSONObject("event").getLong("detected_at") > 86400) {
                        queue.remove(i); diagnostic("R_EXPIRED");
                    }
                }
                if (!save()) { schedule(60); return; }
                int position = 0;
                while (position < queue.length() && queue.getJSONObject(position).optBoolean("stopped")) position++;
                if (position == queue.length()) { if (queue.length() > 0) schedule(3600); return; }
                JSONObject item = queue.getJSONObject(position), event = item.getJSONObject("event");
                current = item;
                byte[] digest = eventDigest(endpoint, event);
                JSONObject report = item.optJSONObject("report");
                if (report == null) {
                    if (now < nextChallengeAt) { next = nextChallengeAt; schedule(next - now); return; }
                    nextChallengeAt = now + 6;
                    String requestId = randomUrl();
                    JSONObject challenge = ByosKeyClient.post(endpoint, "/v1/risk-events/challenge",
                            new JSONObject().put("event", event).put("timestamp", now).put("request_id", requestId)
                            .put("signature", sign(challengeDigest(digest, now, requestId))), null);
                    String value = challenge.getString("challenge");
                    if (challenge.getInt("ttl_seconds") != 60 || !value.matches("[A-Za-z0-9_-]{43}")) throw new SecurityException("K04");
                    report = new JSONObject().put("event", event).put("challenge", value)
                            .put("proof", sign(reportDigest(digest, value)));
                    item.put("report", report).put("challenge_at", now);
                    if (!save()) { schedule(60); return; }
                }
                JSONObject receipt = ByosKeyClient.post(endpoint, "/v1/risk-events/report", report, null);
                if (!"accepted".equals(receipt.optString("status"))
                        || !event.getString("event_id").equals(receipt.optString("event_id"))
                        || !("record".equals(receipt.optString("action")) || "revoke".equals(receipt.optString("action")))
                        || !(receipt.opt("authorization_version") instanceof Integer || receipt.opt("authorization_version") instanceof Long)
                        || receipt.getLong("authorization_version") < 0) throw new SecurityException("K04");
                boolean revoked = false;
                boolean versionSaved = true;
                if (event.getInt("protocol") == 2) {
                    long currentVersion = version(receipt, "current_authorization_version");
                    String status = receipt.getString("current_status");
                    if (currentVersion < version(receipt, "authorization_version")
                            || !("approved".equals(status) || "revoked".equals(status))) throw new SecurityException("K04");
                    synchronized (ByosRiskEvents.class) {
                        if (sessions.get(id) == this && currentVersion >= ByosRiskEvents.authorizationVersion(context, endpoint, installation)) {
                            versionSaved = rememberAuthorizationVersion(context, endpoint, installation, currentVersion);
                            if ("revoked".equals(status)) { RuntimeSecurity.revokeRemoteAccess(); revoked = true; }
                        }
                    }
                }
                if (revoked) {
                    MocikaProtectedResources.revokeRemoteAccess();
                    diagnostic("R_REVOKED");
                }
                if (!versionSaved) throw new IllegalStateException("R_STORAGE");
                queue.remove(position); save(); failures = 0; next = now + 10; schedule(10);
            } catch (Exception error) {
                String code = ByosKeyClient.failure(error).getMessage();
                try {
                    JSONObject item = current;
                    if (item == null) throw new SecurityException();
                    if ("K03_403".equals(code) && item.has("report") && now - item.optLong("challenge_at") >= 60) {
                        item.remove("report"); item.remove("challenge_at");
                    } else if ("K03_400".equals(code) || "K03_409".equals(code) || "K04".equals(code)) {
                        item.put("stopped", true);
                    }
                    save();
                } catch (Exception ignored) { }
                diagnostic("K03_404".equals(code) ? "R_CONFIG" : "K03_403".equals(code) ? "R_DENIED" : "R_RETRY");
                long delay = "K03_404".equals(code) ? 3600 : Math.min(3600, 10L << Math.min(++failures, 8));
                delay += random.nextInt(10);
                next = now + delay; schedule(delay);
            }
        }
        void schedule(long delay) {
            synchronized (ByosRiskEvents.class) {
                if (!scheduled && worker != null && !worker.isShutdown()) {
                    scheduled = true; worker.schedule(this::flush, delay, TimeUnit.SECONDS);
                }
            }
        }
    }
}
