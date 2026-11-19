package dev.mocika.shield.loader;

import android.content.Context;
import android.app.Instrumentation;
import android.os.Bundle;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

/** 仅测试 APK 拦截 HTTPS 连接；验证真实 Keystore 和完整客户端协议，不代表 TLS/正式服务验收。 */
public class ByosDeviceContractTest extends Instrumentation {
    private static Context testContext;
    private static Result startupResult;
    // 真正在 Application.attachBaseContext 主线程运行，防止普通单测掩盖启动期 Keystore 故障。
    public static final class StartupApplication extends android.app.Application {
        @Override protected void attachBaseContext(Context base) {
            super.attachBaseContext(base);
            try {
                java.lang.reflect.Method exempt = StubApp.class.getDeclaredMethod("exemptHiddenApi");
                exempt.setAccessible(true);
                exempt.invoke(null);
                testContext = this;
                assertStartupReleased();
                startupResult = JUnitCore.runClasses(ByosDeviceContractTest.class);
                assertStartupReleased();
            } catch (Exception error) { throw new AssertionError(error); }
        }
    }

    private static void assertStartupReleased() throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= 31) return;
        Class<?> type = Class.forName("android.app.ActivityThread");
        assertNull(type.getMethod("currentApplication").invoke(null));
    }

    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }
    @Override public void onStart() {
        Result result = startupResult;
        if (result == null) throw new AssertionError("未执行 attachBaseContext 取钥回归");
        Bundle report = new Bundle();
        StringBuilder output = new StringBuilder("\nTests: " + result.getRunCount() + ", failures: " + result.getFailureCount() + "\n");
        for (org.junit.runner.notification.Failure failure : result.getFailures()) output.append(failure.getTrace());
        report.putString(REPORT_KEY_STREAMRESULT, output.toString());
        finish(result.wasSuccessful() ? -1 : 0, report);
    }

    private static final String ENDPOINT = "https://byos-test.invalid";
    private static final String CERT = new String(new char[64]).replace('\0', 'A');
    private final Set<String> consumed = new HashSet<>();
    private String approvedKey;
    private String failure = "";
    private JSONObject last;
    private final byte[] ikm = new byte[32];
    private JSONObject riskReport;
    private int riskChallenges, riskReports;
    private boolean loseReceipt = true;

    @Test public void 风险协议固定互操作向量() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (InputStream input = testContext.getAssets().open("risk-event-vector.json")) {
            byte[] buffer = new byte[1024]; int count;
            while ((count = input.read(buffer)) != -1) bytes.write(buffer, 0, count);
        }
        JSONObject vector = new JSONObject(bytes.toString("UTF-8"));
        byte[] digest = ByosRiskEvents.eventDigest(vector.getString("public_base_url"), vector.getJSONObject("event"));
        assertEquals(vector.getString("event_digest"), ByosRiskEvents.hex(digest));
        assertEquals(vector.getString("challenge_digest"), ByosRiskEvents.hex(ByosRiskEvents.challengeDigest(
                digest, vector.getLong("timestamp"), vector.getString("request_id"))));
        assertEquals(vector.getString("report_digest"), ByosRiskEvents.hex(ByosRiskEvents.reportDigest(digest, vector.getString("challenge"))));
    }

    @Test public void 设备批准撤销与加密取钥拒绝路径() throws Exception {
        Arrays.fill(ikm, (byte) 42);
        Context context = testContext;
        context.getSharedPreferences("shellsmith_risk_v1", Context.MODE_PRIVATE).edit().clear().commit();
        assertTrue(ByosRiskEvents.enabled(context));
        java.util.concurrent.ExecutorService threads = java.util.concurrent.Executors.newFixedThreadPool(4);
        KeyPair device;
        try (AutoCloseable startup = ByosProof.startupContext(context)) {
            java.util.List<java.util.concurrent.Future<KeyPair>> keys = new java.util.ArrayList<>();
            for (int i = 0; i < 4; i++) keys.add(threads.submit(() -> ByosProof.deviceKey(context, ENDPOINT, CERT)));
            byte[] first = keys.get(0).get().getPublic().getEncoded();
            for (java.util.concurrent.Future<KeyPair> key : keys) assertArrayEquals(first, key.get().getPublic().getEncoded());
            device = ByosProof.deviceKey(context, ENDPOINT, CERT);
            assertNull(device.getPrivate().getEncoded());
            assertArrayEquals(device.getPublic().getEncoded(), ByosProof.deviceKey(context, ENDPOINT, CERT).getPublic().getEncoded());
            // 已有 Application 时不替换；嵌套调用关闭不能提前清掉外层启动上下文。
            try (AutoCloseable nested = ByosProof.startupContext(context)) {
                assertNull(nested);
            }
        } finally { threads.shutdownNow(); }
        assertStartupReleased();
        URL.setURLStreamHandlerFactory(protocol -> "https".equals(protocol) ? new URLStreamHandler() {
            @Override protected URLConnection openConnection(URL url) {
                assertTrue(url.toString().startsWith(ENDPOINT + "/v1/"));
                return new HttpsURLConnection(url) {
                    final ByteArrayOutputStream request = new ByteArrayOutputStream();
                    JSONObject response;
                    int status;
                    @Override public OutputStream getOutputStream() { return request; }
                    @Override public int getResponseCode() {
                        try {
                            if ("timeout".equals(failure)) new java.util.concurrent.CountDownLatch(1).await();
                            assertFalse(getInstanceFollowRedirects());
                            last = new JSONObject(request.toString("UTF-8"));
                            assertNull(getRequestProperty("Authorization"));
                            assertNull(getRequestProperty("Cookie"));
                            if (url.getPath().startsWith("/v1/risk-events/")) {
                                response = serveRisk(url.getPath(), last); status = 200;
                                if (url.getPath().endsWith("/report") && loseReceipt) { loseReceipt = false; status = 503; }
                            } else if (url.getPath().equals("/v1/resource-keys/challenge")) {
                                response = serveResourceChallenge(last); status = 200;
                            } else { response = serve(last); status = response == null ? 403 : 200; }
                        } catch (Exception e) { throw new AssertionError(e); }
                        return "redirect".equals(failure) ? 302 : status;
                    }
                    @Override public InputStream getInputStream() {
                        return new ByteArrayInputStream(response.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    }
                    @Override public void connect() { }
                    @Override public void disconnect() { }
                    @Override public boolean usingProxy() { return false; }
                    @Override public String getCipherSuite() { return "测试连接"; }
                    @Override public Certificate[] getLocalCertificates() { return null; }
                    @Override public Certificate[] getServerCertificates() { return null; }
                };
            }
        } : null);
        denied(context); // 未批准的新设备不能获取密钥。
        assertRiskInactive();
        approvedKey = encode(device.getPublic().getEncoded());
        for (String bad : new String[]{"mode", "nonce", "raw", "cipher"}) {
            failure = bad; denied(context); assertRiskInactive();
        }
        failure = "";
        assertArrayEquals(ikm, ByosKeyClient.fetch(context, ENDPOINT, "test-token", CERT));
        assertStartupReleased();
        assertFalse(last.has("integrity_token"));
        assertNull(serve(last)); // 同一证明再次提交被拒绝。
        String previousId = last.getString("request_id");
        assertArrayEquals(ikm, ByosKeyClient.fetch(context, ENDPOINT, "test-token", CERT));
        assertStartupReleased();
        assertNotEquals(previousId, last.getString("request_id"));
        for (String bad : new String[]{"mode", "nonce", "raw", "cipher", "redirect", "timeout"}) {
            failure = bad; denied(context);
            assertStartupReleased();
        }
        failure = ""; approvedKey = null; denied(context); // 撤销立即影响后续取钥。
        assertStartupReleased();
        // 已撤销安装仍持有原密钥，可认证上报；丢失收据先重发原请求。
        approvedKey = encode(device.getPublic().getEncoded());
        RuntimeSecurity.detected("debugger");
        flushRiskWorker(false);
        assertEquals(1, riskReports);
        assertEquals(1, riskChallenges);
        String persisted = context.getSharedPreferences("shellsmith_risk_v1", Context.MODE_PRIVATE).getAll().toString();
        assertFalse(persisted.contains("\"ikm\"")); assertFalse(persisted.contains("api_key"));
        flushRiskWorker(true);
        assertEquals(2, riskReports); assertEquals(1, riskChallenges);
        // 清空风险模块内存和队列，单独验证纯资源入口也会在成功解包后启用。
        java.lang.reflect.Field executor = ByosRiskEvents.class.getDeclaredField("worker"); executor.setAccessible(true);
        ((java.util.concurrent.ExecutorService) executor.get(null)).shutdownNow(); executor.set(null, null);
        java.lang.reflect.Field sessions = ByosRiskEvents.class.getDeclaredField("sessions"); sessions.setAccessible(true);
        ((java.util.Map<?, ?>) sessions.get(null)).clear(); RuntimeSecurity.subscribeRisk(null);
        context.getSharedPreferences("shellsmith_risk_v1", Context.MODE_PRIVATE).edit().clear().commit();
        try (AutoCloseable startup = ByosProof.startupContext(context)) {
            assertArrayEquals(ikm, ByosKeyClient.fetchOnWorker(context, ENDPOINT, "r_" + repeat('b', 64), CERT,
                    repeat('a', 32), "media", null));
        }
        assertNotNull(executor.get(null));
        assertTrue(context.getSharedPreferences("shellsmith_risk_v1", Context.MODE_PRIVATE).getAll().toString().contains("media"));
    }

    private static void assertRiskInactive() throws Exception {
        java.lang.reflect.Field field = ByosRiskEvents.class.getDeclaredField("worker"); field.setAccessible(true);
        assertNull(field.get(null));
    }

    private static void flushRiskWorker(boolean force) throws Exception {
        java.lang.reflect.Field executor = ByosRiskEvents.class.getDeclaredField("worker"); executor.setAccessible(true);
        ((java.util.concurrent.ExecutorService) executor.get(null)).submit(() -> {
            if (!force) return;
            try {
                java.lang.reflect.Field sessions = ByosRiskEvents.class.getDeclaredField("sessions"); sessions.setAccessible(true);
                for (Object session : ((java.util.Map<?, ?>) sessions.get(null)).values()) {
                    java.lang.reflect.Field next = session.getClass().getDeclaredField("next"); next.setAccessible(true); next.setLong(session, 0);
                    java.lang.reflect.Method flush = session.getClass().getDeclaredMethod("flush"); flush.setAccessible(true); flush.invoke(session);
                }
            } catch (Exception error) { throw new AssertionError(error); }
        }).get();
    }

    private JSONObject serveRisk(String route, JSONObject request) throws Exception {
        JSONObject event = request.getJSONObject("event");
        assertEquals("test-token", event.getString("token_id"));
        assertEquals("", event.getString("build_id")); assertEquals("", event.getString("resource_group"));
        assertEquals(ByosRiskEvents.hex(ByosRiskEvents.hash(decode(approvedKey))), event.getString("installation_id"));
        byte[] digest = ByosRiskEvents.eventDigest(ENDPOINT, event);
        String challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        boolean isChallenge = route.endsWith("/challenge");
        byte[] signed = isChallenge ? ByosRiskEvents.challengeDigest(digest, request.getLong("timestamp"), request.getString("request_id"))
                : ByosRiskEvents.reportDigest(digest, request.getString("challenge"));
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(decode(approvedKey))));
        verifier.update(signed); assertTrue(verifier.verify(decode(request.getString(isChallenge ? "signature" : "proof"))));
        if (isChallenge) { riskChallenges++; return new JSONObject().put("challenge", challenge).put("ttl_seconds", 60); }
        riskReports++;
        if (riskReport == null) riskReport = request;
        else assertEquals(riskReport.toString(), request.toString());
        return new JSONObject().put("status", "accepted").put("event_id", event.getString("event_id"))
                .put("action", "revoke").put("authorization_version", 3);
    }

    private void denied(Context context) {
        try { ByosKeyClient.fetch(context, ENDPOINT, "test-token", CERT); fail("拒绝路径被放行"); }
        catch (SecurityException expected) {
            String code = "timeout".equals(failure) ? "K10" : "redirect".equals(failure) ? "K03_302"
                    : failure.isEmpty() ? "K03_403" : "K04";
            assertEquals(code, expected.getMessage());
            assertNull(expected.getCause());
        }
    }

    private static String encode(byte[] bytes) {
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP);
    }

    private static String encodeUrl(byte[] bytes) {
        return android.util.Base64.encodeToString(
                bytes,
                android.util.Base64.URL_SAFE
                        | android.util.Base64.NO_WRAP
                        | android.util.Base64.NO_PADDING);
    }

    private static byte[] decode(String value) {
        return android.util.Base64.decode(value, android.util.Base64.DEFAULT);
    }

    private static String repeat(char value, int size) { return new String(new char[size]).replace('\0', value); }

    private JSONObject serveResourceChallenge(JSONObject request) throws Exception {
        assertEquals("r_" + repeat('b', 64), request.getString("token_id"));
        String text = String.join("\n", "shellsmith-resource-challenge-v1", ENDPOINT, request.getString("token_id"),
                request.getString("build_id"), request.getString("resource_group"), Long.toString(request.getLong("timestamp")),
                request.getString("request_id"), request.getString("device_public_key"));
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(decode(request.getString("device_public_key")))));
        signature.update(ByosRiskEvents.hash(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertTrue(signature.verify(decode(request.getString("device_signature"))));
        return new JSONObject().put("challenge", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
    }

    private JSONObject serve(JSONObject request) throws Exception {
        assertEquals("device_approval", request.getString("auth_mode"));
        assertEquals(2, request.getInt("fetch_protocol"));
        String token = request.getString("token_id");
        assertEquals(request.has("build_id") ? "r_" + repeat('b', 64) : "test-token", token);
        assertEquals(CERT, request.getString("cert_fingerprint"));
        byte[] digest = ByosKeyClient.nonceDigest(ENDPOINT, token, request.getString("package_name"), CERT,
                request.getLong("timestamp"), request.getString("request_id"), "device_approval",
                request.getString("response_public_key"), request.getString("device_public_key"));
        if (request.has("build_id")) {
            String text = String.join("\n", "shellsmith-resource-v1", ENDPOINT, token, request.getString("package_name"), CERT,
                    Long.toString(request.getLong("timestamp")), request.getString("request_id"), "device_approval",
                    request.getString("response_public_key"), request.getString("device_public_key"), request.getString("build_id"),
                    request.getString("resource_group"), request.getString("challenge"));
            digest = ByosRiskEvents.hash(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        assertEquals(encodeUrl(digest), request.getString("nonce"));
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(decode(request.getString("device_public_key"))));
        Signature signature = Signature.getInstance("SHA256withECDSA"); signature.initVerify(publicKey); signature.update(digest);
        assertTrue(signature.verify(decode(request.getString("device_signature"))));
        if (!request.getString("device_public_key").equals(approvedKey) || !consumed.add(request.getString("nonce"))) return null;
        byte[] plaintext = new byte[64]; System.arraycopy(digest, 0, plaintext, 0, 32); System.arraycopy(ikm, 0, plaintext, 32, 32);
        Cipher wrapper = Cipher.getInstance("RSA/ECB/OAEPPadding");
        wrapper.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decode(request.getString("response_public_key")))),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] ciphertext = wrapper.doFinal(plaintext);
        if ("cipher".equals(failure)) ciphertext[50] ^= 1;
        JSONObject response = new JSONObject().put("fetch_protocol", 2).put("auth_mode", "mode".equals(failure) ? "play_integrity" : "device_approval")
                .put("token_id", token).put("nonce", "nonce".equals(failure) ? "wrong" : request.getString("nonce"))
                .put("wrapped_ikm", encode(ciphertext));
        if (request.has("build_id")) response.put("ttl_seconds", 60);
        if ("raw".equals(failure)) response.put("ikm", encode(ikm));
        return response;
    }
}
