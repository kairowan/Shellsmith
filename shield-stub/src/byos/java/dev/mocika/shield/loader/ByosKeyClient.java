package dev.mocika.shield.loader;

import android.content.Context;
import android.os.Build;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;

/** BYOS 专用资源中的客户端；不落盘、不缓存 IKM，不提供鉴权降级。 */
final class ByosKeyClient {
    static byte[] fetch(Context ctx, String endpoint, String token, String certificate) {
        if (Build.VERSION.SDK_INT < ByosProof.MIN_API) throw new SecurityException("K00");
        try (AutoCloseable startup = ByosProof.startupContext(ctx)) {
            return fetchWithContext(ctx, endpoint, token, certificate);
        } catch (Exception error) {
            throw failure(error);
        }
    }

    // 保留可排障的固定分类，不把端点、令牌、服务响应或系统异常原文带进崩溃日志。
    static SecurityException failure(Throwable error) {
        if (error instanceof java.util.concurrent.ExecutionException) error = error.getCause();
        String code = "K01";
        if (error instanceof SecurityException && error.getMessage() != null
                && error.getMessage().matches("K(?:0[0-5]|1[0-6]|03_[1-5][0-9]{2})")) code = error.getMessage();
        else if (error instanceof java.util.concurrent.TimeoutException || error instanceof java.net.SocketTimeoutException) code = "K10";
        else if (error instanceof InterruptedException) code = "K11";
        else if (error instanceof java.net.UnknownHostException) code = "K12";
        else if (error instanceof javax.net.ssl.SSLException) code = "K13";
        else if (error instanceof java.net.ConnectException) code = "K14";
        else if (error instanceof java.io.IOException) code = "K15";
        else if (error instanceof javax.crypto.BadPaddingException || error instanceof javax.crypto.IllegalBlockSizeException) code = "K04";
        else if (error instanceof java.security.GeneralSecurityException) code = "K16";
        return new SecurityException(code);
    }

    private static byte[] fetchWithContext(Context ctx, String endpoint, String token, String certificate) {
        FutureTask<byte[]> request = new FutureTask<>(() -> fetchOnWorker(ctx, endpoint, token, certificate, null, null, null));
        Thread worker = new Thread(request, "byos-key");
        worker.setDaemon(true);
        worker.start();
        try {
            // 加载器必须等到业务 DEX 就绪；限制启动等待，禁止无限阻塞。
            return request.get(8, TimeUnit.SECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw failure(error);
        } catch (Exception error) {
            throw failure(error);
        } finally {
            request.cancel(true);
        }
    }

    static URI endpoint(String value) throws Exception {
        if (value == null || value.length() > 2048 || !value.equals(value.trim())) throw new SecurityException("K02");
        URI uri = new URI(value);
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null) throw new SecurityException("K02");
        return uri;
    }

    static byte[] nonceDigest(String endpoint, String token, String pkg, String cert, long timestamp,
            String requestId, String mode, String responseKey, String deviceKey) throws Exception {
        String message = "shellsmith-byos-v2\n" + endpoint + "\n" + token + "\n" + pkg + "\n" + cert
                + "\n" + timestamp + "\n" + requestId + "\n" + mode + "\n" + responseKey + "\n" + deviceKey;
        return MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] decode(String encoded, int length) {
        if (encoded.length() != ((length + 2) / 3) * 4) throw new SecurityException("K04");
        byte[] bytes = Base64.getDecoder().decode(encoded);
        if (bytes.length != length || !encoded.equals(Base64.getEncoder().encodeToString(bytes))) {
            Arrays.fill(bytes, (byte) 0); throw new SecurityException("K04");
        }
        return bytes;
    }

    // 只加密 32 字节请求摘要 + 32 字节 IKM；使用平台 OAEP，避免另造对称封装协议。
    static byte[] unwrap(String encoded, PrivateKey key, byte[] digest) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] plaintext = cipher.doFinal(decode(encoded, 256));
        try {
            if (plaintext.length != 64 || !MessageDigest.isEqual(digest, Arrays.copyOf(plaintext, 32))
                    || Thread.currentThread().isInterrupted()) throw new SecurityException("K04");
            return Arrays.copyOfRange(plaintext, 32, 64);
        } finally { Arrays.fill(plaintext, (byte) 0); }
    }

    static byte[] fetchOnWorker(Context ctx, String endpoint, String token, String certificate,
            String build, String group, String traceId) throws Exception {
        endpoint(endpoint);
        while (endpoint.endsWith("/")) endpoint = endpoint.substring(0, endpoint.length() - 1);
        if (token == null || !token.matches("[A-Za-z0-9_-]{1,256}") || certificate == null
                || !certificate.matches("[0-9A-F]{64}")) throw new SecurityException("K02");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair responseKey = generator.generateKeyPair();
        String publicKey = Base64.getEncoder().encodeToString(responseKey.getPublic().getEncoded());
        KeyPair device = ByosProof.deviceKey(ctx, endpoint, certificate);
        ByosRiskEvents.resume(ctx, endpoint, token, build, group, device);
        String devicePublicKey = device == null ? "" : Base64.getEncoder().encodeToString(device.getPublic().getEncoded());
        byte[] random = new byte[32]; new SecureRandom().nextBytes(random);
        String requestId = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        long timestamp = System.currentTimeMillis() / 1000;
        JSONObject body;
        byte[] digest;
        String route;
        if (build == null) {
            route = "/v1/keys/fetch";
            digest = nonceDigest(endpoint, token, ctx.getPackageName(), certificate, timestamp, requestId,
                    ByosProof.MODE, publicKey, devicePublicKey);
            body = new JSONObject();
        } else {
            route = "/v1/resource-keys/fetch";
            if (device == null || !token.matches("r_[0-9a-f]{64}") || !build.matches("[0-9a-f]{32}")
                    || !group.matches("[a-z0-9_-]{1,64}")) throw new SecurityException("K02");
            JSONObject scope = new JSONObject().put("token_id", token).put("build_id", build).put("resource_group", group);
            String challengeMessage = String.join("\n", "shellsmith-resource-challenge-v1", endpoint, token,
                    build, group, Long.toString(timestamp), requestId, devicePublicKey);
            byte[] challengeDigest = MessageDigest.getInstance("SHA-256").digest(challengeMessage.getBytes(StandardCharsets.UTF_8));
            Signature challengeProof = Signature.getInstance("SHA256withECDSA");
            challengeProof.initSign(device.getPrivate());
            challengeProof.update(challengeDigest);
            String challenge = post(endpoint, "/v1/resource-keys/challenge", scope
                    .put("device_public_key", devicePublicKey).put("timestamp", timestamp).put("request_id", requestId)
                    .put("device_signature", Base64.getEncoder().encodeToString(challengeProof.sign())), traceId)
                    .getString("challenge");
            if (!challenge.matches("[A-Za-z0-9_-]{43}")) throw new SecurityException("K04");
            String message = String.join("\n", "shellsmith-resource-v1", endpoint, token, ctx.getPackageName(),
                    certificate, Long.toString(timestamp), requestId, ByosProof.MODE, publicKey, devicePublicKey,
                    build, group, challenge);
            digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8));
            body = scope.put("challenge", challenge);
        }
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        body.put("fetch_protocol", 2).put("auth_mode", ByosProof.MODE)
                .put("token_id", token).put("server_url", endpoint)
                .put("package_name", ctx.getPackageName()).put("cert_fingerprint", certificate)
                .put("timestamp", timestamp).put("request_id", requestId).put("nonce", nonce)
                .put("response_public_key", publicKey);
        if (device != null) {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(device.getPrivate()); signature.update(digest);
            body.put("device_public_key", devicePublicKey)
                    .put("device_signature", Base64.getEncoder().encodeToString(signature.sign()));
        } else {
            body.put("integrity_token", ByosProof.integrityToken(ctx, nonce));
        }
        try {
            JSONObject response = post(endpoint, route, body, traceId);
            if (!token.equals(response.getString("token_id")) || !nonce.equals(response.getString("nonce"))) throw new SecurityException("K04");
            if (response.has("ikm") || response.getInt("fetch_protocol") != 2
                    || !ByosProof.MODE.equals(response.getString("auth_mode"))) throw new SecurityException("K04");
            if (build != null && response.getInt("ttl_seconds") != 60) throw new SecurityException("K04");
            byte[] ikm = unwrap(response.getString("wrapped_ikm"), responseKey.getPrivate(), digest);
            ByosRiskEvents.authorized(ctx, endpoint, token, build, group, device);
            return ikm;
        } catch (org.json.JSONException | IllegalArgumentException error) {
            throw new SecurityException("K04");
        }
    }

    static JSONObject post(String endpoint, String route, JSONObject body, String traceId) throws Exception {
        HttpsURLConnection connection = (HttpsURLConnection) new URI(endpoint + route).toURL().openConnection();
        try {
            connection.setRequestMethod("POST");
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(3000); connection.setReadTimeout(3000);
            connection.setUseCaches(false); connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            if (traceId != null) connection.setRequestProperty("X-Shellsmith-Request-ID", traceId);
            byte[] json = body.toString().getBytes(StandardCharsets.UTF_8);
            if (json.length > ("/v1/risk-events/report".equals(route) ? 32768 : 4096)) throw new SecurityException("K04");
            connection.setFixedLengthStreamingMode(json.length);
            try (OutputStream output = connection.getOutputStream()) { output.write(json); }
            int status = connection.getResponseCode();
            if (status != 200) throw new SecurityException(status >= 100 && status <= 599 ? "K03_" + status : "K03");
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (InputStream input = connection.getInputStream()) {
                byte[] buffer = new byte[1024]; int n;
                while ((n = input.read(buffer)) != -1) {
                    if (bytes.size() + n > 4096) throw new SecurityException("K04");
                    bytes.write(buffer, 0, n);
                }
            }
            return new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
        } finally {
            connection.disconnect();
        }
    }

}
