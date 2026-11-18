package dev.mocika.shield.loader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

public final class ReaderCheck {
    public static void main(String[] args) throws Exception {
        Path root = Paths.get(args[0]);
        String id = Files.readString(root.resolve("build-id"));
        byte[] build = new byte[16];
        for (int i = 0; i < build.length; i++) {
            build[i] = (byte) Integer.parseInt(id.substring(i * 2, i * 2 + 2), 16);
        }
        byte[] key = Files.readAllBytes(root.resolve("fixture-key"));
        byte[] expected = Files.readAllBytes(root.resolve("rules.json"));
        Path sealed = root.resolve("sealed/rules.ssr");
        try (ProtectedResourceStream reader = ProtectedResourceStream.open(
                Files.newInputStream(sealed), build, "policy", "rules", 3, key, () -> true)) {
            assert Arrays.equals(expected, reader.readAllBytes());
        }
        try (ProtectedResourceStream reader = ProtectedResourceStream.open(
                Files.newInputStream(sealed), build, "policy", "rules", 3, key, () -> true)) {
            ArrayList<String> events = new ArrayList<>();
            reader.observeResult(events::add);
            assert Arrays.equals(Arrays.copyOfRange(expected, 65_530, 65_547), reader.readRange(65_530, 17));
            assert events.equals(Collections.singletonList("verified"));
        }
        for (boolean bulk : new boolean[]{false, true}) {
            ArrayList<String> events = new ArrayList<>();
            try (ProtectedResourceStream reader = ProtectedResourceStream.open(
                    Files.newInputStream(sealed), build, "policy", "rules", 3, key, () -> true)) {
                reader.observeResult(events::add);
                assert Arrays.equals(Arrays.copyOf(expected, expected.length - 1),
                        reader.readNBytes(expected.length - 1));
                assert events.isEmpty();
                if (bulk) {
                    byte[] last = new byte[1];
                    assert reader.read(last) == 1 && last[0] == expected[expected.length - 1];
                } else {
                    assert reader.read() == (expected[expected.length - 1] & 255);
                }
            }
            assert events.equals(Collections.singletonList("verified")) : events;
        }
        for (String malformed : new String[]{"truncated", "extended", "tampered"}) {
            try (ProtectedResourceStream reader = ProtectedResourceStream.open(
                    Files.newInputStream(root.resolve(malformed)), build, "policy", "rules", 3, key, () -> true)) {
                assert reader.readNBytes(65_536).length == 65_536;
                reader.read();
                throw new AssertionError("无效末片仍可读取");
            } catch (IOException expectedFailure) {
                assert "业务资源读取失败".equals(expectedFailure.getMessage());
            }
            try (ProtectedResourceStream reader = ProtectedResourceStream.open(
                    Files.newInputStream(root.resolve(malformed)), build, "policy", "rules", 3, key, () -> true)) {
                reader.readRange(0, 1);
                throw new AssertionError("选择部分字节仍应认证末片");
            } catch (IOException expectedFailure) {
                assert "业务资源读取失败".equals(expectedFailure.getMessage());
            }
        }
        AtomicBoolean active = new AtomicBoolean(true);
        try (ProtectedResourceStream reader = ProtectedResourceStream.open(
                Files.newInputStream(sealed), build, "policy", "rules", 3, key, active::get)) {
            assert reader.read() == 0x42;
            active.set(false);
            try {
                reader.read();
                throw new AssertionError("授权失效后仍可继续读取");
            } catch (IOException expectedFailure) {
                assert "业务资源读取失败".equals(expectedFailure.getMessage());
            }
        }
    }
}
