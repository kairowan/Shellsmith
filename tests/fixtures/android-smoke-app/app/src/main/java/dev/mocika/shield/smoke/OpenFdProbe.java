package dev.mocika.shield.smoke;

import android.content.Context;
import android.content.res.AssetFileDescriptor;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

/** Covers dynamic asset paths and AssetManager.openFd after PAS2 encryption. */
final class OpenFdProbe {
    private OpenFdProbe() {}

    static void verify(Context context) {
        String path = "voice/" + "sample.ogg";
        try (AssetFileDescriptor descriptor = context.getAssets().openFd(path);
             FileInputStream input = descriptor.createInputStream()) {
            byte[] content = new byte[32];
            int length = input.read(content);
            String value = new String(content, 0, length, StandardCharsets.UTF_8);
            if (!"open-fd-pas2-ok\n".equals(value)) {
                throw new IllegalStateException("openFd probe mismatch");
            }
            android.util.Log.i("MocikaSmoke", "MOCIKA_SMOKE_OPEN_FD_OK");
        } catch (Exception error) {
            throw new IllegalStateException("openFd probe failed", error);
        }
    }
}
