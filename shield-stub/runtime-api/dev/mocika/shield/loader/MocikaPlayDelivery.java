package dev.mocika.shield.loader;

import android.content.Context;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/** Compile-only surface. The protected Stub DEX supplies the real implementation. */
public final class MocikaPlayDelivery {
    private MocikaPlayDelivery() {}

    public static InputStream openAsset(Context context, String packName, String path)
            throws IOException {
        throw compileOnly();
    }

    public static File materializeAsset(Context context, String packName, String path)
            throws IOException {
        throw compileOnly();
    }

    public static boolean isAssetPackAvailable(Context context, String packName) {
        throw compileOnly();
    }

    public static Object requestAssetPack(Context context, String packName) throws IOException {
        throw compileOnly();
    }

    public static void refresh(Context context) throws IOException {
        throw compileOnly();
    }

    private static UnsupportedOperationException compileOnly() {
        return new UnsupportedOperationException(
                "mocika-play-delivery-api.jar must be configured as compileOnly");
    }
}

