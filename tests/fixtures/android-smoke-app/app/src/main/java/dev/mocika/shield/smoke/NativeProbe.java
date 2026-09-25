package dev.mocika.shield.smoke;

/** Verifies that a selected business SO is decrypted through the protected search path. */
final class NativeProbe {
    static {
        System.loadLibrary("mocikasmoke");
    }

    private NativeProbe() {}

    private static native int nativeValue(android.content.res.AssetManager assets);

    static void verify(android.content.Context context) {
        int value = nativeValue(context.getAssets());
        if (value != 73) {
            throw new IllegalStateException("Native probe failed: " + value);
        }
        android.util.Log.i("MocikaSmoke", "MOCIKA_SMOKE_NATIVE_OK");
    }
}
