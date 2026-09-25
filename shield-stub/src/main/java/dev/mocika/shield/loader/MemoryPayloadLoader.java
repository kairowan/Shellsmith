package dev.mocika.shield.loader;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;

import java.nio.ByteBuffer;

import dalvik.system.InMemoryDexClassLoader;

import dev.mocika.shield.stub.BuildConfig;

/** 只负责把正式 DEXB 解密结果转换为唯一的内存业务加载器。 */
@TargetApi(29)
final class MemoryPayloadLoader {
    private MemoryPayloadLoader() {}

    static ClassLoader create(Context context, ClassLoader parent,
            MemoryRuntimeProfiler profiler) throws Exception {
        if (Build.VERSION.SDK_INT < 29) throw new IllegalStateException("M04");
        ByteBuffer[] buffers;
        long totalBytes = 0;
        if (BuildConfig.LEGACY_BYTE_ARRAY) {
            byte[][] dexes = Ld.decryptDexBytes(context, profiler);
            buffers = new ByteBuffer[dexes.length];
            for (int index = 0; index < dexes.length; index++) {
                ByteBuffer buffer = ByteBuffer.allocateDirect(dexes[index].length);
                buffer.put(dexes[index]);
                buffer.flip();
                buffers[index] = buffer;
                totalBytes += dexes[index].length;
            }
            if (profiler != null) profiler.stage("direct_copy", dexes.length, totalBytes);
        } else {
            buffers = Ld.decryptDexBuffers(context, profiler);
            for (ByteBuffer buffer : buffers) totalBytes += buffer.remaining();
        }
        MocikaAssets.activateNativeOverlay(context);
        MocikaNativeLibraries.install(context, parent);
        ClassLoader loader = new InMemoryDexClassLoader(
                buffers, MocikaNativeLibraries.searchPath(context), parent);
        if (profiler != null) profiler.stage("class_loader", buffers.length, totalBytes);
        return loader;
    }

}
