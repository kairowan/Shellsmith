package dev.mocika.shield.loader;

import android.content.Context;
import java.io.IOException;
import java.io.InputStream;
import java.util.function.Consumer;

/** 仅供业务应用编译；加固后由设备批准运行时实现。 */
public final class MocikaProtectedResources {
    private MocikaProtectedResources() {}

    public static InputStream open(Context context, String id) throws IOException {
        throw new UnsupportedOperationException("需要 Shellsmith 设备批准运行时");
    }

    public static InputStream open(Context context, String id, boolean blockDebugger,
            Consumer<String> event) throws IOException {
        throw new UnsupportedOperationException("需要 Shellsmith 设备批准运行时");
    }
}
