package dev.mocika.shield.loader;

import android.content.Context;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Stable business-facing adapter for protected Play Asset Delivery modules. */
public final class MocikaPlayDelivery {
    private static final String ENCRYPTED_PREFIX = "protector/aenc/";
    private static final Object LOCK = new Object();
    private static final List<Object> LISTENER_REFERENCES = new ArrayList<>();

    private MocikaPlayDelivery() {}

    /** Opens an authenticated PAS2 asset after its fast-follow/on-demand pack is available. */
    public static InputStream openAsset(Context context, String packName, String path)
            throws IOException {
        File encrypted = encryptedAsset(context, packName, path);
        return MocikaAssets.verifiedStream(new BufferedInputStream(new FileInputStream(encrypted)));
    }

    /** Materializes a verified asset in app-private storage for seekable/native consumers. */
    public static File materializeAsset(Context context, String packName, String path)
            throws IOException {
        String normalized = MocikaAssets.normalize(path);
        File root = new File(context.getDir("mocika_play_assets", Context.MODE_PRIVATE),
                checkedPackName(packName));
        if (!root.isDirectory() && !root.mkdirs()) {
            throw new IOException("cannot create Play asset cache");
        }
        File target = new File(root, digestName(packName + ":" + normalized));
        synchronized (LOCK) {
            if (target.isFile()) return target;
            File partial = File.createTempFile("pas2-", ".tmp", root);
            boolean complete = false;
            try (InputStream input = openAsset(context, packName, normalized);
                 FileOutputStream output = new FileOutputStream(partial)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) output.write(buffer, 0, read);
                }
                output.flush();
                output.getFD().sync();
                complete = partial.renameTo(target);
                if (!complete) throw new IOException("cannot publish Play asset cache");
            } finally {
                if (!complete) partial.delete();
            }
        }
        return target;
    }

    /** Returns whether Play has exposed a filesystem location for this pack. */
    public static boolean isAssetPackAvailable(Context context, String packName) {
        try {
            return resolveAssetsRoot(context, checkedPackName(packName)) != null;
        } catch (Exception unavailable) {
            return false;
        }
    }

    /** Starts an on-demand fetch and returns Play's Task without adding a hard SDK dependency. */
    public static Object requestAssetPack(Context context, String packName) throws IOException {
        try {
            Object manager = assetPackManager(context);
            Method fetch = manager.getClass().getMethod("fetch", List.class);
            return fetch.invoke(manager, Collections.singletonList(checkedPackName(packName)));
        } catch (ReflectiveOperationException error) {
            throw new IOException("Play Asset Delivery API unavailable", error);
        }
    }

    /** Call after a SplitInstall/AssetPack task completes when automatic listeners are unavailable. */
    public static void refresh(Context context) throws IOException {
        Context app = applicationContext(context);
        try {
            MocikaAssets.refreshNativeOverlay(app);
            MocikaNativeLibraries.install(app, app.getClassLoader());
        } catch (IOException error) {
            throw error;
        } catch (Exception error) {
            throw new IOException("cannot refresh protected Play delivery runtime", error);
        }
    }

    /** Installs optional Play listeners without requiring Play libraries on ordinary APKs. */
    static void install(Context context) {
        Context app = applicationContext(context);
        synchronized (LOCK) {
            if (!LISTENER_REFERENCES.isEmpty()) return;
            registerListener(app,
                    "com.google.android.play.core.splitinstall.SplitInstallManagerFactory",
                    "com.google.android.play.core.splitinstall.SplitInstallStateUpdatedListener",
                    5);
            registerListener(app,
                    "com.google.android.play.core.assetpacks.AssetPackManagerFactory",
                    "com.google.android.play.core.assetpacks.AssetPackStateUpdateListener",
                    4);
        }
    }

    private static void registerListener(
            Context context, String factoryName, String listenerName, int completedStatus) {
        try {
            Class<?> factory = Class.forName(factoryName);
            Class<?> listenerType = Class.forName(listenerName);
            Object manager = factory.getMethod("getInstance", Context.class).invoke(null, context);
            InvocationHandler handler = (proxy, method, args) -> {
                if (method.getDeclaringClass() == Object.class) {
                    if ("toString".equals(method.getName())) return "MocikaPlayDeliveryListener";
                    if ("hashCode".equals(method.getName())) return System.identityHashCode(proxy);
                    if ("equals".equals(method.getName())) return proxy == args[0];
                }
                if (args != null && args.length == 1 && "onStateUpdate".equals(method.getName())) {
                    Object status = args[0].getClass().getMethod("status").invoke(args[0]);
                    if (status instanceof Integer && ((Integer) status) == completedStatus) {
                        try { refresh(context); } catch (IOException ignored) {}
                    }
                }
                return null;
            };
            Object listener = Proxy.newProxyInstance(
                    listenerType.getClassLoader(), new Class<?>[]{listenerType}, handler);
            manager.getClass().getMethod("registerListener", listenerType)
                    .invoke(manager, listener);
            LISTENER_REFERENCES.add(manager);
            LISTENER_REFERENCES.add(listener);
        } catch (ReflectiveOperationException | LinkageError unavailable) {
            // Optional dependency: business code can call refresh after its Play task completes.
        }
    }

    private static File encryptedAsset(Context context, String packName, String path)
            throws IOException {
        String normalized = MocikaAssets.normalize(path);
        File root;
        try {
            root = resolveAssetsRoot(context, checkedPackName(packName));
        } catch (ReflectiveOperationException error) {
            throw new IOException("Play Asset Delivery API unavailable", error);
        }
        if (root == null) throw new IOException("Play asset pack is not available: " + packName);
        File canonicalRoot = root.getCanonicalFile();
        File encrypted = new File(canonicalRoot, ENCRYPTED_PREFIX + normalized).getCanonicalFile();
        String rootPrefix = canonicalRoot.getPath() + File.separator;
        if (!encrypted.getPath().startsWith(rootPrefix) || !encrypted.isFile()) {
            throw new IOException("protected Play asset is missing");
        }
        return encrypted;
    }

    private static File resolveAssetsRoot(Context context, String packName)
            throws ReflectiveOperationException {
        Object manager = assetPackManager(context);
        Object location = manager.getClass().getMethod("getPackLocation", String.class)
                .invoke(manager, packName);
        if (location == null) return null;
        Object path = location.getClass().getMethod("assetsPath").invoke(location);
        return path instanceof String && !((String) path).isEmpty()
                ? new File((String) path) : null;
    }

    private static Object assetPackManager(Context context) throws ReflectiveOperationException {
        Class<?> factory = Class.forName(
                "com.google.android.play.core.assetpacks.AssetPackManagerFactory");
        return factory.getMethod("getInstance", Context.class)
                .invoke(null, applicationContext(context));
    }

    private static Context applicationContext(Context context) {
        if (context == null) throw new IllegalArgumentException("context");
        Context app = context.getApplicationContext();
        return app == null ? context : app;
    }

    static String encryptedRelativePath(String packName, String path) {
        return checkedPackName(packName) + "/" + ENCRYPTED_PREFIX + MocikaAssets.normalize(path);
    }

    private static String checkedPackName(String packName) {
        if (packName == null || !packName.matches("[A-Za-z][A-Za-z0-9_]{0,49}")) {
            throw new IllegalArgumentException("invalid asset pack name");
        }
        return packName;
    }

    private static String digestName(String value) throws IOException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(68);
            for (byte item : digest) result.append(String.format("%02x", item & 0xff));
            return result.append(".bin").toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 unavailable", impossible);
        }
    }
}
