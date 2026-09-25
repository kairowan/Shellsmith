package dev.mocika.shield.loader;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.os.ParcelFileDescriptor;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Transparent stream/openFd reader for PAS2 assets emitted by the packer. */
public final class MocikaAssets {
    private static final String PREFIX = "protector/aenc/";
    private static final String NATIVE_INDEX = "protector/native-assets.pas2";
    private static final String DEFERRED_INDEX = "protector/deferred-assets.sha256";
    private static final byte[] PAS2 = {'P', 'A', 'S', '2'};
    private static final int MAX_CHUNK = 4 * 1024 * 1024;
    private static final Object MATERIALIZE_LOCK = new Object();
    private static volatile File materializedRoot;
    private static volatile boolean nativeOverlayInstalled;
    private static volatile File nativeOverlayFile;
    private static final WeakHashMap<AssetManager, Boolean> OVERLAY_MANAGERS = new WeakHashMap<>();

    private MocikaAssets() {}

    static void install(Context context) throws IOException {
        long update = new File(context.getApplicationInfo().sourceDir).lastModified();
        File root = new File(context.getDir("mocika_assets", Context.MODE_PRIVATE),
                "ma-" + Long.toHexString(update));
        if (!root.isDirectory() && !root.mkdirs()) {
            throw new IOException("cannot create PAS2 cache");
        }
        materializedRoot = root;
    }

    /** Adds an authenticated plaintext asset overlay for Native AAssetManager consumers. */
    static void activateNativeOverlay(Context context) throws IOException {
        if (nativeOverlayInstalled) return;
        BufferedInputStream encryptedIndex;
        try {
            encryptedIndex = new BufferedInputStream(context.getAssets().open(NATIVE_INDEX));
        } catch (FileNotFoundException absent) {
            return;
        }
        List<String> paths = readNativeIndex(encryptedIndex);
        if (paths.isEmpty()) throw new IOException("PAS2 native index is empty");
        File root = materializedRoot;
        if (root == null) throw new IOException("PAS2 cache is not initialized");
        File overlay = new File(root, "native-assets.zip");
        synchronized (MATERIALIZE_LOCK) {
            if (overlay.isFile() && !overlay.delete()) {
                throw new IOException("cannot refresh PAS2 Native overlay");
            }
            OverlayBuildResult result = buildNativeOverlay(
                    context.getAssets(), root, overlay, paths,
                    readDeferredHashes(context.getAssets()));
            if (result.available == 0) {
                nativeOverlayInstalled = result.missing == 0;
                return;
            }
            nativeOverlayFile = overlay;
            ensureNativeOverlay(context.getAssets());
            try (InputStream probe = context.getAssets().open(result.firstPath)) {
                if (probe.read() < 0) throw new IOException("PAS2 Native overlay is empty");
            }
            nativeOverlayInstalled = result.missing == 0;
        }
    }

    /** Rebuilds overlays after Play installs a deferred dynamic feature. */
    static void refreshNativeOverlay(Context context) throws IOException {
        synchronized (MATERIALIZE_LOCK) {
            nativeOverlayInstalled = false;
            nativeOverlayFile = null;
        }
        activateNativeOverlay(context);
    }

    public static InputStream open(AssetManager assets, String path) throws IOException {
        return open(assets, path, AssetManager.ACCESS_STREAMING);
    }

    /** Rewritten Context.getAssets bridge: patches each newly-created AssetManager instance. */
    public static AssetManager assets(Context context) throws IOException {
        AssetManager manager = context.getAssets();
        ensureNativeOverlay(manager);
        return manager;
    }

    /** Rewritten Resources.getAssets bridge. */
    public static AssetManager assets(Resources resources) throws IOException {
        AssetManager manager = resources.getAssets();
        ensureNativeOverlay(manager);
        return manager;
    }

    private static void ensureNativeOverlay(AssetManager assets) throws IOException {
        File overlay = nativeOverlayFile;
        if (overlay == null) return;
        synchronized (OVERLAY_MANAGERS) {
            if (OVERLAY_MANAGERS.containsKey(assets)) return;
            addAssetPath(assets, overlay);
            OVERLAY_MANAGERS.put(assets, Boolean.TRUE);
        }
    }

    public static InputStream open(AssetManager assets, String path, int accessMode)
            throws IOException {
        String normalized = normalize(path);
        BufferedInputStream encrypted = openEncrypted(assets, normalized);
        return encrypted == null ? assets.open(path, accessMode) : verifiedStream(encrypted);
    }

    /** Materializes authenticated plaintext in the private code cache for seekable consumers. */
    public static AssetFileDescriptor openFd(AssetManager assets, String path) throws IOException {
        String normalized = normalize(path);
        BufferedInputStream encrypted = openEncrypted(assets, normalized);
        if (encrypted == null) return assets.openFd(path);

        File root = materializedRoot;
        if (root == null) {
            encrypted.close();
            throw new IOException("PAS2 cache is not initialized");
        }
        File target = new File(root, digestName(normalized));
        synchronized (MATERIALIZE_LOCK) {
            if (target.isFile()) encrypted.close();
            else materialize(encrypted, target);
        }
        ParcelFileDescriptor descriptor = ParcelFileDescriptor.open(
                target, ParcelFileDescriptor.MODE_READ_ONLY);
        return new AssetFileDescriptor(descriptor, 0, target.length());
    }

    private static BufferedInputStream openEncrypted(AssetManager assets, String normalized)
            throws IOException {
        try {
            return new BufferedInputStream(
                    assets.open(PREFIX + normalized, AssetManager.ACCESS_STREAMING));
        } catch (FileNotFoundException missing) {
            return null;
        }
    }

    static InputStream verifiedStream(BufferedInputStream encrypted) throws IOException {
        try {
            byte[] magic = new byte[4];
            readFully(encrypted, magic);
            if (!java.util.Arrays.equals(magic, PAS2)) {
                throw new IOException("invalid PAS2 asset");
            }
            return new Pas2InputStream(encrypted);
        } catch (IOException | RuntimeException error) {
            try { encrypted.close(); } catch (IOException ignored) {}
            throw error;
        }
    }

    private static void materialize(BufferedInputStream encrypted, File target) throws IOException {
        File partial = File.createTempFile("pas2-", ".tmp", target.getParentFile());
        boolean complete = false;
        try (InputStream input = verifiedStream(encrypted);
             FileOutputStream output = new FileOutputStream(partial)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) output.write(buffer, 0, read);
            }
            output.getFD().sync();
            complete = partial.renameTo(target);
            if (!complete) throw new IOException("cannot publish PAS2 cache");
        } finally {
            if (!complete) partial.delete();
        }
    }

    private static List<String> readNativeIndex(BufferedInputStream encrypted) throws IOException {
        List<String> paths = new ArrayList<>();
        Set<String> unique = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                verifiedStream(encrypted), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (paths.size() >= 4096 || line.length() > 512) {
                    throw new IOException("PAS2 native index exceeds limits");
                }
                String normalized = normalize(line);
                if (!normalized.equals(line) || !unique.add(normalized)) {
                    throw new IOException("PAS2 native index contains invalid path");
                }
                paths.add(normalized);
            }
        }
        return paths;
    }

    private static OverlayBuildResult buildNativeOverlay(
            AssetManager assets, File root, File target, List<String> paths,
            Set<String> deferredHashes) throws IOException {
        File partial = File.createTempFile("native-assets-", ".zip", root);
        boolean complete = false;
        long total = 0;
        int available = 0;
        int missing = 0;
        String firstPath = null;
        try (FileOutputStream fileOutput = new FileOutputStream(partial);
             ZipOutputStream zip = new ZipOutputStream(fileOutput)) {
            for (String path : paths) {
                BufferedInputStream encrypted = openEncrypted(assets, path);
                if (encrypted == null) {
                    if (!deferredHashes.contains(sha256(path))) {
                        throw new IOException("PAS2 native asset is missing");
                    }
                    missing++;
                    continue;
                }
                File plain = File.createTempFile("native-asset-", ".bin", root);
                if (!plain.delete()) throw new IOException("cannot prepare PAS2 native temp file");
                try {
                    materialize(encrypted, plain);
                    total += plain.length();
                    if (plain.length() > 512L * 1024 * 1024
                            || total > 1024L * 1024 * 1024) {
                        throw new IOException("PAS2 native overlay exceeds limits");
                    }
                    CRC32 crc = new CRC32();
                    try (InputStream input = new FileInputStream(plain)) {
                        byte[] buffer = new byte[64 * 1024];
                        int read;
                        while ((read = input.read(buffer)) >= 0) {
                            if (read > 0) crc.update(buffer, 0, read);
                        }
                    }
                    ZipEntry entry = new ZipEntry("assets/" + path);
                    entry.setMethod(ZipEntry.STORED);
                    entry.setSize(plain.length());
                    entry.setCompressedSize(plain.length());
                    entry.setCrc(crc.getValue());
                    zip.putNextEntry(entry);
                    try (InputStream input = new FileInputStream(plain)) {
                        byte[] buffer = new byte[64 * 1024];
                        int read;
                        while ((read = input.read(buffer)) >= 0) {
                            if (read > 0) zip.write(buffer, 0, read);
                        }
                    }
                    zip.closeEntry();
                    if (firstPath == null) firstPath = path;
                    available++;
                } finally {
                    if (plain.exists()) plain.delete();
                }
            }
            zip.finish();
            zip.flush();
            fileOutput.getFD().sync();
        }
        try {
            if (available > 0 && !partial.renameTo(target)) {
                throw new IOException("cannot publish PAS2 overlay");
            }
            complete = true;
        } finally {
            if (!complete) partial.delete();
        }
        if (available == 0) partial.delete();
        return new OverlayBuildResult(available, missing, firstPath);
    }

    private static Set<String> readDeferredHashes(AssetManager assets) throws IOException {
        Set<String> hashes = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                assets.open(DEFERRED_INDEX), StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.matches("[0-9a-f]{64}") || !hashes.add(line)) {
                    throw new IOException("invalid deferred PAS2 index");
                }
            }
        } catch (FileNotFoundException absent) {
            return hashes;
        }
        return hashes;
    }

    private static void addAssetPath(AssetManager assets, File overlay) throws IOException {
        try {
            Method method = AssetManager.class.getDeclaredMethod("addAssetPath", String.class);
            method.setAccessible(true);
            Object cookie = method.invoke(assets, overlay.getAbsolutePath());
            if (!(cookie instanceof Integer) || ((Integer) cookie) == 0) {
                throw new IOException("cannot add PAS2 Native asset overlay");
            }
        } catch (IOException error) {
            throw error;
        } catch (ReflectiveOperationException error) {
            throw new IOException("cannot activate PAS2 Native asset overlay", error);
        }
    }

    private static String digestName(String path) throws IOException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(path.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(68);
            for (byte value : digest) result.append(String.format("%02x", value & 0xff));
            return result.append(".bin").toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 unavailable", impossible);
        }
    }

    private static String sha256(String path) throws IOException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(path.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest) result.append(String.format("%02x", value & 0xff));
            return result.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 unavailable", impossible);
        }
    }

    static String normalize(String path) {
        if (path == null || path.isEmpty()) throw new IllegalArgumentException("empty asset path");
        String normalized = path.replace('\\', '/');
        while (normalized.startsWith("/")) normalized = normalized.substring(1);
        if (normalized.startsWith("assets/")) normalized = normalized.substring(7);
        if (normalized.contains("..") || normalized.startsWith(PREFIX)) {
            throw new IllegalArgumentException("invalid asset path");
        }
        return normalized;
    }

    private static final class OverlayBuildResult {
        final int available;
        final int missing;
        final String firstPath;

        OverlayBuildResult(int available, int missing, String firstPath) {
            this.available = available;
            this.missing = missing;
            this.firstPath = firstPath;
        }
    }

    private static void readFully(InputStream input, byte[] bytes) throws IOException {
        int offset = 0;
        while (offset < bytes.length) {
            int read = input.read(bytes, offset, bytes.length - offset);
            if (read < 0) throw new IOException("truncated PAS2 asset");
            offset += read;
        }
    }

    private static final class Pas2InputStream extends InputStream {
        private final DataInputStream input;
        private final int chunkSize;
        private long remaining;
        private byte[] current = new byte[0];
        private int offset;

        Pas2InputStream(InputStream input) throws IOException {
            this.input = new DataInputStream(input);
            chunkSize = this.input.readInt();
            remaining = this.input.readLong();
            if (chunkSize <= 0 || chunkSize > MAX_CHUNK || remaining < 0) {
                throw new IOException("invalid PAS2 header");
            }
        }

        @Override public int read() throws IOException {
            return ensureChunk() ? current[offset++] & 0xff : -1;
        }

        @Override public int read(byte[] bytes, int start, int length) throws IOException {
            if (bytes == null) throw new NullPointerException("bytes");
            if (start < 0 || length < 0 || length > bytes.length - start) {
                throw new IndexOutOfBoundsException();
            }
            if (length == 0) return 0;
            if (!ensureChunk()) return -1;
            int count = Math.min(length, current.length - offset);
            System.arraycopy(current, offset, bytes, start, count);
            offset += count;
            return count;
        }

        private boolean ensureChunk() throws IOException {
            if (offset < current.length) return true;
            if (remaining == 0) return false;
            int encryptedLength = input.readInt();
            if (encryptedLength < 32 || encryptedLength > chunkSize + 32) {
                throw new IOException("invalid PAS2 chunk length");
            }
            byte[] encrypted = new byte[encryptedLength];
            input.readFully(encrypted);
            byte[] plain = Ld.u(encrypted);
            int expected = (int) Math.min((long) chunkSize, remaining);
            if (plain == null || plain.length != expected) {
                throw new IOException("invalid PAS2 plaintext length");
            }
            current = plain;
            offset = 0;
            remaining -= plain.length;
            return true;
        }

        @Override public void close() throws IOException {
            remaining = 0;
            current = new byte[0];
            input.close();
        }
    }
}
