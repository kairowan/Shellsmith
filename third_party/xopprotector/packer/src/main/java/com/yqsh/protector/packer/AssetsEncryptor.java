package com.yqsh.protector.packer;

import com.yqsh.protector.packer.util.CryptoUtils;

import java.io.File;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Phase 2A — encrypt app {@code assets/**} (excluding {@code assets/protector/**}).
 * Ciphertext layout: {@code assets/protector/aenc/<relpath>} uses chunked PAS2 records.
 * Index: {@code assets/protector/assets.map} (one relative path per line).
 */
public final class AssetsEncryptor {
    public static final String AENC_DIR = "protector/aenc";
    public static final String MAP_NAME = "assets.map";
    /** Magic: Protector ASset v2 (chunked and streamable). */
    public static final byte[] MAGIC = {'P', 'A', 'S', '2'};
    public static final byte[] CHUNK_MAGIC = {'P', 'A', 'S', '1'};
    public static final int CHUNK_SIZE = 1024 * 1024;

    /**
     * Formats that require native/random-access readers stay plaintext. PAS2 is
     * stream-safe, but wrapping media changes seek and decoder buffering semantics.
     */
    private static final String[] SKIP_EXT = {
            ".so", ".dex", ".jar", ".apk", ".aab", ".ttf", ".otf",
            ".tflite", ".onnx", ".db", ".sqlite", ".sqlite3",
            ".mp3", ".m4a", ".wav", ".ogg", ".oga", ".aac", ".flac", ".opus", ".amr",
            ".3gp", ".mp4", ".mkv", ".webm", ".ts", ".mov", ".m3u8"
    };

    private AssetsEncryptor() {
    }

    public static final class Result {
        public final int encrypted;
        public final int skipped;
        public final List<String> paths;

        Result(int encrypted, int skipped, List<String> paths) {
            this.encrypted = encrypted;
            this.skipped = skipped;
            this.paths = paths;
        }
    }

    /**
     * Encrypt business assets under {@code unpack/assets}. Returns null if nothing encrypted.
     */
    public static Result encryptAll(File unpackRoot, byte[] assetsAesKey) throws Exception {
        return encryptSelected(unpackRoot, assetsAesKey, null);
    }

    /** Encrypt only assets whose exact path is statically present in the app DEX string pool. */
    public static Result encryptReferenced(
            File unpackRoot, byte[] assetsAesKey, Set<String> referencedPaths) throws Exception {
        if (referencedPaths == null) throw new IllegalArgumentException("referencedPaths required");
        return encryptSelected(unpackRoot, assetsAesKey, referencedPaths);
    }

    private static Result encryptSelected(
            File unpackRoot, byte[] assetsAesKey, Set<String> referencedPaths) throws Exception {
        if (assetsAesKey == null || assetsAesKey.length != 16) {
            throw new IllegalArgumentException("invalid assets AES key");
        }
        File assetsRoot = new File(unpackRoot, "assets");
        if (!assetsRoot.isDirectory()) {
            return new Result(0, 0, List.of());
        }

        List<Path> files;
        try (Stream<Path> walk = Files.walk(assetsRoot.toPath())) {
            files = walk.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(Path::toString))
                    .collect(Collectors.toList());
        }

        // Count work items (exclude already under protector/).
        int workTotal = 0;
        for (Path abs : files) {
            String rel = assetsRoot.toPath().relativize(abs).toString().replace('\\', '/');
            if (rel.startsWith("protector/") || rel.equals("protector")) {
                continue;
            }
            workTotal++;
        }
        ProgressMilestones prog = new ProgressMilestones("assets encrypt", workTotal);

        File aencRoot = new File(assetsRoot, AENC_DIR.replace('/', File.separatorChar));
        List<String> encryptedPaths = new ArrayList<>();
        Set<String> exactReferences = null;
        List<String> prefixReferences = List.of();
        if (referencedPaths != null) {
            exactReferences = new HashSet<>();
            List<String> prefixes = new ArrayList<>();
            for (String raw : referencedPaths) {
                String normalized = normalizeReference(raw);
                if (normalized == null) continue;
                if (normalized.endsWith("/")) prefixes.add(normalized);
                else exactReferences.add(normalized);
            }
            prefixReferences = prefixes;
        }
        int skipped = 0;

        for (Path abs : files) {
            String rel = assetsRoot.toPath().relativize(abs).toString().replace('\\', '/');
            if (rel.startsWith("protector/") || rel.equals("protector")) {
                continue;
            }
            // AGP may place baseline profiles under assets/dexopt — leave for ART.
            if (rel.startsWith("dexopt/") || rel.equals("dexopt")) {
                skipped++;
                prog.tick();
                continue;
            }
            if (shouldSkip(rel)) {
                skipped++;
                prog.tick();
                continue;
            }
            if (exactReferences != null && !isReferenced(rel, exactReferences, prefixReferences)) {
                skipped++;
                prog.tick();
                continue;
            }
            File dest = new File(aencRoot, rel.replace('/', File.separatorChar));
            File parent = dest.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new IOException("cannot mkdir " + parent);
            }
            encryptChunked(abs, dest.toPath(), assetsAesKey);
            Files.delete(abs);
            encryptedPaths.add(rel);
            prog.tick();
        }
        prog.finish();

        pruneEmptyDirs(assetsRoot);

        File protectorDir = new File(assetsRoot, "protector");
        if (!protectorDir.exists() && !protectorDir.mkdirs()) {
            throw new IOException("cannot mkdir " + protectorDir);
        }
        File mapFile = new File(protectorDir, MAP_NAME);
        StringBuilder map = new StringBuilder();
        map.append("# protector assets.map v2\n");
        for (String p : encryptedPaths) {
            map.append(p).append('\n');
        }
        Files.writeString(mapFile.toPath(), map.toString(), StandardCharsets.UTF_8);

        return new Result(encryptedPaths.size(), skipped, encryptedPaths);
    }

    /** Exact constants plus explicit directory constants cover common dynamic path construction. */
    private static boolean isReferenced(
            String rel, Set<String> exactReferences, List<String> prefixReferences) {
        if (exactReferences.contains(rel)) return true;
        for (String prefix : prefixReferences) if (rel.startsWith(prefix)) return true;
        return false;
    }

    public static List<String> matchingPaths(List<String> encryptedPaths, Set<String> references) {
        if (encryptedPaths == null || references == null || references.isEmpty()) return List.of();
        Set<String> exact = new HashSet<>();
        List<String> prefixes = new ArrayList<>();
        for (String raw : references) {
            String normalized = normalizeReference(raw);
            if (normalized == null) continue;
            if (normalized.endsWith("/")) prefixes.add(normalized);
            else exact.add(normalized);
        }
        return encryptedPaths.stream()
                .filter(path -> isReferenced(path, exact, prefixes))
                .sorted()
                .collect(Collectors.toList());
    }

    /** Authenticated PAS2 index consumed only after the runtime key is initialized. */
    public static void writeEncryptedIndex(
            File unpackRoot, String relativeOutput, byte[] key, List<String> paths)
            throws Exception {
        File output = new File(new File(unpackRoot, "assets"), relativeOutput);
        if (paths == null || paths.isEmpty()) {
            Files.deleteIfExists(output.toPath());
            return;
        }
        File parent = output.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("cannot mkdir " + parent);
        }
        Path plain = Files.createTempFile(parent.toPath(), "native-assets-", ".map");
        try {
            Files.writeString(plain, String.join("\n", paths) + "\n", StandardCharsets.UTF_8);
            encryptChunked(plain, output.toPath(), key);
        } finally {
            Files.deleteIfExists(plain);
        }
    }

    private static String normalizeReference(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        String normalized = raw.replace('\\', '/');
        while (normalized.startsWith("/")) normalized = normalized.substring(1);
        if (normalized.startsWith("assets/")) normalized = normalized.substring(7);
        if (normalized.isEmpty() || normalized.contains("..")) return null;
        return normalized;
    }

    private static void encryptChunked(Path source, Path dest, byte[] key) throws Exception {
        Path partial = dest.resolveSibling(dest.getFileName() + ".partial");
        try {
            try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(source.toFile()));
                 DataOutputStream out = new DataOutputStream(new BufferedOutputStream(
                         new FileOutputStream(partial.toFile())))) {
                out.write(MAGIC);
                out.writeInt(CHUNK_SIZE);
                out.writeLong(Files.size(source));
                byte[] buffer = new byte[CHUNK_SIZE];
                int length;
                while ((length = readChunk(in, buffer)) > 0) {
                    byte[] plain = length == buffer.length ? buffer : Arrays.copyOf(buffer, length);
                    byte[] gcm = CryptoUtils.aesGcmEncrypt(key, plain);
                    out.writeInt(CHUNK_MAGIC.length + gcm.length);
                    out.write(CHUNK_MAGIC);
                    out.write(gcm);
                }
            }
            try {
                Files.move(partial, dest, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(partial, dest, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(partial);
        }
    }

    private static int readChunk(BufferedInputStream in, byte[] buffer) throws IOException {
        int total = 0;
        while (total < buffer.length) {
            int n = in.read(buffer, total, buffer.length - total);
            if (n < 0) break;
            if (n == 0) continue;
            total += n;
        }
        return total;
    }

    private static boolean shouldSkip(String relPath) {
        String lower = relPath.toLowerCase(Locale.US);
        for (String ext : SKIP_EXT) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    private static void pruneEmptyDirs(File dir) {
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File k : kids) {
            if (k.isDirectory()) {
                pruneEmptyDirs(k);
                File[] remain = k.listFiles();
                if (remain != null && remain.length == 0) {
                    //noinspection ResultOfMethodCallIgnored
                    k.delete();
                }
            }
        }
    }
}
