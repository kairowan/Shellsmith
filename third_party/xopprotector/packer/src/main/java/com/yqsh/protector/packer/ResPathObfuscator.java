package com.yqsh.protector.packer;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Phase 2B — AndResGuard-style {@code res/} path shortening + in-place
 * {@code resources.arsc} string-pool rewrite. Does <em>not</em> encrypt arsc
 * (must stay STORED for mmap).
 */
public final class ResPathObfuscator {
    private static final int RES_TABLE_TYPE = 0x0002;
    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int UTF8_FLAG = 1 << 8;

    /** Keep file paths matching these globs (Ant-style {@code *} / {@code **}). */
    private static final String[] DEFAULT_WHITELIST = {
            // Launcher / adaptive icon XML sometimes loaded by path heuristics on OEM skins
            // — keep mipmap paths by default for safety; still shortens drawable/layout/xml.
            "res/mipmap*/**",
    };

    private ResPathObfuscator() {
    }

    public static final class Result {
        public final int pathCount;
        public final int rewrittenInArsc;
        public final int filesMoved;
        public final Map<String, String> mapping;

        Result(int pathCount, int rewrittenInArsc, int filesMoved, Map<String, String> mapping) {
            this.pathCount = pathCount;
            this.rewrittenInArsc = rewrittenInArsc;
            this.filesMoved = filesMoved;
            this.mapping = mapping;
        }
    }

    /**
     * Obfuscate res paths under an unpacked APK directory.
     *
     * @return mapping old→new (empty if nothing to do)
     */
    public static Result obfuscate(File unpackDir) throws IOException {
        return obfuscate(unpackDir, DEFAULT_WHITELIST);
    }

    public static Result obfuscate(File unpackDir, String[] whitelistGlobs) throws IOException {
        File arsc = new File(unpackDir, "resources.arsc");
        if (!arsc.isFile()) {
            System.out.println("res-protect: resources.arsc missing — skip");
            return new Result(0, 0, 0, Collections.emptyMap());
        }

        byte[] data = Files.readAllBytes(arsc.toPath());
        StringPool pool = StringPool.findGlobal(data);
        if (pool == null) {
            throw new IOException("res-protect: global string pool not found in resources.arsc");
        }

        List<Pattern> white = compileWhitelist(whitelistGlobs);
        Map<String, Integer> pathToIndex = new LinkedHashMap<>();
        Map<String, File> pathToFile = new HashMap<>();
        Map<String, String> csIdByEntry = loadCsStoreReverse(unpackDir); // entry -> id
        for (int i = 0; i < pool.stringCount; i++) {
            String s = pool.readString(i);
            if (s == null || !isResFilePath(s)) {
                continue;
            }
            if (isWhitelisted(s, white)) {
                continue;
            }
            File f = resolveResFile(unpackDir, s, csIdByEntry);
            if (f == null || !f.isFile()) {
                continue;
            }
            pathToIndex.putIfAbsent(s, i);
            pathToFile.putIfAbsent(s, f);
        }

        if (pathToIndex.isEmpty()) {
            System.out.println("res-protect: no file-backed res/ paths to obfuscate");
            return new Result(0, 0, 0, Collections.emptyMap());
        }

        Map<String, String> typeDirMap = new HashMap<>();
        ShortNameGen typeGen = new ShortNameGen();
        Map<String, ShortNameGen> fileGens = new HashMap<>();
        Map<String, String> mapping = new LinkedHashMap<>();

        for (String oldPath : pathToIndex.keySet()) {
            String newPath = allocatePath(oldPath, typeDirMap, typeGen, fileGens);
            // Must fit in-place in the string pool slot.
            if (!pool.canReplace(pathToIndex.get(oldPath), newPath)) {
                System.out.println("res-protect: skip (won't fit in pool slot): " + oldPath
                        + " -> " + newPath);
                continue;
            }
            mapping.put(oldPath, newPath);
        }

        // Move files first — only rewrite arsc after every mapped file is in place.
        int moved = moveFiles(unpackDir, mapping, pathToFile, csIdByEntry);
        if (moved != mapping.size()) {
            throw new IOException("res-protect: moved " + moved + "/" + mapping.size()
                    + " files; aborting arsc rewrite to avoid path mismatch");
        }

        ProgressMilestones arscProg = new ProgressMilestones("res-protect arsc", mapping.size());
        int rewritten = 0;
        for (Map.Entry<String, String> e : mapping.entrySet()) {
            int idx = pathToIndex.get(e.getKey());
            pool.replaceString(idx, e.getValue());
            rewritten++;
            arscProg.tick();
        }
        arscProg.finish();
        Files.write(arsc.toPath(), data);

        System.out.println("res-protect: paths=" + mapping.size()
                + " arsc_rewritten=" + rewritten
                + " files_moved=" + moved);
        return new Result(mapping.size(), rewritten, moved, mapping);
    }

    /** Apply path mapping to a STORED-entry set (old names → new names). */
    public static void remapStoreEntries(Set<String> storeEntries, Map<String, String> mapping) {
        if (storeEntries == null || mapping == null || mapping.isEmpty()) {
            return;
        }
        Set<String> next = new HashSet<>();
        for (String e : storeEntries) {
            next.add(mapping.getOrDefault(e, e));
        }
        storeEntries.clear();
        storeEntries.addAll(next);
    }

    private static String allocatePath(String oldPath,
                                       Map<String, String> typeDirMap,
                                       ShortNameGen typeGen,
                                       Map<String, ShortNameGen> fileGens) {
        // res/<typeDir>/<file>  OR  res/<file> (flat AGP)
        String rel = oldPath.startsWith("res/") ? oldPath.substring(4) : oldPath;
        int slash = rel.lastIndexOf('/');
        String typeDir;
        String fileName;
        if (slash < 0) {
            typeDir = "_";
            fileName = rel;
        } else {
            typeDir = rel.substring(0, slash);
            fileName = rel.substring(slash + 1);
        }
        String shortType = typeDirMap.computeIfAbsent(typeDir, t -> typeGen.next());
        ShortNameGen fileGen = fileGens.computeIfAbsent(typeDir, t -> new ShortNameGen());
        String ext = extensionOf(fileName);
        String shortFile = fileGen.next() + ext;
        return "r/" + shortType + "/" + shortFile;
    }

    private static String extensionOf(String fileName) {
        int dot = fileName.lastIndexOf('.');
        if (dot <= 0 || dot == fileName.length() - 1) {
            return "";
        }
        // keep .9.png
        if (fileName.endsWith(".9.png")) {
            return ".9.png";
        }
        return fileName.substring(dot).toLowerCase(Locale.ROOT);
    }

    private static boolean isResFilePath(String s) {
        if (s.length() < 5 || !s.startsWith("res/")) {
            return false;
        }
        if (s.contains("..") || s.endsWith("/")) {
            return false;
        }
        // values* are compiled into arsc — no file; skip pure type names
        String lower = s.toLowerCase(Locale.ROOT);
        if (lower.contains("/values") && !lower.contains(".")) {
            return false;
        }
        return s.indexOf('.') > 0; // require an extension
    }

    private static boolean isWhitelisted(String path, List<Pattern> white) {
        for (Pattern p : white) {
            if (p.matcher(path).matches()) {
                return true;
            }
        }
        return false;
    }

    private static List<Pattern> compileWhitelist(String[] globs) {
        List<Pattern> out = new ArrayList<>();
        if (globs == null) {
            return out;
        }
        for (String g : globs) {
            if (g == null || g.isEmpty()) continue;
            out.add(globToPattern(g));
        }
        return out;
    }

    /** Minimal Ant-style {@code *} / {@code **} → regex. */
    static Pattern globToPattern(String glob) {
        StringBuilder sb = new StringBuilder("^");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            if (c == '*' && i + 1 < glob.length() && glob.charAt(i + 1) == '*') {
                sb.append(".*");
                i++;
            } else if (c == '*') {
                sb.append("[^/]*");
            } else if ("\\.[]{}()+-^$|".indexOf(c) >= 0) {
                sb.append('\\').append(c);
            } else {
                sb.append(c);
            }
        }
        sb.append('$');
        return Pattern.compile(sb.toString());
    }

    /** entryName → csstore id */
    private static Map<String, String> loadCsStoreReverse(File unpackDir) throws IOException {
        Map<String, String> out = new HashMap<>();
        File mapFile = new File(unpackDir, ".csstore/map.txt");
        if (!mapFile.isFile()) {
            return out;
        }
        for (String line : Files.readAllLines(mapFile.toPath(), StandardCharsets.UTF_8)) {
            int tab = line.indexOf('\t');
            if (tab > 0) {
                String id = line.substring(0, tab);
                String entry = line.substring(tab + 1);
                out.put(entry, id);
            }
        }
        return out;
    }

    private static File resolveResFile(File unpackDir, String entry,
                                       Map<String, String> csIdByEntry) {
        // Prefer .csstore when this exact ZIP entry was stored there — on
        // case-insensitive FS, File("res/HQ.xml") may alias res/hq.xml.
        String id = csIdByEntry.get(entry);
        if (id != null) {
            File cs = new File(unpackDir, ".csstore/" + id);
            if (cs.isFile()) {
                return cs;
            }
        }
        File direct = new File(unpackDir, entry.replace('/', File.separatorChar));
        if (direct.isFile()) {
            return direct;
        }
        return null;
    }

    private static int moveFiles(File unpackDir,
                                 Map<String, String> mapping,
                                 Map<String, File> pathToFile,
                                 Map<String, String> csIdByEntry) throws IOException {
        List<Map.Entry<String, String>> entries = new ArrayList<>(mapping.entrySet());
        entries.sort(Comparator.comparingInt((Map.Entry<String, String> e) -> e.getKey().length())
                .reversed());
        Set<String> removedCsEntries = new HashSet<>();
        Map<String, File> movedCanonical = new HashMap<>(); // canonical src -> dest
        ProgressMilestones moveProg = new ProgressMilestones("res-protect move", entries.size());
        int moved = 0;
        for (Map.Entry<String, String> e : entries) {
            File src = pathToFile.get(e.getKey());
            if (src == null || !src.isFile()) {
                src = resolveResFile(unpackDir, e.getKey(), csIdByEntry);
            }
            File dst = new File(unpackDir, e.getValue().replace('/', File.separatorChar));
            File parent = dst.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new IOException("cannot mkdir " + parent);
            }

            if (src != null && src.isFile()) {
                String canon = src.getCanonicalPath();
                File already = movedCanonical.get(canon);
                if (already != null) {
                    // Same physical file aliased under two ZIP names — copy.
                    Files.copy(already.toPath(), dst.toPath(), StandardCopyOption.REPLACE_EXISTING);
                } else {
                    Files.move(src.toPath(), dst.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    movedCanonical.put(canon, dst);
                    pruneEmptyParents(src.getParentFile(), new File(unpackDir, "res"));
                    pruneEmptyParents(src.getParentFile(), new File(unpackDir, ".csstore"));
                }
                moved++;
            } else {
                System.out.println("res-protect: missing file for " + e.getKey());
                moveProg.tick();
                continue;
            }
            if (csIdByEntry.containsKey(e.getKey())) {
                removedCsEntries.add(e.getKey());
            }
            moveProg.tick();
        }
        moveProg.finish();
        if (!removedCsEntries.isEmpty()) {
            rewriteCsStoreMap(unpackDir, removedCsEntries);
        }
        // Drop orphan .csstore blobs whose map lines were removed or never matched.
        cleanupOrphanCsStore(unpackDir);
        return moved;
    }

    private static void cleanupOrphanCsStore(File unpackDir) throws IOException {
        File csDir = new File(unpackDir, ".csstore");
        if (!csDir.isDirectory()) {
            return;
        }
        Map<String, String> idToEntry = new HashMap<>();
        File mapFile = new File(csDir, "map.txt");
        if (mapFile.isFile()) {
            for (String line : Files.readAllLines(mapFile.toPath(), StandardCharsets.UTF_8)) {
                int tab = line.indexOf('\t');
                if (tab > 0) {
                    idToEntry.put(line.substring(0, tab), line.substring(tab + 1));
                }
            }
        }
        File[] kids = csDir.listFiles();
        if (kids == null) {
            return;
        }
        for (File f : kids) {
            if (!f.isFile() || "map.txt".equals(f.getName())) {
                continue;
            }
            if (!idToEntry.containsKey(f.getName())) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            }
        }
        if (idToEntry.isEmpty() && mapFile.isFile()) {
            //noinspection ResultOfMethodCallIgnored
            mapFile.delete();
        }
        String[] left = csDir.list();
        if (left != null && left.length == 0) {
            //noinspection ResultOfMethodCallIgnored
            csDir.delete();
        }
    }

    private static void rewriteCsStoreMap(File unpackDir, Set<String> removedEntries)
            throws IOException {
        File mapFile = new File(unpackDir, ".csstore/map.txt");
        if (!mapFile.isFile()) {
            return;
        }
        List<String> keep = new ArrayList<>();
        for (String line : Files.readAllLines(mapFile.toPath(), StandardCharsets.UTF_8)) {
            int tab = line.indexOf('\t');
            if (tab > 0) {
                String entry = line.substring(tab + 1);
                if (removedEntries.contains(entry)) {
                    continue;
                }
            }
            keep.add(line);
        }
        if (keep.isEmpty()) {
            //noinspection ResultOfMethodCallIgnored
            mapFile.delete();
        } else {
            Files.write(mapFile.toPath(), keep, StandardCharsets.UTF_8);
        }
    }

    private static void pruneEmptyParents(File dir, File stopAt) {
        File cur = dir;
        while (cur != null) {
            if (cur.equals(stopAt) || !cur.getPath().startsWith(stopAt.getPath())) {
                break;
            }
            String[] kids = cur.list();
            if (kids != null && kids.length == 0) {
                //noinspection ResultOfMethodCallIgnored
                cur.delete();
                cur = cur.getParentFile();
            } else {
                break;
            }
        }
    }

    // ── short names ───────────────────────────────────────────────

    static final class ShortNameGen {
        private static final char[] CHARS =
                "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        private int i;

        String next() {
            int n = i++;
            StringBuilder sb = new StringBuilder();
            do {
                sb.append(CHARS[n % CHARS.length]);
                n /= CHARS.length;
            } while (n-- > 0);
            return sb.reverse().toString();
        }
    }

    // ── resources.arsc string pool ────────────────────────────────

    static final class StringPool {
        final byte[] data;
        final int chunkOffset;
        final int stringCount;
        final int styleCount;
        final boolean utf8;
        final int stringsStart; // absolute offset of string data
        final int stylesStart;  // absolute; == stringsStart when styleCount==0
        final int[] offsets;    // absolute offsets into data
        final int stringDataEnd; // exclusive end of string bytes (stylesStart or chunk end)

        StringPool(byte[] data, int chunkOffset, int stringCount, int styleCount, boolean utf8,
                   int stringsStart, int stylesStart, int[] offsets, int stringDataEnd) {
            this.data = data;
            this.chunkOffset = chunkOffset;
            this.stringCount = stringCount;
            this.styleCount = styleCount;
            this.utf8 = utf8;
            this.stringsStart = stringsStart;
            this.stylesStart = stylesStart;
            this.offsets = offsets;
            this.stringDataEnd = stringDataEnd;
        }

        static StringPool findGlobal(byte[] data) {
            if (data.length < 12) {
                return null;
            }
            ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            int type = bb.getShort(0) & 0xffff;
            int headerSize = bb.getShort(2) & 0xffff;
            int tableSize = bb.getInt(4);
            if (type != RES_TABLE_TYPE || headerSize < 12 || tableSize > data.length) {
                return null;
            }
            int pos = headerSize;
            while (pos + 8 <= data.length) {
                int ctype = bb.getShort(pos) & 0xffff;
                int cheader = bb.getShort(pos + 2) & 0xffff;
                int csize = bb.getInt(pos + 4);
                if (csize < 8 || pos + csize > data.length) {
                    break;
                }
                if (ctype == RES_STRING_POOL_TYPE && cheader >= 28) {
                    return parse(data, pos);
                }
                pos += csize;
            }
            return null;
        }

        static StringPool parse(byte[] data, int chunkOffset) {
            ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            int headerSize = bb.getShort(chunkOffset + 2) & 0xffff;
            int csize = bb.getInt(chunkOffset + 4);
            int stringCount = bb.getInt(chunkOffset + 8);
            int styleCount = bb.getInt(chunkOffset + 12);
            int flags = bb.getInt(chunkOffset + 16);
            int stringsStartRel = bb.getInt(chunkOffset + 20);
            int stylesStartRel = bb.getInt(chunkOffset + 24);
            boolean utf8 = (flags & UTF8_FLAG) != 0;
            int stringsStart = chunkOffset + stringsStartRel;
            int chunkEnd = chunkOffset + csize;
            int stylesStart = (styleCount > 0 && stylesStartRel > 0)
                    ? chunkOffset + stylesStartRel
                    : chunkEnd;
            if (stylesStart < stringsStart || stylesStart > chunkEnd) {
                stylesStart = chunkEnd;
            }
            int[] offsets = new int[stringCount];
            for (int i = 0; i < stringCount; i++) {
                int off = bb.getInt(chunkOffset + headerSize + i * 4);
                offsets[i] = stringsStart + off;
            }
            return new StringPool(data, chunkOffset, stringCount, styleCount, utf8,
                    stringsStart, stylesStart, offsets, stylesStart);
        }

        String readString(int index) {
            if (index < 0 || index >= stringCount) {
                return null;
            }
            int pos = offsets[index];
            if (utf8) {
                DecodedLen chars = decodeLengthUtf8(data, pos);
                pos = chars.next;
                DecodedLen bytes = decodeLengthUtf8(data, pos);
                pos = bytes.next;
                if (pos + bytes.value > data.length) {
                    return null;
                }
                return new String(data, pos, bytes.value, StandardCharsets.UTF_8);
            } else {
                DecodedLen chars = decodeLengthUtf16(data, pos);
                pos = chars.next;
                int byteLen = chars.value * 2;
                if (pos + byteLen > data.length) {
                    return null;
                }
                return new String(data, pos, byteLen, StandardCharsets.UTF_16LE);
            }
        }

        /**
         * Exclusive end of this string's writable slot: next strictly greater
         * string offset, else start of style data / chunk end.
         */
        int slotEnd(int index) {
            int start = offsets[index];
            int end = stringDataEnd;
            for (int i = 0; i < stringCount; i++) {
                int off = offsets[i];
                if (off > start && off < end) {
                    end = off;
                }
            }
            return end;
        }

        boolean canReplace(int index, String neu) {
            int start = offsets[index];
            int end = slotEnd(index);
            int capacity = end - start;
            if (capacity <= 0) {
                return false;
            }
            byte[] encoded = encode(neu);
            return encoded.length <= capacity;
        }

        void replaceString(int index, String neu) {
            int start = offsets[index];
            int end = slotEnd(index);
            byte[] encoded = encode(neu);
            if (encoded.length > end - start) {
                throw new IllegalArgumentException("string does not fit slot " + index);
            }
            System.arraycopy(encoded, 0, data, start, encoded.length);
            for (int i = start + encoded.length; i < end; i++) {
                data[i] = 0;
            }
        }

        private byte[] encode(String s) {
            if (utf8) {
                byte[] raw = s.getBytes(StandardCharsets.UTF_8);
                int charLen = s.length(); // Android stores UTF-16 code-unit count approx; use Unicode code points
                // AOSP uses UTF-16 length (code units). Mirror String.length() for BMP-heavy paths.
                charLen = s.length();
                byte[] charLenEnc = encodeLengthUtf8(charLen);
                byte[] byteLenEnc = encodeLengthUtf8(raw.length);
                byte[] out = new byte[charLenEnc.length + byteLenEnc.length + raw.length + 1];
                int p = 0;
                System.arraycopy(charLenEnc, 0, out, p, charLenEnc.length);
                p += charLenEnc.length;
                System.arraycopy(byteLenEnc, 0, out, p, byteLenEnc.length);
                p += byteLenEnc.length;
                System.arraycopy(raw, 0, out, p, raw.length);
                p += raw.length;
                out[p] = 0;
                return out;
            } else {
                byte[] raw = s.getBytes(StandardCharsets.UTF_16LE);
                int charLen = s.length();
                byte[] charLenEnc = encodeLengthUtf16(charLen);
                byte[] out = new byte[charLenEnc.length + raw.length + 2];
                int p = 0;
                System.arraycopy(charLenEnc, 0, out, p, charLenEnc.length);
                p += charLenEnc.length;
                System.arraycopy(raw, 0, out, p, raw.length);
                p += raw.length;
                out[p] = 0;
                out[p + 1] = 0;
                return out;
            }
        }

        private static DecodedLen decodeLengthUtf8(byte[] data, int pos) {
            int b0 = data[pos] & 0xff;
            if ((b0 & 0x80) != 0) {
                int b1 = data[pos + 1] & 0xff;
                int val = ((b0 & 0x7f) << 8) | b1;
                return new DecodedLen(val, pos + 2);
            }
            return new DecodedLen(b0, pos + 1);
        }

        private static DecodedLen decodeLengthUtf16(byte[] data, int pos) {
            int b0 = (data[pos] & 0xff) | ((data[pos + 1] & 0xff) << 8);
            if ((b0 & 0x8000) != 0) {
                int b1 = (data[pos + 2] & 0xff) | ((data[pos + 3] & 0xff) << 8);
                int val = ((b0 & 0x7fff) << 16) | b1;
                return new DecodedLen(val, pos + 4);
            }
            return new DecodedLen(b0, pos + 2);
        }

        private static byte[] encodeLengthUtf8(int len) {
            if (len > 0x7f) {
                return new byte[]{
                        (byte) (0x80 | ((len >> 8) & 0x7f)),
                        (byte) (len & 0xff)
                };
            }
            return new byte[]{(byte) len};
        }

        private static byte[] encodeLengthUtf16(int len) {
            if (len > 0x7fff) {
                throw new IllegalArgumentException("UTF-16 string too long for simple encode: " + len);
            }
            return new byte[]{(byte) (len & 0xff), (byte) ((len >> 8) & 0xff)};
        }
    }

    private static final class DecodedLen {
        final int value;
        final int next;

        DecodedLen(int value, int next) {
            this.value = value;
            this.next = next;
        }
    }
}
