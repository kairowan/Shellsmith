package com.yqsh.protector.packer;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Walle-compatible channel payload in the APK Signing Block (ID {@code 0x71777777}).
 * Writing does <em>not</em> invalidate APK Signature Scheme v2/v3 — stamp after sign.
 */
public final class ApkChannel {
    /** Same ID as Meituan Walle {@code APK_CHANNEL_BLOCK_ID}. */
    public static final int CHANNEL_BLOCK_ID = 0x71777777;

    private static final int APK_SIG_BLOCK_MIN_SIZE = 32;
    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L; // "2 blkco"
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L; // " gSi APK"
    private static final int ZIP_EOCD_REC_MIN_SIZE = 22;
    private static final int ZIP_EOCD_REC_SIG = 0x06054b50;
    private static final int UINT16_MAX_VALUE = 0xffff;
    private static final int ZIP_EOCD_COMMENT_LENGTH_OFFSET = 20;
    private static final int VERITY_PADDING_BLOCK_ID = 0x42726577;
    private static final int ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;

    private ApkChannel() {
    }

    /** Read raw channel-block value bytes, or {@code null} if absent. */
    public static byte[] readRaw(File apk) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(apk, "r")) {
            Pair<ByteBuffer, Long> block = findApkSigningBlock(raf);
            Map<Integer, ByteBuffer> idValues = findIdValues(block.getLeft());
            ByteBuffer payload = idValues.get(CHANNEL_BLOCK_ID);
            if (payload == null) {
                return null;
            }
            byte[] out = new byte[payload.remaining()];
            payload.get(out);
            return out;
        }
    }

    /** Read channel string from Walle-style JSON ({@code {"channel":"..."}}), or plain UTF-8. */
    public static String readChannel(File apk) throws IOException {
        byte[] raw = readRaw(apk);
        if (raw == null || raw.length == 0) {
            return null;
        }
        String s = new String(raw, StandardCharsets.UTF_8).trim();
        if (s.startsWith("{")) {
            String ch = extractJsonString(s, "channel");
            return ch != null ? ch : s;
        }
        return s;
    }

    /**
     * Write / replace channel on a V2/V3-signed APK (in place or to {@code output}).
     *
     * @param channel channel id (non-empty); stored as {@code {"channel":"..."}}
     */
    public static void writeChannel(File inputApk, File outputApk, String channel) throws IOException {
        if (channel == null || channel.isEmpty()) {
            throw new IllegalArgumentException("channel must be non-empty");
        }
        if (channel.length() > 256) {
            throw new IllegalArgumentException("channel too long (max 256)");
        }
        for (int i = 0; i < channel.length(); i++) {
            char c = channel.charAt(i);
            if (c < 0x20 || c == '"' || c == '\\') {
                throw new IllegalArgumentException("channel has illegal char at " + i);
            }
        }
        String json = "{\"channel\":\"" + channel + "\"}";
        writeRaw(inputApk, outputApk, json.getBytes(StandardCharsets.UTF_8));
    }

    /** Write raw payload bytes under {@link #CHANNEL_BLOCK_ID}. */
    public static void writeRaw(File inputApk, File outputApk, byte[] payload) throws IOException {
        if (payload == null) {
            throw new IllegalArgumentException("payload is required");
        }
        File dest = outputApk != null ? outputApk : inputApk;
        boolean inPlace = dest.getCanonicalFile().equals(inputApk.getCanonicalFile());
        File work = inPlace
                ? File.createTempFile("protector-channel-", ".apk", dest.getParentFile())
                : dest;
        try {
            rewriteSigningBlock(inputApk, work, payload);
            if (inPlace) {
                Files.move(work.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            if (inPlace && work.isFile() && !work.equals(dest)) {
                //noinspection ResultOfMethodCallIgnored
                work.delete();
            }
            throw e;
        }
    }

    private static void rewriteSigningBlock(File inputApk, File outputApk, byte[] channelPayload)
            throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(inputApk, "r")) {
            Pair<ByteBuffer, Long> blockAndOffset = findApkSigningBlock(raf);
            ByteBuffer apkSigningBlock = blockAndOffset.getLeft();
            long apkSigningBlockOffset = blockAndOffset.getRight();

            Map<Integer, ByteBuffer> originIdValues = findIdValues(apkSigningBlock);
            // Drop old padding; regenerate below if needed.
            originIdValues.remove(VERITY_PADDING_BLOCK_ID);
            originIdValues.put(CHANNEL_BLOCK_ID, ByteBuffer.wrap(channelPayload));

            ByteBuffer newBlock = createApkSigningBlock(originIdValues);
            long centralDirOffset = findCentralDirOffset(raf);
            long centralDirSize = raf.length() - centralDirOffset;
            byte[] centralDir = new byte[(int) centralDirSize];
            raf.seek(centralDirOffset);
            raf.readFully(centralDir);

            try (RandomAccessFile out = new RandomAccessFile(outputApk, "rw")) {
                out.setLength(0);
                // Contents before signing block.
                raf.seek(0);
                byte[] buf = new byte[8192];
                long remaining = apkSigningBlockOffset;
                while (remaining > 0) {
                    int n = (int) Math.min(buf.length, remaining);
                    int r = raf.read(buf, 0, n);
                    if (r < 0) {
                        throw new IOException("unexpected EOF copying APK contents");
                    }
                    out.write(buf, 0, r);
                    remaining -= r;
                }
                out.write(newBlock.array(), newBlock.arrayOffset(), newBlock.remaining());

                long newCentralDirOffset = out.getFilePointer();
                // EOCD: update CD offset (little-endian uint32 at relative +16).
                ByteBuffer eocd = ByteBuffer.wrap(centralDir);
                eocd.order(ByteOrder.LITTLE_ENDIAN);
                int eocdOffsetInCd = findEocdOffsetInTail(centralDir);
                eocd.putInt(eocdOffsetInCd + 16, (int) newCentralDirOffset);
                out.write(centralDir);
            }
        }
    }

    private static ByteBuffer createApkSigningBlock(Map<Integer, ByteBuffer> idValues) {
        // pairs length = sum(8 + 4 + value)
        long pairsLen = 0;
        for (Map.Entry<Integer, ByteBuffer> e : idValues.entrySet()) {
            pairsLen += 8 + 4 + e.getValue().remaining();
        }
        // block size field counts: pairs + 8 (size) + 16 (magic)
        long blockSize = pairsLen + 8 + 16;

        // Optional verity padding so (signing block + preceding content) ends on 4K —
        // preserve Walle/AGP behavior when padding ID was present or block grew oddly.
        int padding = 0;
        // size(8) + pairs + size(8) + magic(16) = blockSize + 8
        long totalSigningBlock = blockSize + 8;
        int remainder = (int) (totalSigningBlock % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES);
        if (remainder != 0) {
            padding = ANDROID_COMMON_PAGE_ALIGNMENT_BYTES - remainder;
            if (padding < 12) {
                // Need room for length(8)+id(4) at minimum; bump another page.
                padding += ANDROID_COMMON_PAGE_ALIGNMENT_BYTES;
            }
            pairsLen += padding;
            blockSize = pairsLen + 8 + 16;
            totalSigningBlock = blockSize + 8;
        }

        ByteBuffer buffer = ByteBuffer.allocate((int) totalSigningBlock);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(blockSize);
        for (Map.Entry<Integer, ByteBuffer> e : idValues.entrySet()) {
            ByteBuffer value = e.getValue().duplicate();
            buffer.putLong(4L + value.remaining());
            buffer.putInt(e.getKey());
            buffer.put(value);
        }
        if (padding > 0) {
            // length includes id(4) + zero pad
            buffer.putLong(padding - 8L);
            buffer.putInt(VERITY_PADDING_BLOCK_ID);
            int padBytes = padding - 12;
            for (int i = 0; i < padBytes; i++) {
                buffer.put((byte) 0);
            }
        }
        buffer.putLong(blockSize);
        buffer.putLong(APK_SIG_BLOCK_MAGIC_LO);
        buffer.putLong(APK_SIG_BLOCK_MAGIC_HI);
        if (buffer.hasRemaining()) {
            throw new IllegalStateException("signing block size mismatch remaining=" + buffer.remaining());
        }
        buffer.flip();
        return buffer;
    }

    private static Pair<ByteBuffer, Long> findApkSigningBlock(RandomAccessFile apk)
            throws IOException {
        long centralDirOffset = findCentralDirOffset(apk);
        if (centralDirOffset < APK_SIG_BLOCK_MIN_SIZE) {
            throw new IOException("APK too small for signing block; CD offset=" + centralDirOffset);
        }
        // Footer: size(8) + magic(16) immediately before CD.
        apk.seek(centralDirOffset - 24);
        ByteBuffer footer = ByteBuffer.allocate(24);
        footer.order(ByteOrder.LITTLE_ENDIAN);
        apk.readFully(footer.array());
        if (footer.getLong(8) != APK_SIG_BLOCK_MAGIC_LO
                || footer.getLong(16) != APK_SIG_BLOCK_MAGIC_HI) {
            throw new IOException(
                    "No APK Signing Block (need V2/V3 signed APK). magic mismatch before CD.");
        }
        long blockSizeInFooter = footer.getLong(0);
        if (blockSizeInFooter < footer.capacity() || blockSizeInFooter > Integer.MAX_VALUE - 8) {
            throw new IOException("APK Signing Block size out of range: " + blockSizeInFooter);
        }
        long totalSize = blockSizeInFooter + 8;
        long blockOffset = centralDirOffset - totalSize;
        if (blockOffset < 0) {
            throw new IOException("APK Signing Block offset negative");
        }
        apk.seek(blockOffset);
        ByteBuffer block = ByteBuffer.allocate((int) totalSize);
        block.order(ByteOrder.LITTLE_ENDIAN);
        apk.readFully(block.array());
        long blockSizeInHeader = block.getLong(0);
        if (blockSizeInHeader != blockSizeInFooter) {
            throw new IOException("APK Signing Block size mismatch header/footer");
        }
        return new Pair<>(block, blockOffset);
    }

    private static Map<Integer, ByteBuffer> findIdValues(ByteBuffer apkSigningBlock) {
        checkLittleEndian(apkSigningBlock);
        // pairs: between first size(8) and trailing size(8)+magic(16)
        int pairsEnd = apkSigningBlock.capacity() - 24;
        int pairsStart = 8;
        if (pairsEnd < pairsStart) {
            throw new IllegalArgumentException("APK Signing Block too small");
        }
        ByteBuffer pairs = slice(apkSigningBlock, pairsStart, pairsEnd - pairsStart);
        Map<Integer, ByteBuffer> idValues = new LinkedHashMap<>();
        while (pairs.remaining() >= 8) {
            long lenLong = pairs.getLong();
            if (lenLong < 4 || lenLong > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("bad pair length " + lenLong);
            }
            int len = (int) lenLong;
            if (pairs.remaining() < len) {
                throw new IllegalArgumentException("pair exceeds signing block");
            }
            int id = pairs.getInt();
            int valueLen = len - 4;
            ByteBuffer value = slice(pairs, pairs.position(), valueLen);
            pairs.position(pairs.position() + valueLen);
            idValues.put(id, value);
        }
        return idValues;
    }

    private static long findCentralDirOffset(RandomAccessFile apk) throws IOException {
        long fileSize = apk.length();
        if (fileSize < ZIP_EOCD_REC_MIN_SIZE) {
            throw new IOException("APK too small");
        }
        long maxCommentLength = Math.min(UINT16_MAX_VALUE, fileSize - ZIP_EOCD_REC_MIN_SIZE);
        long eocdWithMaxComment = ZIP_EOCD_REC_MIN_SIZE + maxCommentLength;
        long searchStart = fileSize - eocdWithMaxComment;
        if (searchStart < 0) {
            searchStart = 0;
        }
        byte[] eocd = new byte[ZIP_EOCD_REC_MIN_SIZE];
        for (long commentLength = 0; commentLength <= maxCommentLength; commentLength++) {
            long eocdPos = fileSize - ZIP_EOCD_REC_MIN_SIZE - commentLength;
            if (eocdPos < searchStart) {
                break;
            }
            apk.seek(eocdPos);
            apk.readFully(eocd);
            ByteBuffer bb = ByteBuffer.wrap(eocd).order(ByteOrder.LITTLE_ENDIAN);
            if (bb.getInt(0) != ZIP_EOCD_REC_SIG) {
                continue;
            }
            int actualComment = bb.getShort(ZIP_EOCD_COMMENT_LENGTH_OFFSET) & 0xffff;
            if (actualComment != commentLength) {
                continue;
            }
            return bb.getInt(16) & 0xffffffffL;
        }
        throw new IOException("ZIP End of Central Directory not found");
    }

    private static int findEocdOffsetInTail(byte[] centralDirAndEocd) {
        // centralDir buffer is CD + EOCD(+comment); find EOCD signature from end.
        int maxComment = Math.min(UINT16_MAX_VALUE, centralDirAndEocd.length - ZIP_EOCD_REC_MIN_SIZE);
        for (int commentLength = 0; commentLength <= maxComment; commentLength++) {
            int eocdPos = centralDirAndEocd.length - ZIP_EOCD_REC_MIN_SIZE - commentLength;
            if (eocdPos < 0) {
                break;
            }
            int sig = (centralDirAndEocd[eocdPos] & 0xff)
                    | ((centralDirAndEocd[eocdPos + 1] & 0xff) << 8)
                    | ((centralDirAndEocd[eocdPos + 2] & 0xff) << 16)
                    | ((centralDirAndEocd[eocdPos + 3] & 0xff) << 24);
            if (sig != ZIP_EOCD_REC_SIG) {
                continue;
            }
            int actualComment = (centralDirAndEocd[eocdPos + ZIP_EOCD_COMMENT_LENGTH_OFFSET] & 0xff)
                    | ((centralDirAndEocd[eocdPos + ZIP_EOCD_COMMENT_LENGTH_OFFSET + 1] & 0xff) << 8);
            if (actualComment == commentLength) {
                return eocdPos;
            }
        }
        throw new IllegalArgumentException("EOCD not found in CD tail");
    }

    private static ByteBuffer slice(ByteBuffer source, int position, int length) {
        ByteBuffer dup = source.duplicate();
        dup.order(ByteOrder.LITTLE_ENDIAN);
        dup.position(position);
        dup.limit(position + length);
        return dup.slice().order(ByteOrder.LITTLE_ENDIAN);
    }

    private static void checkLittleEndian(ByteBuffer buffer) {
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
    }

    /** Minimal JSON string extractor for {@code "key":"value"} (no nesting). */
    static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\"";
        int i = json.indexOf(needle);
        if (i < 0) {
            return null;
        }
        int colon = json.indexOf(':', i + needle.length());
        if (colon < 0) {
            return null;
        }
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int p = q1 + 1; p < json.length(); p++) {
            char c = json.charAt(p);
            if (c == '\\' && p + 1 < json.length()) {
                sb.append(json.charAt(++p));
                continue;
            }
            if (c == '"') {
                return sb.toString();
            }
            sb.append(c);
        }
        return null;
    }

    private static final class Pair<A, B> {
        private final A left;
        private final B right;

        Pair(A left, B right) {
            this.left = left;
            this.right = right;
        }

        A getLeft() {
            return left;
        }

        B getRight() {
            return right;
        }
    }
}
