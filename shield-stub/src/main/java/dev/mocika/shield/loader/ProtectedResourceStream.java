package dev.mocika.shield.loader;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.function.BooleanSupplier;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** 按分片认证读取显式授权的业务资源。 */
final class ProtectedResourceStream extends InputStream {
    private static final int CHUNK_SIZE = 64 * 1024;
    private static final int MAX_SIZE = 16 * 1024 * 1024;
    private final DataInputStream input;
    private final BooleanSupplier authorized;
    private final byte[] key;
    private final byte[] aad;
    private int remaining;
    private int sequence;
    private byte[] chunk = new byte[0];
    private int position;
    private boolean closed;

    static ProtectedResourceStream open(InputStream input, byte[] build, String group,
            String resource, long version, byte[] key, BooleanSupplier authorized) throws IOException {
        try {
            return new ProtectedResourceStream(input, build, group, resource, version, key, authorized);
        } catch (IOException | RuntimeException failure) {
            try {
                input.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw failure;
        }
    }

    private ProtectedResourceStream(InputStream source, byte[] build, String group,
            String resource, long version, byte[] key, BooleanSupplier authorized) throws IOException {
        if (key.length != 32 || build.length != 16 || version < 1 || version > 0xffffffffL
                || !group.matches("[a-z0-9_-]{1,64}") || !resource.matches("[a-z0-9_-]{1,64}")) {
            throw new IOException("业务资源上下文无效");
        }
        this.input = new DataInputStream(source);
        this.authorized = authorized;
        ByteArrayOutputStream header = new ByteArrayOutputStream(164);
        byte[] prefix = readBytes(20);
        header.write(prefix, 0, prefix.length);
        if (!Arrays.equals(new byte[]{'S','S','R','1'}, Arrays.copyOf(prefix, 4))
                || !Arrays.equals(build, Arrays.copyOfRange(prefix, 4, 20))
                || !group.equals(readIdentifier(header))
                || !resource.equals(readIdentifier(header))) {
            throw new IOException("业务资源身份不匹配");
        }
        byte[] dimensions = readBytes(12);
        header.write(dimensions, 0, dimensions.length);
        long actualVersion = 0;
        long length = 0;
        for (int i = 0; i < 4; i++) actualVersion = (actualVersion << 8) | (dimensions[i] & 255);
        for (int i = 4; i < 12; i++) length = (length << 8) | (dimensions[i] & 255);
        if (actualVersion != version || length < 1 || length > MAX_SIZE) {
            throw new IOException("业务资源版本或长度无效");
        }
        this.remaining = (int) length;
        this.aad = Arrays.copyOf(header.toByteArray(), header.size() + 4);
        this.key = key.clone();
    }

    private String readIdentifier(ByteArrayOutputStream header) throws IOException {
        int length = input.readUnsignedByte();
        if (length < 1 || length > 64) throw new IOException("业务资源标识长度无效");
        byte[] bytes = readBytes(length);
        header.write(length);
        header.write(bytes, 0, length);
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    private byte[] readBytes(int length) throws IOException {
        byte[] result = new byte[length];
        input.readFully(result);
        return result;
    }

    private boolean availableChunk() throws IOException {
        if (closed) throw new IOException("业务资源已关闭");
        try {
            if (!authorized.getAsBoolean()) throw new IOException("业务资源授权已失效");
            if (position < chunk.length) return true;
            if (remaining == 0) return false;
            int length = Math.min(remaining, CHUNK_SIZE);
            byte[] nonce = readBytes(12);
            byte[] encrypted = readBytes(length + 16);
            if (remaining == length && input.read() != -1) throw new IOException("业务资源含多余数据");
            for (int i = 0; i < 4; i++) aad[aad.length - 1 - i] = (byte) (sequence >>> (i * 8));
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            Arrays.fill(chunk, (byte) 0);
            chunk = cipher.doFinal(encrypted);
            if (!authorized.getAsBoolean()) throw new IOException("业务资源授权已失效");
            position = 0;
            remaining -= length;
            sequence++;
            return true;
        } catch (GeneralSecurityException | IOException | RuntimeException failure) {
            try {
                close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw new IOException("业务资源读取失败", failure);
        }
    }

    @Override public int read() throws IOException {
        return availableChunk() ? chunk[position++] & 255 : -1;
    }

    @Override public int read(byte[] buffer, int offset, int length) throws IOException {
        if (offset < 0 || length < 0 || offset > buffer.length - length) throw new IndexOutOfBoundsException();
        if (length == 0) return 0;
        if (!availableChunk()) return -1;
        int count = Math.min(length, chunk.length - position);
        System.arraycopy(chunk, position, buffer, offset, count);
        position += count;
        return count;
    }

    @Override public void close() throws IOException {
        if (!closed) {
            closed = true;
            Arrays.fill(chunk, (byte) 0);
            Arrays.fill(key, (byte) 0);
            input.close();
        }
    }
}
