package com.yqsh.protector.packer;

/**
 * Lightweight method-level VM packing (PVM1): Dalvik → non-Dalvik image for
 * static unreadability. Runtime unpacks inside .bitcode before writing DEX.
 * This is virtualized packing, not a full bytecode interpreter.
 */
public final class VmCodec {
    /** Legacy PVM1 packing (decode → write Dalvik). */
    public static final int FLAG_VMP = 1;
    /** True VMP: PVM2 image interpreted natively (never restored to DEX). */
    public static final int FLAG_TRUE_VMP = 2;
    private static final byte[] MAGIC = {'P', 'V', 'M', '1'};

    private VmCodec() {
    }

    /** Encode plaintext Dalvik insn bytes into a PVM1 blob (same length + 4). */
    public static byte[] encode(int methodIdx, byte[] dalvik) {
        if (dalvik == null) return null;
        byte[] out = new byte[MAGIC.length + dalvik.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        for (int i = 0; i < dalvik.length; i++) {
            int ks = keystream(methodIdx, i);
            int b = (dalvik[i] & 0xff) ^ ks;
            // Nibble-swap opcode-ish bytes to break linear Dalvik scanning.
            if ((i & 1) == 0) {
                b = ((b << 4) & 0xf0) | ((b >> 4) & 0x0f);
            }
            out[MAGIC.length + i] = (byte) b;
        }
        return out;
    }

    /** Decode PVM1 → Dalvik. Returns null if magic/size mismatch. */
    public static byte[] decode(int methodIdx, byte[] pvm, int expectedPlainLen) {
        if (pvm == null || pvm.length < MAGIC.length + expectedPlainLen) return null;
        for (int i = 0; i < MAGIC.length; i++) {
            if (pvm[i] != MAGIC[i]) return null;
        }
        byte[] out = new byte[expectedPlainLen];
        for (int i = 0; i < expectedPlainLen; i++) {
            int b = pvm[MAGIC.length + i] & 0xff;
            if ((i & 1) == 0) {
                b = ((b << 4) & 0xf0) | ((b >> 4) & 0x0f);
            }
            out[i] = (byte) (b ^ keystream(methodIdx, i));
        }
        return out;
    }

    private static int keystream(int methodIdx, int i) {
        return (methodIdx * 131 + i * 17 + 0xA5) & 0xff;
    }
}
