package com.yqsh.protector.packer;

import com.android.dex.Code;
import com.android.tools.smali.dexlib2.Opcodes;
import java.util.BitSet;

/** 校验编译所需的结构边界；可空接收者交给运行时按原指令位置抛出并派发异常。 */
final class Pvm2Safety {
    private static final Opcodes OPCODES = Opcodes.getDefault();

    private Pvm2Safety() {}

    static String check(Code code) {
        if (code == null) return "semantic safety: no code";
        short[] units = code.getInstructions();
        int registers = code.getRegistersSize(), inputs = code.getInsSize();
        if (registers < 0 || registers > 255 || inputs < 0 || inputs > registers)
            return "semantic safety: invalid register frame";
        if (units == null || units.length == 0) return null;
        BitSet boundaries = new BitSet(units.length + 1);
        BitSet executable = new BitSet(units.length);
        try {
            for (int pc = 0; pc < units.length;) {
                int width = widthOf(units, pc);
                if (width <= 0 || width > units.length - pc)
                    return "semantic safety: malformed instruction";
                boundaries.set(pc);
                if ((units[pc] & 0xff) != 0 || units[pc] == 0) executable.set(pc);
                pc += width;
            }
            boundaries.set(units.length);
            for (int pc = executable.nextSetBit(0); pc >= 0; pc = executable.nextSetBit(pc + 1)) {
                int u0 = units[pc] & 0xffff, op = u0 & 0xff;
                long target = -1;
                if (op == 0x28) target = (long)pc + (byte)(u0 >>> 8);
                else if (op == 0x29 || (op >= 0x32 && op <= 0x3d)) target = (long)pc + units[pc + 1];
                else if (op == 0x2a) target = (long)pc + signed32(units, pc + 1);
                if ((op >= 0x28 && op <= 0x2a || op >= 0x32 && op <= 0x3d)
                        && !contains(executable, target)) return "semantic safety: malformed branch target";
                if (op == 0x2b || op == 0x2c || op == 0x26) {
                    long address = (long)pc + signed32(units, pc + 1);
                    if (!contains(boundaries, address) || address >= units.length || (address & 1) != 0)
                        return "semantic safety: malformed payload target";
                    int payload = (int)address;
                    int ident = op == 0x2b ? 0x0100 : op == 0x2c ? 0x0200 : 0x0300;
                    if ((units[payload] & 0xffff) != ident) return "semantic safety: malformed payload type";
                    if (op != 0x26) {
                        int size = units[payload + 1] & 0xffff;
                        int base = payload + (op == 0x2b ? 4 : 2 + size * 2);
                        for (int i = 0; i < size; i++)
                            if (!contains(executable, (long)pc + signed32(units, base + i * 2)))
                                return "semantic safety: malformed switch target";
                    }
                }
                if (op >= 0x6e && op <= 0x72 || op >= 0x74 && op <= 0x78) {
                    boolean range = op >= 0x74;
                    int count = range ? u0 >>> 8 : u0 >>> 12;
                    if (!range && count > 5) return "semantic safety: invalid invoke argument count";
                    if (count == 0 && op != 0x71 && op != 0x77)
                        return "semantic safety: invoke missing receiver";
                    int packed = units[pc + 2] & 0xffff;
                    for (int i = 0; i < count; i++) {
                        int register = range ? packed + i : i == 4 ? (u0 >>> 8) & 15 : (packed >>> (i * 4)) & 15;
                        if (register >= registers) return "semantic safety: invoke register out of range";
                    }
                }
            }
            if (code.getTries() != null) for (Code.Try block : code.getTries()) {
                int start = block.getStartAddress(), count = block.getInstructionCount();
                int index = block.getCatchHandlerIndex();
                Code.CatchHandler[] handlers = code.getCatchHandlers();
                if (!contains(executable, start) || count <= 0 || count > units.length - start
                        || !boundaries.get(start + count) || handlers == null || index < 0 || index >= handlers.length)
                    return "semantic safety: malformed exception table";
                Code.CatchHandler handler = handlers[index];
                int[] addresses = handler.getAddresses(), types = handler.getTypeIndexes();
                if (addresses == null || types == null || addresses.length != types.length
                        || addresses.length == 0 && handler.getCatchAllAddress() < 0)
                    return "semantic safety: malformed exception table";
                for (int address : addresses) if (!contains(executable, address))
                    return "semantic safety: malformed exception target";
                if (handler.getCatchAllAddress() >= 0 && !contains(executable, handler.getCatchAllAddress()))
                    return "semantic safety: malformed exception target";
            }
        } catch (RuntimeException malformed) {
            return "semantic safety: malformed instruction";
        }
        return null;
    }

    private static boolean contains(BitSet boundaries, long pc) {
        return pc >= 0 && pc < Integer.MAX_VALUE && boundaries.get((int)pc);
    }

    private static int signed32(short[] units, int pc) {
        return (units[pc] & 0xffff) | (units[pc + 1] << 16);
    }

    private static int widthOf(short[] units, int pc) {
        int ident = units[pc] & 0xffff;
        if (ident == 0x0100) return 4 + (units[pc + 1] & 0xffff) * 2;
        if (ident == 0x0200) return 2 + (units[pc + 1] & 0xffff) * 4;
        if (ident == 0x0300) {
            int elementWidth = units[pc + 1] & 0xffff;
            long size = Integer.toUnsignedLong(signed32(units, pc + 2));
            long width = 4 + (size * elementWidth + 1) / 2;
            if (elementWidth != 1 && elementWidth != 2 && elementWidth != 4 && elementWidth != 8
                    || width > Integer.MAX_VALUE) throw new IllegalArgumentException("bad payload");
            return (int)width;
        }
        var opcode = OPCODES.getOpcodeByValue(ident & 0xff);
        if (opcode == null || opcode.format.size <= 0) throw new IllegalArgumentException("unknown opcode");
        return opcode.format.size / 2;
    }
}
