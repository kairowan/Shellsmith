package com.yqsh.protector.packer;

import com.android.dex.Code;
import com.android.dex.Dex;
import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.immutable.*;
import com.android.tools.smali.dexlib2.immutable.instruction.*;
import com.android.tools.smali.dexlib2.immutable.reference.*;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import java.util.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.io.DataOutputStream;
import java.util.Random;

/** 由实际 Java 编译器生成三种调度变体的普通、必保和异常方法，交给生产 C++ 解析器和 JNI 执行。 */
public final class Pvm2RuntimeImages {
    /** 小范围结构试验：条件反转加跳转；尚未作为生产保护策略启用。 */
    static Code branchInput(int condition, boolean inverted) {
        short[] units = inverted
                ? new short[]{(short) (0x2132 + (condition ^ 1)), 4, 0x0029, 4, 0x0012, 0x0228, 0x1012, 0x000f}
                : new short[]{(short) (0x2132 + condition), 4, 0x0012, 0x0228, 0x1012, 0x000f};
        return new Code(3, 2, 0, 0, units, new Code.Try[0], new Code.CatchHandler[0]);
    }

    private static Dex receiverFixtures(Path path) throws Exception {
        String owner = "Lfixture/ReceiverFlow;";
        var stringType = new ImmutableTypeReference("Ljava/lang/String;");
        var length = new ImmutableMethodReference("Ljava/lang/String;", "length", List.of(), "I");
        var guarded = new ImmutableMethod(owner, "guarded", List.of(new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), null)), "I", 9, Set.of(), Set.of(),
            new ImmutableMethodImplementation(3, List.of(
                new ImmutableInstruction22c(Opcode.INSTANCE_OF, 0, 2, stringType),
                new ImmutableInstruction21t(Opcode.IF_EQZ, 0, 9),
                new ImmutableInstruction21c(Opcode.CHECK_CAST, 2, stringType),
                new ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 2, 0, 0, 0, 0, length),
                new ImmutableInstruction11x(Opcode.MOVE_RESULT, 0), new ImmutableInstruction11x(Opcode.RETURN, 0),
                new ImmutableInstruction11n(Opcode.CONST_4, 0, -1), new ImmutableInstruction11x(Opcode.RETURN, 0)), List.of(), List.of()));
        var caught = new ImmutableMethod(owner, "caught", guarded.getParameters(), "I", 9, Set.of(), Set.of(),
            new ImmutableMethodImplementation(3, List.of(
                new ImmutableInstruction21c(Opcode.CONST_STRING, 1, new ImmutableStringReference("kept")),
                new ImmutableInstruction21c(Opcode.CHECK_CAST, 2, stringType),
                new ImmutableInstruction11n(Opcode.CONST_4, 0, 7), new ImmutableInstruction11x(Opcode.RETURN, 0),
                new ImmutableInstruction11x(Opcode.MOVE_EXCEPTION, 0),
                new ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 1, 0, 0, 0, 0, length),
                new ImmutableInstruction11x(Opcode.MOVE_RESULT, 0), new ImmutableInstruction11x(Opcode.RETURN, 0)),
                List.of(new ImmutableTryBlock(2, 2, List.of(new ImmutableExceptionHandler("Ljava/lang/ClassCastException;", 6)))), List.of()));
        var mixed = new ImmutableMethod(owner, "mixed", List.of(
                new ImmutableMethodParameter("J", Set.of(), null), new ImmutableMethodParameter("D", Set.of(), null),
                new ImmutableMethodParameter("F", Set.of(), null), new ImmutableMethodParameter("Z", Set.of(), null),
                new ImmutableMethodParameter("I", Set.of(), null)), "I", 9, Set.of(), Set.of(),
                new ImmutableMethodImplementation(7, List.of(new ImmutableInstruction11x(Opcode.RETURN, 6)), List.of(), List.of()));
        var tail = new ImmutableMethod(owner, "tail", List.of(new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), null),
                new ImmutableMethodParameter("I", Set.of(), null)), "I", 9, Set.of(), Set.of(),
                new ImmutableMethodImplementation(2, List.of(new ImmutableInstruction11x(Opcode.RETURN, 1)), List.of(), List.of()));
        DexPool pool = new DexPool(Opcodes.getDefault());
        pool.internClass(new ImmutableClassDef(owner, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(caught, guarded, mixed, tail)));
        FileDataStore store = new FileDataStore(path.toFile());
        try { pool.writeTo(store); } finally { store.close(); }
        return new Dex(path.toFile());
    }

    public static void main(String[] args) throws Exception {
        // 独立 JCE 参考覆盖空输入、分块边界和较大镜像，避免加解密共享缺陷而自证通过。
        Random random = new Random(20261015);
        try (DataOutputStream out = new DataOutputStream(Files.newOutputStream(Path.of(args[0], "aes-vectors.bin")))) {
            int[] extra = {127, 128, 129, 255, 256, 257, 1024, 4097};
            for (int i = 0; i < 65 + extra.length; i++) {
                int length = i < 65 ? i : extra[i - 65];
                byte[] key = new byte[16], bytes = new byte[length];
                random.nextBytes(key); random.nextBytes(bytes);
                byte[] encrypted = com.yqsh.protector.packer.util.CryptoUtils.aesGcmEncrypt(key, bytes);
                out.write(key); out.writeInt(length); out.write(bytes); out.write(encrypted);
                out.write(com.yqsh.protector.packer.util.CryptoUtils.aesCtrCrypt(key, bytes));
            }
        }
        Code code = new Code(1, 0, 0, 0, new short[]{0x0014, 42, 0, 0x000f},
                new Code.Try[0], new Code.CatchHandler[0]);
        Dex dex = receiverFixtures(Path.of(args[0], "receivers.dex"));
        List<Code> receivers = new ArrayList<>();
        for (var cls : dex.classDefs()) for (var method : dex.readClassData(cls).allMethods()) receivers.add(dex.readCode(method));
        if (receivers.size() != 4) throw new AssertionError("接收者样本数量不符");
        for (int i = 0; i < 72; i++) {
            int isa = i % 3;
            Code input = i < 6 ? code : new Code(1, 0, 0, 0, new short[]{0x0012, 0x0027},
                    new Code.Try[0], new Code.CatchHandler[0]);
            if (i >= 9 && i < 45) input = branchInput((i - 9) / 6, ((i - 9) / 3) % 2 != 0);
            if (i >= 45 && i < 57) input = receivers.get((i - 45) / 3);
            String returnType = "I";
            String[] parameters = i >= 54 ? new String[]{"Ljava/lang/Object;", "I"} : i >= 51 ? new String[]{"J", "D", "F", "Z", "I"} : i >= 45 ? new String[]{"Ljava/lang/Object;"} : i >= 9 ? new String[]{"I", "I"} : new String[0];
            if (i >= 57) {
                // 引用透传、空值选择、同一对象比较、null 判断及数组透传，覆盖三种 ISA。
                int kind = (i - 57) / 3;
                short[] units = switch (kind) {
                    case 0, 4 -> new short[]{0x1007, 0x0011};
                    case 1 -> new short[]{0x0139, 3, 0x0211, 0x0111};
                    case 2 -> branchInput(0, false).getInstructions();
                    default -> new short[]{0x0138, 4, 0x0012, 0x0228, 0x1012, 0x000f};
                };
                boolean pair = kind == 1 || kind == 2;
                input = new Code(pair ? 3 : 2, pair ? 2 : 1, 0, 0, units, new Code.Try[0], new Code.CatchHandler[0]);
                returnType = kind == 2 || kind == 3 ? "I" : kind == 4 ? "[I" : "Ljava/lang/Object;";
                parameters = pair ? new String[]{"Ljava/lang/Object;", "Ljava/lang/Object;"}
                        : new String[]{kind == 4 ? "[I" : "Ljava/lang/Object;"};
            }
            Pvm2Compiler.Result result = Pvm2Compiler.tryCompile(i >= 45 ? dex : null, input, returnType, true,
                    Pvm2Morph.fromIsa(isa, new SecureRandom()), i >= 3, parameters);
            if (!result.isOk()) throw new AssertionError(result.failReason);
            Files.write(Path.of(args[0], "image" + i + ".bin"), result.image);
            Files.write(Path.of(args[0], "image" + i + ".gcm"),
                    com.yqsh.protector.packer.util.CryptoUtils.aesGcmEncrypt(new byte[16], result.image));
        }
        String owner = "Lfixture/ui/VirtualRules;";
        List<ImmutableMethod> methods = new ArrayList<>(Pvm2ProtectionCheck.exceptionMethods(owner));
        methods.add(new ImmutableMethod(owner, "self", List.of(), "Ljava/lang/Object;", 1, Set.of(), Set.of(),
                new ImmutableMethodImplementation(1, List.of(new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0)), List.of(), List.of())));
        methods.add(new ImmutableMethod(owner, "identity", List.of(new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), null)),
                "Ljava/lang/Object;", 1, Set.of(), Set.of(), new ImmutableMethodImplementation(2,
                        List.of(new ImmutableInstruction11x(Opcode.RETURN_OBJECT, 1)), List.of(), List.of())));
        var cls = new ImmutableClassDef(owner, 1, "Lexternal/Base;", List.of("Lexternal/Contract;"), null, Set.of(), List.of(), methods);
        DexPool pool = new DexPool(Opcodes.getDefault()); pool.internClass(cls);
        Path path = Path.of(args[0], "compatibility.dex");
        FileDataStore store = new FileDataStore(path.toFile());
        try { pool.writeTo(store); } finally { store.close(); }
        Dex compatibility = new Dex(path.toFile());
        Map<String, Code> bodies = new HashMap<>();
        for (var definition : compatibility.classDefs()) for (var method : compatibility.readClassData(definition).allMethods())
            bodies.put(compatibility.strings().get(compatibility.methodIds().get(method.getMethodIndex()).getNameIndex()), compatibility.readCode(method));
        for (int kind = 0; kind < methods.size(); kind++) for (int isa = 0; isa < 3; isa++) {
            var method = methods.get(kind);
            if (AutoVmpPolicy.exclusionReason(cls, method) != null) throw new AssertionError("兼容样本未准入");
            var result = Pvm2Compiler.tryCompile(compatibility, bodies.get(method.getName()), method.getReturnType(), false,
                    Pvm2Morph.fromIsa(isa, new SecureRandom()), true, method.getParameterTypes().stream().map(CharSequence::toString).toArray(String[]::new));
            if (!result.isOk()) throw new AssertionError(method.getName() + ": " + result.failReason);
            int index = 72 + kind * 3 + isa;
            Files.write(Path.of(args[0], "image" + index + ".bin"), result.image);
            Files.write(Path.of(args[0], "image" + index + ".gcm"),
                    com.yqsh.protector.packer.util.CryptoUtils.aesGcmEncrypt(new byte[16], result.image));
        }
    }
}
