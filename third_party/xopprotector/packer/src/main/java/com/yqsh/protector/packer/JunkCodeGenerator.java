package com.yqsh.protector.packer;

import com.android.dx.Code;
import com.android.dx.DexMaker;
import com.android.dx.Local;
import com.android.dx.MethodId;
import com.android.dx.TypeId;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Generates a junkcode dex with a stable base class plus random decoy classes.
 * Runtime FindClass("com/yqsh/protector/junkcode/JunkClass") must succeed.
 */
public final class JunkCodeGenerator {
    private static final String BASE_CLASS_NAME = "com/yqsh/protector/junkcode/JunkClass";
    private static final int MAX_GENERATE_COUNT = 100;
    private static final Set<String> classNameSet = new HashSet<>();

    private JunkCodeGenerator() {
    }

    private static void insertSystemExit(Code code, boolean returnVoid) {
        TypeId<System> systemType = TypeId.get(System.class);
        MethodId<System, Void> exit = systemType.getMethod(TypeId.VOID, "exit", TypeId.INT);
        Local<Integer> exitCode = code.newLocal(TypeId.INT);
        code.loadConstant(exitCode, 0);
        code.invokeStatic(exit, null, exitCode);
        if (returnVoid) {
            code.returnVoid();
        }
    }

    private static void insertNullExceptionCode(Code code) {
        TypeId<NullPointerException> npe = TypeId.get(NullPointerException.class);
        Local<NullPointerException> local = code.newLocal(npe);
        MethodId<NullPointerException, Void> ctor = npe.getConstructor();
        code.newInstance(local, ctor);
        code.throwValue(local);
    }

    private static String generateBaseClassName() {
        return String.format(Locale.US, "L%s;", BASE_CLASS_NAME);
    }

    private static String generateClassName() {
        SecureRandom secureRandom = new SecureRandom();
        int number = Math.floorMod(secureRandom.nextInt(), MAX_GENERATE_COUNT * 10);
        return String.format(Locale.US, "L%s%d;", BASE_CLASS_NAME, number);
    }

    private static String randomMethodName(SecureRandom rng) {
        char[] buf = new char[3];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = (char) ('a' + rng.nextInt(26));
        }
        return new String(buf);
    }

    public static void generateJunkCodeDex(File file) throws IOException {
        classNameSet.clear();
        SecureRandom secureRandom = new SecureRandom();
        final int generateClassCount =
                secureRandom.nextInt(MAX_GENERATE_COUNT / 2) + (MAX_GENERATE_COUNT / 2);

        DexMaker dexMaker = new DexMaker();
        for (int i = 0; i < generateClassCount; i++) {
            String className;
            if (i == 0) {
                className = generateBaseClassName();
            } else {
                do {
                    className = generateClassName();
                } while (classNameSet.contains(className));
                classNameSet.add(className);
            }

            TypeId<?> typeId = TypeId.get(className);
            dexMaker.declare(typeId, "", Modifier.PUBLIC, TypeId.OBJECT);

            // <clinit>/<init> must be side-effect free: runtime integrity checks
            // resolve the class without intending to run it. System.exit here
            // would kill the host app when FindClass/loadClass initializes the class.
            MethodId<?, Void> clinitMethod = typeId.getMethod(TypeId.VOID, "<clinit>");
            Code clinitCode = dexMaker.declare(clinitMethod, Modifier.STATIC);
            clinitCode.returnVoid();

            MethodId<?, Void> initMethod = typeId.getConstructor();
            Code initCode = dexMaker.declare(initMethod, Modifier.PUBLIC);
            // Call Object.<init> then return — never System.exit.
            MethodId<Object, Void> objectInit = TypeId.OBJECT.getConstructor();
            initCode.invokeDirect(objectInit, null, initCode.getThis(typeId));
            initCode.returnVoid();

            int methodCount = secureRandom.nextInt(2) + 2;
            Set<String> methodNames = new HashSet<>();
            for (int j = 0; j < methodCount; j++) {
                String name;
                do {
                    name = randomMethodName(secureRandom);
                } while (!methodNames.add(name));
                MethodId<?, Void> randomMethod =
                        typeId.getMethod(TypeId.VOID, name);
                Code randomMethodCode = dexMaker.declare(randomMethod, Modifier.PUBLIC);
                if (j % 2 == 0) {
                    insertSystemExit(randomMethodCode, true);
                } else {
                    insertNullExceptionCode(randomMethodCode);
                }
            }
        }

        byte[] generate = dexMaker.generate();
        Files.write(file.toPath(), generate);
        System.out.println("generated junk class count: " + generateClassCount
                + " size=" + generate.length);
    }
}
