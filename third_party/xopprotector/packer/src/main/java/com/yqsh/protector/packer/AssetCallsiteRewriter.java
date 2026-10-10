package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction35c;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction3rc;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction3rc;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.rewriter.DexRewriter;
import com.android.tools.smali.dexlib2.rewriter.InstructionRewriter;
import com.android.tools.smali.dexlib2.rewriter.Rewriter;
import com.android.tools.smali.dexlib2.rewriter.RewriterModule;
import com.android.tools.smali.dexlib2.rewriter.Rewriters;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** Redirects common AssetManager.open/openFd overloads to a host-owned static PAS2 bridge. */
public final class AssetCallsiteRewriter {
    private static final String ASSET_MANAGER = "Landroid/content/res/AssetManager;";
    private static final String CONTEXT = "Landroid/content/Context;";
    private static final String RESOURCES = "Landroid/content/res/Resources;";
    private static final String INPUT_STREAM = "Ljava/io/InputStream;";
    private static final String ASSET_FD = "Landroid/content/res/AssetFileDescriptor;";

    private AssetCallsiteRewriter() {
    }

    public static int rewrite(File dexFile, String bridge, String bridgeMethod) throws IOException {
        if (bridge == null || !bridge.startsWith("L") || !bridge.endsWith(";")) {
            throw new IOException("invalid assets bridge descriptor: " + bridge);
        }
        AtomicInteger changed = new AtomicInteger();
        DexBackedDexFile dex;
        try (BufferedInputStream input = new BufferedInputStream(new FileInputStream(dexFile))) {
            dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), input);
        }
        RewriterModule module = new RewriterModule() {
            @Override public Rewriter<Instruction> getInstructionRewriter(Rewriters rewriters) {
                InstructionRewriter base = new InstructionRewriter(rewriters);
                return instruction -> maybeRewrite(
                        base.rewrite(instruction), bridge, bridgeMethod, changed);
            }
        };
        var rewritten = new DexRewriter(module).getDexFileRewriter().rewrite(dex);
        DexPool pool = new DexPool(Opcodes.getDefault());
        for (ClassDef cls : rewritten.getClasses()) pool.internClass(cls);
        File temp = new File(dexFile.getParentFile(), dexFile.getName() + ".assets.tmp");
        pool.writeTo(new FileDataStore(temp));
        Files.move(temp.toPath(), dexFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        return changed.get();
    }

    private static Instruction maybeRewrite(Instruction instruction, String bridge,
                                            String bridgeMethod, AtomicInteger changed) {
        MethodReference reference;
        if (instruction instanceof Instruction35c invoke
                && invoke.getReference() instanceof MethodReference method) {
            reference = method;
            if (!isAssetAccess(reference)) return instruction;
            changed.incrementAndGet();
            return new ImmutableInstruction35c(
                    Opcode.INVOKE_STATIC,
                    invoke.getRegisterCount(), invoke.getRegisterC(), invoke.getRegisterD(),
                    invoke.getRegisterE(), invoke.getRegisterF(), invoke.getRegisterG(),
                    bridgeReference(bridge, bridgeMethod, reference));
        }
        if (instruction instanceof Instruction3rc invoke
                && invoke.getReference() instanceof MethodReference method) {
            reference = method;
            if (!isAssetAccess(reference)) return instruction;
            changed.incrementAndGet();
            return new ImmutableInstruction3rc(
                    Opcode.INVOKE_STATIC_RANGE, invoke.getStartRegister(), invoke.getRegisterCount(),
                    bridgeReference(bridge, bridgeMethod, reference));
        }
        return instruction;
    }

    static boolean isAssetAccess(MethodReference method) {
        if (isAssetManagerProvider(method)) return true;
        if (!ASSET_MANAGER.equals(method.getDefiningClass())) return false;
        List<? extends CharSequence> params = method.getParameterTypes();
        if ("openFd".equals(method.getName()) && ASSET_FD.equals(method.getReturnType())) {
            return params.size() == 1 && "Ljava/lang/String;".contentEquals(params.get(0));
        }
        if (!"open".equals(method.getName()) || !INPUT_STREAM.equals(method.getReturnType())) {
            return false;
        }
        return (params.size() == 1 && "Ljava/lang/String;".contentEquals(params.get(0))) ||
                (params.size() == 2
                && "Ljava/lang/String;".contentEquals(params.get(0))
                && "I".contentEquals(params.get(1)));
    }

    private static boolean isAssetManagerProvider(MethodReference method) {
        return "getAssets".equals(method.getName())
                && ASSET_MANAGER.equals(method.getReturnType())
                && method.getParameterTypes().isEmpty()
                && (CONTEXT.equals(method.getDefiningClass())
                || RESOURCES.equals(method.getDefiningClass()));
    }

    private static MethodReference bridgeReference(
            String bridge, String method, MethodReference original) {
        if (isAssetManagerProvider(original)) {
            return new ImmutableMethodReference(
                    bridge, "assets", List.of(original.getDefiningClass()), ASSET_MANAGER);
        }
        boolean fd = "openFd".equals(original.getName());
        List<String> params = original.getParameterTypes().size() == 1
                ? List.of(ASSET_MANAGER, "Ljava/lang/String;")
                : List.of(ASSET_MANAGER, "Ljava/lang/String;", "I");
        return new ImmutableMethodReference(
                bridge, fd ? "openFd" : method, params, fd ? ASSET_FD : INPUT_STREAM);
    }
}
