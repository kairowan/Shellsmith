package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.immutable.*;
import com.android.tools.smali.dexlib2.immutable.instruction.*;
import com.android.tools.smali.dexlib2.immutable.reference.*;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import org.json.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;

/** 使用生成的 DEX 验证通用行为，不依赖业务 APK、固定包名或新增测试框架。 */
public final class Pvm2ProtectionCheck {
    private static final String OWNER = "Lfixture/Arbitrary;";
    private static final String BRIDGE = "Lfixture/Bridge;";
    private static final String KEY = "000102030405060708090a0b0c0d0e0f";

    public static void main(String[] args) throws Exception {
        // if-ne 的相等落空边、if-eq 的相等跳转边均可继承 this 的非空事实。
        short[] equalFallthrough = {0x1033, 5, 0x106e, 0, 1, 0x000e};
        assert Pvm2Safety.check(equalFallthrough, 2, 2, false, false) == null;
        assert Pvm2Safety.check(new short[]{0x1032, 3, 0x000e, 0x106e, 0, 1, 0x000e}, 2, 2, false, false) == null;
        short[] unequalFallthrough = equalFallthrough.clone(); unequalFallthrough[0] = 0x1032;
        assert Pvm2Safety.check(unequalFallthrough, 2, 2, false, false) != null;
        assert Pvm2Safety.check(equalFallthrough, 2, 2, true, false) != null;
        assert Pvm2Safety.check(new short[]{0x1033, 6, 0x0112, 0x106e, 0, 1, 0x000e}, 2, 2, false, false) != null;
        // 首次调用可能抛 NPE，但正常边之后的控制流可以复用同一接收者。
        short[] repeated = {0x106e, 0, 1, 0x0038, 5, 0x106e, 0, 1, 0x000e};
        assert Pvm2Safety.check(repeated, 2, 2, true, false) == null;
        assert Pvm2Safety.check(repeated, 2, 2, true, true) != null;
        // 字段/数组正常边可证明对象非空，但读取结果、写入值和异常边不能继承该事实。
        for (short[] access : List.of(new short[]{0x1021}, new short[]{0x1052, 0},
                new short[]{0x1054, 0}, new short[]{0x1059, 0},
                new short[]{0x0044, 0x0201}, new short[]{0x004b, 0x0201})) {
            short[] flow = Arrays.copyOf(access, access.length + 6);
            short[] tail = {0x0238, 5, 0x106e, 0, 1, 0x000e};
            System.arraycopy(tail, 0, flow, access.length, tail.length);
            assert Pvm2Safety.check(flow, 3, 3, true, false) == null;
            flow[access.length + 4] = 0; // v0 的字段值/数组元素仍可能为空。
            assert Pvm2Safety.check(flow, 3, 3, true, false) != null;
        }
        assert Pvm2Safety.check(new short[]{0x1154, 0, 0x0238, 5, 0x106e, 0, 1, 0x000e}, 3, 3, true, false) != null;
        assert Pvm2Safety.check(new short[]{0x0146, 0x0201, 0x0238, 5, 0x106e, 0, 1, 0x000e}, 3, 3, true, false) != null;
        // 一条路径绕过解引用时，汇合点仍按未知处理。
        assert Pvm2Safety.check(new short[]{0x0238, 4, 0x1052, 0, 0x106e, 0, 1, 0x000e}, 3, 3, true, false) != null;
        // wide 写入必须清掉第二格，不能继续相信原来的非空值。
        for (short[] write : List.of(new short[]{0x0004}, new short[]{0x0005, 0},
                new short[]{0x0006, 0, 0}, new short[]{0x000b}, new short[]{0x0016, 0},
                new short[]{0x0017, 0, 0}, new short[]{0x0018, 0, 0, 0, 0}, new short[]{0x0019, 0},
                new short[]{0x0045, 0}, new short[]{0x0053, 0}, new short[]{0x0061, 0},
                new short[]{0x007d}, new short[]{0x0081}, new short[]{0x0083}, new short[]{0x0086},
                new short[]{0x009b, 0}, new short[]{0x00ab, 0}, new short[]{0x00bb}, new short[]{0x00cb})) {
            short[] flow = new short[write.length + 8];
            flow[0] = 0x011a;
            System.arraycopy(write, 0, flow, 2, write.length);
            short[] tail = {0x0238, 5, 0x106e, 0, 1, 0x000e};
            System.arraycopy(tail, 0, flow, 2 + write.length, tail.length);
            assert Pvm2Safety.check(flow, 3, 0, true, false) != null;
        }
        // lit8 的目标 v16 不能被错误解码为 v0；对象自移动和 check-cast 保留事实。
        assert Pvm2Safety.check(new short[]{0x101a, 0, 0x10d8, 0, 0x0038, 5, 0x0174, 0, 16, 0x000e}, 17, 0, true, false) != null;
        assert Pvm2Safety.check(new short[]{0x011a, 0, 0x1107, 0x011f, 0, 0x0038, 5, 0x106e, 0, 1, 0x000e}, 2, 0, true, false) == null;
        // this 寄存器在 try 前被覆盖后，catch 不能重新把它当成入口时的非空 this。
        var tryConstructor = com.android.dex.Code.Try.class.getDeclaredConstructor(int.class, int.class, int.class);
        tryConstructor.setAccessible(true);
        var caught = new com.android.dex.Code(2, 2, 1, 0,
                new short[]{0x1007, 0x001f, 0, 0x000e, 0x010d, 0x106e, 0, 0, 0x000e},
                new com.android.dex.Code.Try[]{tryConstructor.newInstance(1, 2, 0)},
                new com.android.dex.Code.CatchHandler[]{new com.android.dex.Code.CatchHandler(new int[0], new int[0], 4, 0)});
        assert Pvm2Safety.check(caught, false) != null;
        // 未改写的 this 可以沿真实抛异常边进入 catch；只有正常边建立的事实不可沿异常边传播。
        for (boolean preserved : new boolean[]{true, false}) {
            short[] instructions = {preserved ? (short)0x0000 : (short)0x1007,
                    0x001f, 0, 0x000e, 0x010d, 0x106e, 0, 0, 0x000e};
            var precise = new com.android.dex.Code(2, 2, 1, 0, instructions,
                    new com.android.dex.Code.Try[]{tryConstructor.newInstance(1, 2, 0)}, caught.getCatchHandlers());
            assert (Pvm2Safety.check(precise, false) == null) == preserved;
        }
        // 两条抛异常路径汇合，任一边覆盖 this 都必须拒绝；不抛异常的覆盖不污染 catch。
        for (boolean secondThrow : new boolean[]{false, true}) {
            short[] instructions = {0x001f, 0, 0x1007, secondThrow ? (short)0x001f : (short)0x0000,
                    0, 0x000e, 0x010d, 0x106e, 0, 0, 0x000e};
            var merged = new com.android.dex.Code(2, 2, 1, 0, instructions,
                    new com.android.dex.Code.Try[]{tryConstructor.newInstance(0, 5, 0)},
                    new com.android.dex.Code.CatchHandler[]{new com.android.dex.Code.CatchHandler(new int[0], new int[0], 6, 0)});
            assert (Pvm2Safety.check(merged, false) == null) == !secondThrow;
        }
        // instanceof 的真假边、覆盖及汇合：仅为真且关系仍有效时可证明接收者。
        assert Pvm2Safety.check(new short[]{0x1020, 0, 0x0038, 5, 0x106e, 0, 1, 0x000e}, 2, 1, true, false) == null;
        assert Pvm2Safety.check(new short[]{0x1020, 0, 0x0039, 3, 0x000e, 0x106e, 0, 1, 0x000e}, 2, 1, true, false) == null;
        assert Pvm2Safety.check(new short[]{0x1020, 0, 0x0039, 5, 0x106e, 0, 1, 0x000e}, 2, 1, true, false) != null;
        for (short write : new short[]{0x0112, 0x0012, 0x0016}) {
            short[] overwritten = write == 0x0016
                ? new short[]{0x1020, 0, write, 0, 0x0038, 5, 0x106e, 0, 1, 0x000e}
                : new short[]{0x1020, 0, write, 0x0038, 5, 0x106e, 0, 1, 0x000e};
            assert Pvm2Safety.check(overwritten, 2, 1, true, false) != null;
        }
        assert Pvm2Safety.check(new short[]{0x0238, 4, 0x1020, 0, 0x0038, 5, 0x106e, 0, 1, 0x000e}, 3, 2, true, false) != null;
        Path root = Path.of(args[0]);
        checkZeroMethodReports(root);
        checkMethodCompatibility(root);
        Path dex = Files.createDirectory(root.resolve("dex"));
        fixture(dex.resolve("classes.dex"));
        fixture(dex.resolve("classes3.dex"));
        Path config = root.resolve("config.json"), code = root.resolve("code.bin"), report = root.resolve("report.json");
        String required = "feature_rules\t" + OWNER + "->value(I)I";
        JSONObject selection = new JSONObject().put("schema_version", 2)
                .put("modules", new JSONObject().put("classes.dex", "base").put("classes3.dex", "feature_rules"))
                .put("required", new JSONArray(List.of(required)));
        Files.writeString(config, selection.toString());
        run(dex, config, code, report, true);
        JSONObject result = new JSONObject(Files.readString(report));
        assert result.getInt("schema_version") == 2;
        assert result.getJSONObject("dexes").getJSONObject("classes3.dex").getString("module").equals("feature_rules");
        int verified = 0, mandatory = 0, skipped = 0, excluded = 0;
        for (Object value : result.getJSONArray("methods")) {
            JSONObject row = (JSONObject) value;
            if (row.getBoolean("artifact_verified")) {
                verified++;
                assert row.getString("plaintext_policy").equals(row.getBoolean("required") ? "clear_after_use" : "bounded_cache");
                assert row.getInt("final_dex_index") == (row.getString("module").equals("base") ? 0 : 2);
                if (row.getBoolean("required")) { mandatory++; assert row.getString("descriptor").endsWith("value(I)I"); }
            } else {
                assert row.isNull("plaintext_policy"); skipped++;
                if (row.getString("descriptor").startsWith("Lfixture/MainActivity;")) {
                    assert row.getString("reason").equals("ui_runtime_glue"); excluded++;
                } else assert row.getString("reason").equals("no_code");
            }
        }
        assert verified == 4 && mandatory == 1 && skipped == 4 && excluded == 2;
        var finalDex = new DexBackedDexFile(Opcodes.getDefault(), Files.readAllBytes(dex.resolve("classes3.dex")));
        for (var cls : finalDex.getClasses()) for (var method : cls.getMethods()) {
            if (method.getImplementation() == null) continue;
            if (cls.getType().equals("Lfixture/MainActivity;")) {
                assert !TrueVmpTrampoline.matches(method, 2, finalDex.getMethodSection().indexOf(method), BRIDGE, "interpret");
                continue;
            }
            int index = finalDex.getMethodSection().indexOf(method);
            assert TrueVmpTrampoline.matches(method, 2, index, BRIDGE, "interpret");
            assert !TrueVmpTrampoline.matches(method, 1, index, BRIDGE, "interpret");
            var instructions = new ArrayList<com.android.tools.smali.dexlib2.iface.instruction.Instruction>();
            method.getImplementation().getInstructions().forEach(instructions::add);
            instructions.set(instructions.size() - 1, new ImmutableInstruction10x(Opcode.NOP));
            var changed = new ImmutableMethod(method.getDefiningClass(), method.getName(), method.getParameters(), method.getReturnType(), method.getAccessFlags(), method.getAnnotations(), method.getHiddenApiRestrictions(), new ImmutableMethodImplementation(method.getImplementation().getRegisterCount(), instructions, List.of(), List.of()));
            assert !TrueVmpTrampoline.matches(changed, 2, index, BRIDGE, "interpret");
        }
        // 精确清单可独立选择，不要求使用类前缀，也不能误选同名重载。
        fixture(dex.resolve("classes.dex")); fixture(dex.resolve("classes3.dex"));
        run(dex, config, code, report, false);
        result = new JSONObject(Files.readString(report));
        assert result.getJSONArray("methods").length() == 1;
        assert result.getJSONArray("methods").getJSONObject(0).getBoolean("artifact_verified");
        // 清单中的模块和方法都必须实际存在，声明无法转换的方法必须失败。
        for (String invalid : List.of("missing\t" + OWNER + "->value(I)I", "base\t" + OWNER + "->missing()I", "base\t" + OWNER + "->nativeCall()I")) {
            fixture(dex.resolve("classes.dex")); fixture(dex.resolve("classes3.dex"));
            selection.put("required", new JSONArray(List.of(invalid)));
            Files.writeString(config, selection.toString());
            try { run(dex, config, code, report, false); throw new AssertionError("未拒绝无效关键方法"); }
            catch (InvocationTargetException expected) { assert expected.getCause() instanceof IllegalArgumentException || expected.getCause() instanceof IllegalStateException; }
        }
        byte[] key = HexFormat.of().parseHex(KEY);
        var input = new com.android.dex.Code(1, 0, 0, 0, new short[]{0x0012, 0x000f},
                new com.android.dex.Code.Try[0], new com.android.dex.Code.CatchHandler[0]);
        byte[] plain = Pvm2Compiler.tryCompile(null, input, "I", true, null, true).image;
        assert plain != null && plain[18] == 1;
        Pvm2Report.verifyPolicy(plain, true);
        for (int fault = 0; fault < 4; fault++) {
            byte[] broken = plain.clone();
            if (fault == 0) broken[18] = 0;
            if (fault == 1) broken[18] = 2;
            if (fault == 2) broken[4] = 6;
            if (fault == 3) broken = Arrays.copyOf(broken, 18);
            try { Pvm2Report.verifyPolicy(broken, true); throw new AssertionError("未拒绝错误清理策略"); }
            catch (IllegalStateException expected) { }
        }
        byte[] encrypted = com.yqsh.protector.packer.util.CryptoUtils.aesGcmEncrypt(key, plain);
        byte[] nonce = Arrays.copyOf(encrypted, 12), ciphertext = Arrays.copyOfRange(encrypted, 12, encrypted.length);
        Pvm2Report.authenticateImage(key, nonce, ciphertext, plain.length, Pvm2Report.sha256(plain), true);
        try { Pvm2Report.authenticateImage(key, nonce, ciphertext, plain.length, "wrong", true); throw new AssertionError("未拒绝错误镜像"); }
        catch (IllegalStateException expected) { }
        try { Pvm2Report.authenticateImage(key, nonce, ciphertext, plain.length, Pvm2Report.sha256(plain), false); throw new AssertionError("未拒绝认证后的策略错配"); }
        catch (IllegalStateException expected) { }
        ciphertext[18] ^= 1; // 试图把必保策略改成普通缓存，GCM 必须拒绝。
        try { Pvm2Report.authenticateImage(key, nonce, ciphertext, plain.length, Pvm2Report.sha256(plain), true); throw new AssertionError("未拒绝篡改密文"); }
        catch (javax.crypto.AEADBadTagException expected) { }
        System.out.println("PVM2 通用检查通过：重载、精确选择、跨模块、非连续 DEX、完整跳板篡改、跳过与关键方法失败关闭");
    }

    private static void run(Path dex, Path config, Path code, Path report, boolean prefixes) throws Exception {
        run(dex, config, code, report, prefixes ? "Lfixture/" : null);
    }

    private static void run(Path dex, Path config, Path code, Path report, String prefix) throws Exception {
        List<String> args = new ArrayList<>(List.of("pvm2-transform", "--dex-dir", dex.toString(), "--code-out", code.toString(), "--insn-key-hex", KEY, "--package-name", "fixture.unrelated", "--vm-bridge", BRIDGE, "--report-config", config.toString(), "--report-out", report.toString(), "--no-payment-auto-vmp", "--no-industry-auto-vmp"));
        if (prefix != null) args.addAll(List.of("--true-vmp-prefix", prefix));
        Method method = PackerMain.class.getDeclaredMethod("runPvm2TransformCli", String[].class);
        method.setAccessible(true);
        method.invoke(null, (Object) args.toArray(String[]::new));
    }

    private static void checkZeroMethodReports(Path root) throws Exception {
        // 三种真实零转换原因：无 DEX 方法体、类级兼容排除、编译器寄存器上限。
        for (String kind : List.of("native", "ui", "registers")) {
            Path work = Files.createDirectory(root.resolve("zero-" + kind));
            Path dex = Files.createDirectory(work.resolve("dex"));
            String owner = kind.equals("ui") ? "Lfixture/MainActivity;" : "Lfixture/Rules;";
            List<ImmutableMethod> methods = new ArrayList<>();
            methods.add(new ImmutableMethod(owner, "nativeCall", List.of(), "I", 0x109, Set.of(), Set.of(), null));
            methods.add(new ImmutableMethod(owner, "<clinit>", List.of(), "V", 0x10008, Set.of(), Set.of(),
                    new ImmutableMethodImplementation(0, List.of(new ImmutableInstruction10x(Opcode.RETURN_VOID)), List.of(), List.of())));
            if (!kind.equals("native")) methods.add(new ImmutableMethod(owner, "value", List.of(), "I", kind.equals("ui") ? 1 : 9, Set.of(), Set.of(),
                    new ImmutableMethodImplementation(kind.equals("registers") ? 512 : 1,
                            List.of(new ImmutableInstruction31i(Opcode.CONST, 0, 42), new ImmutableInstruction11x(Opcode.RETURN, 0)), List.of(), List.of())));
            DexPool pool = new DexPool(Opcodes.getDefault());
            pool.internClass(new ImmutableClassDef(owner, 1, kind.equals("ui") ? "Landroid/app/Activity;" : "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), methods));
            FileDataStore store = new FileDataStore(dex.resolve("classes.dex").toFile());
            try { pool.writeTo(store); } finally { store.close(); }
            Path config = work.resolve("config.json"), report = work.resolve("report.json");
            Files.writeString(config, new JSONObject().put("schema_version", 2)
                    .put("modules", new JSONObject().put("classes.dex", "base")).put("required", new JSONArray()).toString());
            try {
                run(dex, config, work.resolve("code.bin"), report, "Lfixture/");
                throw new AssertionError("零方法转换被误判为成功");
            } catch (InvocationTargetException expected) {
                assert expected.getCause().getMessage().contains("selected zero methods");
            }
            JSONObject result = new JSONObject(Files.readString(report));
            Map<String, Integer> reasons = new TreeMap<>();
            for (Object value : result.getJSONArray("methods")) {
                JSONObject row = (JSONObject) value;
                assert row.getString("transform_status").equals("skipped") && !row.getBoolean("artifact_verified");
                reasons.merge(row.getString("reason"), 1, Integer::sum);
            }
            assert reasons.get("no_code") == 1 && reasons.get("initializer") == 1 : reasons;
            if (kind.equals("ui")) assert reasons.get("ui_runtime_glue") == 1 : reasons;
            if (kind.equals("registers")) assert reasons.get("too many regs") == 1 : reasons;
            System.out.println("零方法失败报告通过：" + kind + " " + reasons);
        }
    }

    private static ImmutableMethod calculation(String owner, String name, int flags) {
        boolean isStatic = (flags & 8) != 0;
        return new ImmutableMethod(owner, name, List.of(new ImmutableMethodParameter("I", Set.of(), null)),
                "I", flags, Set.of(), Set.of(), new ImmutableMethodImplementation(isStatic ? 2 : 3,
                List.of(new ImmutableInstruction22b(Opcode.ADD_INT_LIT8, 0, isStatic ? 1 : 2, 7),
                        new ImmutableInstruction11x(Opcode.RETURN, 0)), List.of(), List.of()));
    }

    private static ImmutableClassDef calculationOwner(String type, String parent, List<String> interfaces, List<ImmutableMethod> methods) {
        return new ImmutableClassDef(type, 1, parent, interfaces, null, Set.of(), List.of(), methods);
    }

    private static void writeClasses(Path path, List<ImmutableClassDef> classes) throws Exception {
        DexPool pool = new DexPool(Opcodes.getDefault());
        for (var cls : classes) pool.internClass(cls);
        FileDataStore store = new FileDataStore(path.toFile());
        try { pool.writeTo(store); } finally { store.close(); }
    }

    private static void checkMethodCompatibility(Path root) throws Exception {
        for (String reason : List.of("ui_runtime_glue", "data_resource_runtime_glue", "compiler_generated_bridge", "playback_compatibility"))
            assert Pvm2Admission.classify(reason) == Pvm2Admission.SkipReason.compatibility;
        // 相同计算体不应因 UI、数据、资源、设备或媒体命名而整类消失。
        for (String type : List.of("Lfixture/ui/Rules;", "Lfixture/navigation/Rules;", "Lfixture/MainActivity;",
                "Lfixture/adapter/Rules;", "Lfixture/QuoteView;", "Lfixture/RouteNavigator;",
                "Lfixture/data/Rules;", "Lfixture/QuoteRepository;", "Lfixture/PriceViewModel;",
                "Lfixture/dao/Rules;", "Lfixture/resource/Rules;", "Lfixture/helper/Rules;",
                "Lfixture/hepler/Rules;", "Lfixture/device/ble/Rules;", "Lfixture/PermissionManager;",
                "Lfixture/audio/Rules;", "Lfixture/TrackRules;", "Lfixture/PlainRules;")) {
            for (int flags : List.of(1, 2, 9)) {
                var method = calculation(type, "calculate", flags);
                var cls = calculationOwner(type, "Ljava/lang/Object;", List.of(), List.of(method));
                assert AutoVmpPolicy.exclusionReason(cls, method) == null : type;
            }
        }
        String type = "Lfixture/ui/Rules;";
        var publicMethod = calculation(type, "calculate", 1);
        var privateMethod = calculation(type, "local", 2);
        var staticMethod = calculation(type, "utility", 9);
        for (String parent : List.of("Landroid/app/Activity;", "Lfixture/BaseActivity;", "Lexternal/Unknown;")) {
            var cls = calculationOwner(type, parent, List.of(), List.of());
            assert AutoVmpPolicy.exclusionReason(cls, publicMethod).equals("ui_runtime_glue");
            assert AutoVmpPolicy.exclusionReason(cls, privateMethod) == null;
            assert AutoVmpPolicy.exclusionReason(cls, staticMethod) == null;
        }
        var callback = calculationOwner(type, "Ljava/lang/Object;", List.of("Lexternal/Callback;"), List.of());
        assert AutoVmpPolicy.exclusionReason(callback, publicMethod).equals("ui_runtime_glue");
        var plain = calculationOwner(type, "Ljava/lang/Object;", List.of(), List.of());
        for (int flags : List.of(0x29, 0x20009, 0x49, 0x1009))
            assert AutoVmpPolicy.exclusionReason(plain, calculation(type, "calculate", flags)) != null;
        for (String generated : List.of("Lfixture/Rules$$ExternalSyntheticLambda0;", "Lfixture/Rules$1;"))
            assert AutoVmpPolicy.exclusionReason(calculationOwner(generated, "Ljava/lang/Object;", List.of(), List.of()),
                    calculation(generated, "calculate", 9)).equals("compiler_generated_bridge");
        // 混淆类仍直接继承已知框架类型时，生命周期和接口回调保持原执行方式。
        var obfuscated = calculation("Lfixture/a;", "callback", 1);
        assert AutoVmpPolicy.exclusionReason(calculationOwner("Lfixture/a;", "Landroid/app/Activity;", List.of(), List.of()), obfuscated).equals("ui_runtime_glue");
        assert AutoVmpPolicy.exclusionReason(calculationOwner("Lfixture/a;", "Ljava/lang/Object;", List.of("Landroid/view/View$OnClickListener;"), List.of()), obfuscated).equals("ui_runtime_glue");
        // 原始 opcode、对象类型、字段/数组访问、调用和锁都不能借纯计算规则放行。
        var field = new ImmutableFieldReference(type, "state", "I");
        var call = new ImmutableMethodReference(type, "external", List.of(), "I");
        for (var instruction : List.of(new ImmutableInstruction12x(Opcode.MOVE_OBJECT, 0, 1),
                new ImmutableInstruction21c(Opcode.SGET, 0, field), new ImmutableInstruction22c(Opcode.IGET, 0, 1, field),
                new ImmutableInstruction23x(Opcode.AGET, 0, 1, 2),
                new ImmutableInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, call),
                new ImmutableInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 1, 0, 0, 0, 0, call),
                new ImmutableInstruction11x(Opcode.MONITOR_ENTER, 1),
                new ImmutableInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference(type)))) {
            var method = new ImmutableMethod(type, "stateful", List.of(), "I", 9, Set.of(), Set.of(),
                    new ImmutableMethodImplementation(3, List.of(instruction, new ImmutableInstruction11x(Opcode.RETURN, 0)), List.of(), List.of()));
            assert AutoVmpPolicy.exclusionReason(plain, method).equals("ui_runtime_glue") : instruction.getOpcode();
        }
        for (String reference : List.of("Ljava/lang/Object;", "[I")) {
            var method = new ImmutableMethod(type, "objectArgument", List.of(new ImmutableMethodParameter(reference, Set.of(), null)),
                    "I", 9, Set.of(), Set.of(), staticMethod.getImplementation());
            assert AutoVmpPolicy.exclusionReason(plain, method).equals("ui_runtime_glue");
        }

        Path work = Files.createDirectory(root.resolve("method-compatibility"));
        Path dex = Files.createDirectory(work.resolve("dex"));
        Path config = work.resolve("config.json"), code = work.resolve("code.bin"), report = work.resolve("report.json");
        JSONObject selection = new JSONObject().put("schema_version", 2)
                .put("modules", new JSONObject().put("classes.dex", "base")).put("required", new JSONArray());
        Files.writeString(config, selection.toString());
        List<ImmutableClassDef> classes = new ArrayList<>();
        for (String owner : List.of("Lfixture/ui/PriceRules;", "Lfixture/data/BalanceRepository;", "Lfixture/player/TrackRules;")) {
            List<ImmutableMethod> methods = new ArrayList<>();
            methods.add(new ImmutableMethod(owner, "<clinit>", List.of(), "V", 0x10008, Set.of(), Set.of(),
                    new ImmutableMethodImplementation(0, List.of(new ImmutableInstruction10x(Opcode.RETURN_VOID)), List.of(), List.of())));
            for (int i = 0; i < 6; i++) methods.add(calculation(owner, "calculate" + i, List.of(1, 2, 9).get(i % 3)));
            classes.add(calculationOwner(owner, "Ljava/lang/Object;", List.of(), methods));
        }
        writeClasses(dex.resolve("classes.dex"), classes);
        run(dex, config, code, report, "Lfixture/");
        JSONObject result = new JSONObject(Files.readString(report));
        assert result.getJSONArray("methods").length() == 21;
        int verified = 0, initializers = 0;
        for (Object value : result.getJSONArray("methods")) {
            JSONObject row = (JSONObject) value;
            if (row.getBoolean("artifact_verified")) verified++;
            else { assert row.getString("reason").equals("initializer"); initializers++; }
        }
        assert verified == 18 && initializers == 3;
        // 精确必保清单也必须服从同一兼容判断；声明回调不会使其自动变得安全。
        String activity = "Lfixture/ui/ScreenActivity;";
        var sensitive = calculationOwner(activity, "Landroid/app/Activity;", List.of(),
                List.of(calculation(activity, "callback", 1), calculation(activity, "local", 2)));
        writeClasses(dex.resolve("classes.dex"), List.of(sensitive));
        var captured = new java.io.ByteArrayOutputStream();
        var previous = System.out;
        try (var stream = new java.io.PrintStream(captured, true, java.nio.charset.StandardCharsets.UTF_8)) {
            System.setOut(stream);
            run(dex, config, code, report, "Lfixture/");
        } finally { System.setOut(previous); }
        assert captured.toString(java.nio.charset.StandardCharsets.UTF_8)
                .contains("candidates=1 attempted=1 success=1 fallback=0 rate=100.0%");
        var mixed = new JSONObject(Files.readString(report)).getJSONArray("methods");
        assert mixed.length() == 2;
        int kept = 0, protectedCount = 0;
        for (Object value : mixed) {
            var row = (JSONObject) value;
            if (row.getBoolean("artifact_verified")) protectedCount++;
            else { assert row.getString("reason").equals("ui_runtime_glue"); kept++; }
        }
        assert kept == 1 && protectedCount == 1 : "转换成功率不能代替完整范围覆盖率";
        for (boolean safe : List.of(true, false)) {
            writeClasses(dex.resolve("classes.dex"), List.of(sensitive));
            selection.put("required", new JSONArray(List.of("base\t" + activity + "->" + (safe ? "local" : "callback") + "(I)I")));
            Files.writeString(config, selection.toString());
            try {
                run(dex, config, code, report, false);
                assert safe : "回调被精确清单绕过兼容检查";
            } catch (InvocationTargetException failure) {
                assert !safe && failure.getCause().getMessage().contains("关键方法未通过验证");
                JSONObject row = new JSONObject(Files.readString(report)).getJSONArray("methods").getJSONObject(0);
                assert !row.getBoolean("artifact_verified") && row.getString("reason").equals("ui_runtime_glue");
            }
        }
        System.out.println("方法级兼容检查通过：通用命名、独立计算、回调保留、必保约束、3 类 21 方法中的 18 个计算方法转换");
    }

    private static void fixture(Path path) throws Exception {
        List<ImmutableMethod> methods = new ArrayList<>();
        for (boolean parameter : List.of(false, true)) {
            var parameters = parameter ? List.of(new ImmutableMethodParameter("I", Set.of(), null)) : List.<ImmutableMethodParameter>of();
            methods.add(new ImmutableMethod(OWNER, "value", parameters, "I", 9, Set.of(), Set.of(), new ImmutableMethodImplementation(parameter ? 2 : 1, List.of(new ImmutableInstruction31i(Opcode.CONST, 0, 123456), new ImmutableInstruction11x(Opcode.RETURN, 0)), List.of(), List.of())));
        }
        methods.add(new ImmutableMethod(OWNER, "nativeCall", List.of(), "I", 0x109, Set.of(), Set.of(), null));
        DexPool pool = new DexPool(Opcodes.getDefault());
        pool.internClass(new ImmutableClassDef(OWNER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), methods));
        String excluded = "Lfixture/MainActivity;";
        var unchanged = new ImmutableMethod(excluded, "value", List.of(), "I", 1, Set.of(), Set.of(),
                new ImmutableMethodImplementation(1, List.of(new ImmutableInstruction31i(Opcode.CONST, 0, 42),
                        new ImmutableInstruction11x(Opcode.RETURN, 0)), List.of(), List.of()));
        pool.internClass(new ImmutableClassDef(excluded, 1, "Landroid/app/Activity;", List.of(), null, Set.of(), List.of(), List.of(unchanged)));
        FileDataStore store = new FileDataStore(path.toFile());
        try { pool.writeTo(store); } finally { store.close(); }
    }
}
