package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Predicate;

/** 方法清单独立于运行时协议；只统计实际输入 DEX，不猜测源码包名或业务含义。 */
public final class Pvm2Report {
    public static final int SCHEMA_VERSION = 2;
    private final Map<String, String> modules = new TreeMap<>();
    private final NavigableSet<String> required = new TreeSet<>();
    private final Map<String, JSONObject> methods = new TreeMap<>();
    private final Map<String, JSONObject> dexes = new TreeMap<>();
    private final Map<String, String> images = new HashMap<>();
    private String currentModule;

    Pvm2Report(File config) throws Exception {
        if (config == null) return;
        JSONObject data = new JSONObject(Files.readString(config.toPath(), StandardCharsets.UTF_8));
        if (data.getInt("schema_version") != SCHEMA_VERSION) throw new IllegalArgumentException("方法报告配置版本不兼容");
        JSONObject mapping = data.getJSONObject("modules");
        for (String dex : mapping.keySet()) modules.put(dex, mapping.getString(dex));
        for (Object item : data.getJSONArray("required")) {
            String value = (String) item;
            if (!required.add(value)) throw new IllegalArgumentException("关键方法重复：" + value);
        }
    }

    static String descriptor(MethodReference method) {
        StringBuilder value = new StringBuilder(method.getDefiningClass()).append("->")
                .append(method.getName()).append('(');
        for (CharSequence type : method.getParameterTypes()) value.append(type);
        return value.append(')').append(method.getReturnType()).toString();
    }

    static String sha256(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    void inventory(List<File> files, Predicate<String> selectedType) throws Exception {
        for (File file : files) {
            String module = modules.getOrDefault(file.getName(), "base");
            byte[] bytes = Files.readAllBytes(file.toPath());
            dexes.put(file.getName(), new JSONObject().put("module", module)
                    .put("input_sha256", sha256(bytes)));
            DexBackedDexFile dex = new DexBackedDexFile(Opcodes.getDefault(), bytes);
            for (var cls : dex.getClasses()) for (Method method : cls.getMethods()) {
                String signature = descriptor(method);
                String id = module + "\t" + signature;
                if (!selectedType.test(cls.getType()) && !required.contains(id)) continue;
                int size = 0;
                var impl = method.getImplementation();
                if (impl != null) for (var instruction : impl.getInstructions()) size += instruction.getCodeUnits() * 2;
                String reason = impl == null ? "no_code" : method.getName().startsWith("<") ? "initializer" : "not_attempted";
                String exclusion = AutoVmpPolicy.exclusionReason(cls, method);
                // 没有方法体和初始化器先按实际结构计数，避免被类级兼容规则掩盖。
                if (reason.equals("not_attempted") && exclusion != null) reason = exclusion;
                JSONObject row = new JSONObject().put("module", module).put("descriptor", signature)
                        .put("required", required.contains(id)).put("input_instruction_bytes", size)
                        .put("input_dex", file.getName()).put("transform_status", "skipped")
                        .put("reason", reason).put("artifact_verified", false)
                        .put("plaintext_policy", JSONObject.NULL);
                if (impl != null && !method.getName().startsWith("<"))
                    row.put("admission", admissionFacts(cls, method, exclusion));
                if (methods.putIfAbsent(id, row) != null) throw new IllegalArgumentException("模块中存在重复方法：" + id);
            }
        }
        for (String id : required) if (!methods.containsKey(id)) throw new IllegalArgumentException("关键方法未匹配输入 DEX：" + id);
    }

    /** 记录准入事实，不将命名启发式解释为业务分类或语义已获支持。 */
    static JSONObject admissionFacts(ClassDef owner, Method method, String exclusion) {
        var code = method.getImplementation();
        Map<String, Integer> opcodes = new TreeMap<>();
        for (var instruction : code.getInstructions())
            opcodes.merge(instruction.getOpcode().name, 1, Integer::sum);
        String parent = owner.getSuperclass();
        boolean coroutine = Set.of("Lkotlin/coroutines/jvm/internal/SuspendLambda;",
                "Lkotlin/coroutines/jvm/internal/RestrictedSuspendLambda;",
                "Lkotlin/coroutines/jvm/internal/ContinuationImpl;",
                "Lkotlin/coroutines/jvm/internal/RestrictedContinuationImpl;").contains(parent == null ? "" : parent);
        // ponytail: 仅记录直接父类；不从方法名推断协程，也不宣称已解析完整继承链。
        return new JSONObject().put("policy_exclusion", exclusion == null ? JSONObject.NULL : exclusion)
                .put("method_bridge_flag", (method.getAccessFlags() & 0x40) != 0)
                .put("method_synthetic_flag", (method.getAccessFlags() & 0x1000) != 0)
                .put("class_synthetic_flag", (owner.getAccessFlags() & 0x1000) != 0)
                .put("generated_name_rule", AutoVmpPolicy.isCompilerGeneratedBridge(owner.getType()))
                .put("direct_coroutine_base", coroutine)
                .put("register_count", code.getRegisterCount()).put("try_blocks", code.getTryBlocks().size())
                .put("opcodes", new JSONObject(opcodes));
    }

    void begin(File dex) { currentModule = modules.getOrDefault(dex.getName(), "base"); }

    boolean requiresType(String type) {
        String prefix = currentModule + "\t" + type + "->";
        String next = required.ceiling(prefix);
        return next != null && next.startsWith(prefix);
    }

    boolean requires(String internalKey) { return required.contains(id(internalKey)); }

    private String id(String internalKey) { return currentModule + "\t" + internalKey.replaceFirst("#", "->"); }

    void skipped(String key, String reason) {
        JSONObject row = methods.get(id(key));
        if (row != null) row.put("reason", reason);
    }

    void compiled(String key, byte[] image) throws Exception {
        JSONObject row = methods.get(id(key));
        if (row == null) throw new IllegalStateException("转换了未清点的方法：" + key);
        verifyPolicy(image, row.getBoolean("required"));
        row.put("transform_status", "transformed").put("reason", JSONObject.NULL)
                .put("plaintext_policy", row.getBoolean("required") ? "clear_after_use" : "bounded_cache");
        row.remove("admission");
        images.put(id(key), sha256(image));
    }

    void verifyDex(File file, int dexIndex, List<PackerMain.InsnRecord> records,
                   String bridge, String bridgeMethod) throws Exception {
        begin(file);
        byte[] bytes = Files.readAllBytes(file.toPath());
        DexBackedDexFile dex = new DexBackedDexFile(Opcodes.getDefault(), bytes);
        Map<String, Method> definitions = new HashMap<>();
        for (var cls : dex.getClasses()) for (Method method : cls.getMethods()) definitions.put(descriptor(method), method);
        Set<Integer> seen = new HashSet<>();
        for (PackerMain.InsnRecord rec : records) {
            String signature = rec.definingClass + "->" + rec.methodName + "(" + String.join("", rec.paramTypes) + ")" + rec.returnType;
            if (!seen.add(rec.methodIndex) || !signature.equals(descriptor(dex.getMethodSection().get(rec.methodIndex))))
                throw new IllegalStateException("产物方法索引错位或重复：" + signature);
            Method method = definitions.get(signature);
            if (method == null || !TrueVmpTrampoline.matches(method, dexIndex, rec.methodIndex, bridge, bridgeMethod))
                throw new IllegalStateException("产物方法不是预期完整跳板：" + signature);
            JSONObject row = methods.get(currentModule + "\t" + signature);
            row.put("final_dex_index", dexIndex).put("final_method_index", rec.methodIndex);
        }
        dexes.get(file.getName()).put("output_sha256", sha256(bytes));
    }

    /** 重新读取落盘 sidecar，认证每条记录，并与本次编译的镜像摘要逐一对照。 */
    void finish(File code, byte[] key, File output) throws Exception {
        byte[] bytes = Files.readAllBytes(code.toPath());
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        if (buffer.getShort() != 4) throw new IllegalStateException("code.bin 版本无效");
        int count = Short.toUnsignedInt(buffer.getShort());
        int[] offsets = new int[count];
        for (int i = 0; i < count; i++) offsets[i] = buffer.getInt();
        Map<String, JSONObject> keys = new HashMap<>();
        for (JSONObject row : methods.values()) if (row.has("final_method_index")) {
            String index = row.getInt("final_dex_index") + ":" + row.getInt("final_method_index");
            if (keys.put(index, row) != null) throw new IllegalStateException("产物索引重复");
        }
        for (int offset : offsets) {
            if (offset != buffer.position()) throw new IllegalStateException("code.bin 偏移不连续");
            int dexIndex = buffer.getInt();
            int methodCount = Short.toUnsignedInt(buffer.getShort());
            for (int i = 0; i < methodCount; i++) {
                int methodIndex = buffer.getInt(), plainSize = buffer.getInt(), size = buffer.getInt(), flags = buffer.getInt();
                JSONObject row = keys.remove(dexIndex + ":" + methodIndex);
                if (row == null || flags != 2 || size < 28 || size > buffer.remaining()) throw new IllegalStateException("code.bin 记录不匹配");
                byte[] nonce = new byte[12], ciphertext = new byte[size - 12];
                buffer.get(nonce).get(ciphertext);
                String id = row.getString("module") + "\t" + row.getString("descriptor");
                authenticateImage(key, nonce, ciphertext, plainSize, images.get(id), row.getBoolean("required"));
                row.put("artifact_verified", true);
            }
        }
        if (buffer.hasRemaining() || !keys.isEmpty()) throw new IllegalStateException("code.bin 多余或缺失记录");
        JSONObject report = new JSONObject().put("schema_version", SCHEMA_VERSION)
                .put("image_version", Pvm2Opcodes.VERSION).put("code_version", 4)
                .put("dexes", new JSONObject(dexes)).put("code_sha256", sha256(bytes))
                .put("methods", new JSONArray(methods.values()));
        Files.writeString(output.toPath(), report.toString(2) + "\n", StandardCharsets.UTF_8);
        for (JSONObject row : methods.values()) if (row.getBoolean("required") && !row.getBoolean("artifact_verified"))
            throw new IllegalStateException("关键方法未通过验证：" + row.getString("module") + "\t" + row.getString("descriptor") + "（" + row.optString("reason") + "）");
    }
    static void verifyPolicy(byte[] image, boolean clearAfterUse) {
        if (image.length < 19 || image[0] != 'P' || image[1] != 'V' || image[2] != 'M' || image[3] != '2'
                || image[4] != Pvm2Opcodes.VERSION || image[5] != 0 || image[18] != (clearAfterUse ? 1 : 0))
            throw new IllegalStateException("PVM2 镜像版本或明文清理策略不匹配");
    }

    static void authenticateImage(byte[] key, byte[] nonce, byte[] ciphertext, int plainSize, String digest,
                                  boolean clearAfterUse) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        byte[] plain = cipher.doFinal(ciphertext);
        try {
            if (plain.length != plainSize || !sha256(plain).equals(digest)) throw new IllegalStateException("PVM2 镜像与编译结果不匹配");
            verifyPolicy(plain, clearAfterUse);
        } finally { Arrays.fill(plain, (byte) 0); }
    }

}
