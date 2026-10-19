package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import org.json.JSONArray;
import org.json.JSONObject;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.zip.ZipFile;

/** 对授权产物复现公开包内材料的恢复边界；不接受或输出签名密码/构建密钥。 */
public final class ApkRecoveryCheck {
    private static ByteBuffer buffer(byte[] data) { return ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN); }
    private static byte[] take(ByteBuffer b, int n) {
        if (n < 0 || n > b.remaining()) throw new IllegalArgumentException("载荷长度无效");
        byte[] data = new byte[n]; b.get(data); return data;
    }
    private static int u16(ByteBuffer b) { return Short.toUnsignedInt(b.getShort()); }
    private static String hash(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }
    private static byte[] derive(byte[] salt, byte[] input, byte[] info, int size) throws Exception {
        if (size < 1 || size > 32) throw new IllegalArgumentException("仅支持单块 HKDF 输出");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(input);
        mac.init(new SecretKeySpec(prk, "HmacSHA256")); mac.update(info); mac.update((byte) 1);
        return Arrays.copyOf(mac.doFinal(), size);
    }
    private static byte[] decrypt(byte[] key, byte[] nonce, byte[] data, boolean aes) throws Exception {
        Cipher cipher = Cipher.getInstance(aes ? "AES/GCM/NoPadding" : "ChaCha20-Poly1305");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, aes ? "AES" : "ChaCha20"),
                aes ? new GCMParameterSpec(128, nonce) : new IvParameterSpec(nonce));
        return cipher.doFinal(data);
    }

    /** 白盒成本检查：复用已公开的指令长度/寄存器布局，反解每包的置换表。 */
    private static byte[] canonicalCode(byte[] image) throws Exception {
        ByteBuffer b = buffer(image);
        if (image.length < 19 || b.getInt() != 0x324d5650) throw new IllegalArgumentException("VM 镜像无效");
        int version = u16(b);
        if (version < 7 || version > 9) throw new IllegalArgumentException("恢复检查不支持该 VM 版本；不能视为防护通过");
        int registers = u16((ByteBuffer) b.position(6));
        b.position(10); int handlers = u16(b), size = u16(b);
        b.position(16); int strings = u16(b); b.get();
        for (int i = 0; i < strings; i++) take(b, u16(b));
        for (int i = 0; i < 3; i++) take(b, u16(b) * 2);
        byte[] forward = take(b, Byte.toUnsignedInt(b.get())), inverse = new byte[256];
        Arrays.fill(inverse, (byte) -1);
        for (int i = 0; i < forward.length; i++) {
            int wire = Byte.toUnsignedInt(forward[i]);
            if (inverse[wire] != -1) throw new IllegalArgumentException("操作码映射重复");
            inverse[wire] = (byte) i;
        }
        b.get(); int immediateKey = b.getInt();
        byte[] mapping = take(b, Byte.toUnsignedInt(b.get())), reverse = new byte[registers];
        if (mapping.length != registers) throw new IllegalArgumentException("寄存器映射长度错误");
        Arrays.fill(reverse, (byte) -1);
        for (int i = 0; i < registers; i++) {
            int slot = Byte.toUnsignedInt(mapping[i]);
            if (slot >= registers || reverse[slot] != -1) throw new IllegalArgumentException("寄存器映射无效");
            reverse[slot] = (byte) i;
        }
        if (version >= 8) take(b, Byte.toUnsignedInt(b.get()));
        take(b, handlers * 10);
        byte[] code = take(b, size);
        if (b.hasRemaining()) throw new IllegalArgumentException("VM 镜像尾部残留");
        var remap = Pvm2Morph.class.getDeclaredMethod("remapRegisters", byte[].class, int.class, int.class, byte[].class);
        remap.setAccessible(true);
        for (int pc = 0; pc < code.length;) {
            int canonical = inverse[Byte.toUnsignedInt(code[pc])];
            if (canonical < 0) throw new IllegalArgumentException("未知操作码");
            code[pc] = (byte) canonical;
            int length = Pvm2Morph.insnSize(code, pc);
            if (pc + length > code.length) throw new IllegalArgumentException("截断的虚拟指令");
            remap.invoke(null, code, pc, canonical, reverse);
            if (canonical == Pvm2Opcodes.OP_CONST || canonical == Pvm2Opcodes.OP_CONST_WIDE) {
                ByteBuffer value = buffer(code);
                value.putInt(pc + 2, value.getInt(pc + 2) ^ immediateKey);
                if (canonical == Pvm2Opcodes.OP_CONST_WIDE) value.putInt(pc + 6, value.getInt(pc + 6) ^ immediateKey);
            }
            pc += length;
        }
        return code;
    }

    // ponytail: 仅识别条件反转试验的有限语法；复杂程序需完整控制流语义分析。
    private static int branchResult(byte[] code, int pc) {
        int[] registers = new int[3];
        for (int steps = 0; steps < code.length; steps++) {
            switch (code[pc]) {
                case Pvm2Opcodes.OP_CONST:
                    registers[code[pc + 1]] = buffer(code).getInt(pc + 2); pc += 6; break;
                case Pvm2Opcodes.OP_GOTO:
                    pc += 3 + buffer(code).getShort(pc + 1); break;
                case Pvm2Opcodes.OP_RETURN:
                    return registers[code[pc + 1]];
                default: throw new IllegalArgumentException("结构试验包含未支持的路径");
            }
        }
        throw new IllegalArgumentException("结构试验路径未终止");
    }

    private static void selfTest() throws Exception {
        byte[] input = new byte[22]; Arrays.fill(input, (byte) 0x0b);
        byte[] key = derive(HexFormat.of().parseHex("000102030405060708090a0b0c"), input,
                HexFormat.of().parseHex("f0f1f2f3f4f5f6f7f8f9"), 32);
        if (!HexFormat.of().formatHex(key).equals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"))
            throw new AssertionError("HKDF 与 RFC 5869 测试向量不一致");
        var code = new com.android.dex.Code(1, 0, 0, 0, new short[]{0x0013, 0x1234, 0x000f},
                new com.android.dex.Code.Try[0], new com.android.dex.Code.CatchHandler[0]);
        byte[] expected = {1, 0, 0x34, 0x12, 0, 0, 11, 0};
        for (int isa = 0; isa < 3; isa++) for (int build = 0; build < 20; build++) {
            byte[] image = Pvm2Compiler.tryCompile(null, code, "I", true,
                    Pvm2Morph.fromIsa(isa, new java.security.SecureRandom()), true).image;
            if (!Arrays.equals(canonicalCode(image), expected)) throw new AssertionError("随机映射未还原为预期指令");
            byte[] unsupported = image.clone(); unsupported[4] = 10;
            try { canonicalCode(unsupported); throw new AssertionError("未拒绝未知镜像版本"); }
            catch (IllegalArgumentException expectedFailure) { }
            // 此无常量池样本的前两个操作码映射位于 26、27 字节。
            image[27] = image[26];
            try { canonicalCode(image); throw new AssertionError("未拒绝重复映射"); }
            catch (IllegalArgumentException expectedFailure) { }
        }
        System.out.println("恢复检查自检通过：标准 HKDF 向量、三种 ISA 各 20 次随机映射、重复映射拒绝");
        for (int isa = 0; isa < 3; isa++) for (int condition = 0; condition < 6; condition++)
            for (int build = 0; build < 5; build++) for (boolean inverted : new boolean[]{false, true}) {
                byte[] image = Pvm2Compiler.tryCompile(null, Pvm2RuntimeImages.branchInput(condition, inverted),
                        "I", true, Pvm2Morph.fromIsa(isa, new java.security.SecureRandom()), true, new String[]{"I", "I"}).image;
                byte[] canonical = canonicalCode(image);
                if (canonical[0] != Pvm2Opcodes.OP_IF_CMP || canonical[2] != 1 || canonical[3] != 2)
                    throw new AssertionError("比较输入发生变化");
                int yes = branchResult(canonical, 6 + buffer(canonical).getShort(4));
                int no = branchResult(canonical, 6);
                int normalized = canonical[1];
                if (yes == 0 && no == 1) normalized ^= 1;
                else if (yes != 1 || no != 0) throw new AssertionError("返回路径无法恢复");
                if (normalized != condition) throw new AssertionError("未恢复原比较关系");
            }
        System.out.println("结构试验恢复检查：180 个镜像仍可复用分支规范化；不作为抗还原提升启用");
    }

    private static JSONObject recoverNative(Path apk, Path root, byte[] cert, byte[] ikm) throws Exception {
        JSONObject restored = new JSONObject();
        try (ZipFile zip = new ZipFile(apk.toFile())) {
            var entry = zip.getEntry("assets/protector/mocika-sokeys.bin");
            if (entry == null) return restored;
            if (entry.getSize() < 32 || entry.getSize() > 1024 * 1024) throw new IllegalArgumentException("SO 密钥表长度无效");
            ByteBuffer table = buffer(zip.getInputStream(entry).readAllBytes());
            if (!Arrays.equals(take(table, 4), new byte[]{'P','S','O','2'})) throw new IllegalArgumentException("仅检查 PSO2");
            byte[] key = derive(cert, ikm, "mocika-shield/native-so/v1".getBytes(StandardCharsets.UTF_8), 16);
            ByteBuffer keys = buffer(decrypt(key, take(table, 12), take(table, table.remaining()), true));
            int count = keys.getInt();
            if (count < 1 || count > 10000) throw new IllegalArgumentException("SO 条目数量无效");
            Map<String, byte[]> mapping = new HashMap<>();
            for (int i = 0; i < count; i++) {
                String name = new String(take(keys, u16(keys)), StandardCharsets.UTF_8);
                if (!name.matches("[A-Za-z0-9_.-]+\\.so") || mapping.put(name, take(keys, 16)) != null)
                    throw new IllegalArgumentException("SO 名称无效或重复");
            }
            if (keys.hasRemaining()) throw new IllegalArgumentException("SO 密钥表尾部残留");
            var ranges = BusinessSoProtector.class.getDeclaredMethod("readFunctionRanges", java.io.File.class);
            ranges.setAccessible(true);
            for (var item : java.util.Collections.list(zip.entries())) {
                String name = item.getName(), basename = name.substring(name.lastIndexOf('/') + 1);
                if (!name.startsWith("lib/") || !mapping.containsKey(basename)) continue;
                if (!name.matches("lib/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+\\.so") || item.getSize() > 256L * 1024 * 1024)
                    throw new IllegalArgumentException("SO 路径或长度无效");
                Path file = root.resolve(name); Files.createDirectories(file.getParent());
                if (Files.exists(file)) throw new IllegalArgumentException("重复 SO 文件");
                byte[] bytes = zip.getInputStream(item).readAllBytes(); Files.write(file, bytes);
                for (Object range : (java.util.List<?>) ranges.invoke(null, file.toFile())) {
                    var offset = range.getClass().getDeclaredField("offset"); offset.setAccessible(true);
                    var size = range.getClass().getDeclaredField("size"); size.setAccessible(true);
                    int start = Math.toIntExact(offset.getLong(range)), length = size.getInt(range);
                    byte[] plain = com.yqsh.protector.packer.util.CryptoUtils.rc4Crypt(mapping.get(basename), Arrays.copyOfRange(bytes, start, start + length));
                    System.arraycopy(plain, 0, bytes, start, length); Arrays.fill(plain, (byte) 0);
                }
                Files.write(file, bytes); restored.put(name, hash(bytes));
            }
            for (byte[] value : mapping.values()) Arrays.fill(value, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
        return restored;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--self-test")) { selfTest(); return; }
        if (args.length < 3 || args.length > 4)
            throw new IllegalArgumentException("用法：APK 新输出目录 zstd路径 [产物报告]");
        long begin = System.nanoTime();
        Path apk = Path.of(args[0]), root = Path.of(args[1]);
        Files.createDirectory(root); // 已有目录不覆盖，也不允许恢复项越界。
        byte[] dex;
        try (ZipFile zip = new ZipFile(apk.toFile())) {
            if (zip.getEntry("classes.dex").getSize() > 512L * 1024 * 1024)
                throw new IllegalArgumentException("APK DEX 过大");
            dex = zip.getInputStream(zip.getEntry("classes.dex")).readAllBytes();
        }
        int payload = -1;
        for (int i = 0; i + 12 <= dex.length; i++) {
            if (dex[i] == 'M' && dex[i + 1] == 'S' && dex[i + 2] == 'H' && dex[i + 3] == 'D'
                    && buffer(dex).getInt(i + 4) == dex.length - i - 8
                    && dex[i + 8] == 'D' && dex[i + 9] == 'E' && dex[i + 10] == 'X' && dex[i + 11] == 'B') {
                if (payload >= 0) throw new IllegalArgumentException("多个 MSHD 载荷");
                payload = i + 8;
            }
        }
        if (payload < 0) throw new IllegalArgumentException("未找到 DEXB 载荷");
        ByteBuffer b = buffer(Arrays.copyOfRange(dex, payload, dex.length));
        b.position(4);
        if (b.getInt() != 6) throw new IllegalArgumentException("仅检查 DEXB v6");
        int count = b.getInt(), layers = b.getInt();
        if (count < 1 || count > 10000 || layers < 1 || layers > 3) throw new IllegalArgumentException("头部数量无效");
        byte[] cert = take(b, Byte.toUnsignedInt(b.get())), build = take(b, 16), wrapNonce = take(b, 12);
        byte[] wrapped = take(b, u16(b)), nonce = take(b, 12);
        byte[] ikm = decrypt(derive(build, cert, "mocika-shield/dexb/v6/envelope".getBytes(StandardCharsets.UTF_8), 32), wrapNonce, wrapped, false);
        ByteBuffer plain = buffer(decrypt(derive(nonce, ikm, cert, 32), nonce, take(b, b.remaining()), false));
        String[] names = new String[count]; int[] sizes = new int[count], originals = new int[count];
        for (int i = 0; i < count; i++) {
            names[i] = new String(take(plain, Byte.toUnsignedInt(plain.get())), StandardCharsets.UTF_8);
            if (!names[i].matches("[A-Za-z0-9_.-]+") || names[i].equals("..")) throw new IllegalArgumentException("恢复文件名无效");
            sizes[i] = plain.getInt(); originals[i] = plain.getInt();
            if (originals[i] < 0 || originals[i] > 256 * 1024 * 1024) throw new IllegalArgumentException("恢复文件过大");
        }
        JSONObject hashes = new JSONObject();
        for (int i = 0; i < count; i++) {
            Path file = root.resolve(names[i]);
            if (Files.exists(file)) throw new IllegalArgumentException("恢复项重名");
            byte[] value = take(plain, sizes[i]);
            for (int layer = 0; layer < layers; layer++) {
                Path compressed = root.resolve(".compressed"), unpacked = root.resolve(".unpacked");
                Files.write(compressed, value);
                Process process = new ProcessBuilder(args[2], "-q", "-d", "-f", compressed.toString(), "-o", unpacked.toString()).inheritIO().start();
                if (process.waitFor() != 0 || Files.size(unpacked) > 256L * 1024 * 1024) throw new IllegalStateException("Zstd 恢复失败或超限");
                value = Files.readAllBytes(unpacked); Files.delete(compressed); Files.delete(unpacked);
            }
            if (value.length != originals[i]) throw new IllegalStateException("恢复长度不匹配");
            Files.write(file, value); hashes.put(names[i], hash(value));
        }
        if (plain.hasRemaining()) throw new IllegalStateException("载荷尾部残留");
        JSONArray images = new JSONArray();
        Map<String, Integer> recovered = new HashMap<>();
        Path sidecar = root.resolve("xop-pvm2.bin");
        if (Files.exists(sidecar)) {
            ByteBuffer code = buffer(Files.readAllBytes(sidecar));
            if (u16(code) != 4) throw new IllegalArgumentException("仅检查 code.bin v4");
            int groups = u16(code); int[] offsets = new int[groups];
            for (int i = 0; i < groups; i++) offsets[i] = code.getInt();
            byte[] key = derive(cert, ikm, "mocika-shield/xop-pvm2/v1".getBytes(StandardCharsets.UTF_8), 16);
            for (int offset : offsets) {
                if (offset != code.position()) throw new IllegalStateException("VM 偏移不连续");
                int dexIndex = code.getInt(), methods = u16(code);
                for (int i = 0; i < methods; i++) {
                    int method = code.getInt(), original = code.getInt(), size = code.getInt(), flags = code.getInt();
                    if (size < 28 || flags != 2) throw new IllegalArgumentException("VM 记录无效");
                    byte[] image = decrypt(key, take(code, 12), take(code, size - 12), true);
                    if (image.length != original) throw new IllegalStateException("VM 镜像长度不一致");
                    byte[] canonical = canonicalCode(image);
                    String name = "image-" + dexIndex + "-" + method + ".bin";
                    if (recovered.put(dexIndex + ":" + method, (int) image[18]) != null) throw new IllegalStateException("重复 VM 记录");
                    Files.write(root.resolve(name), image);
                    Files.write(root.resolve(name + ".canonical"), canonical);
                    images.put(new JSONObject().put("file", name).put("sha256", hash(image)).put("policy", image[18])
                            .put("canonical_code_sha256", hash(canonical)));
                }
            }
            if (code.hasRemaining()) throw new IllegalStateException("VM 尾部残留");
        }
        int trampolines = 0;
        if (args.length == 4) {
            JSONObject report = new JSONObject(Files.readString(Path.of(args[3])));
            if (!hash(Files.readAllBytes(apk)).equals(report.getString("output_sha256"))) throw new IllegalStateException("报告与 APK 不匹配");
            JSONObject selection = report.getJSONObject("build").getJSONObject("selection");
            Map<String, Map<String, com.android.tools.smali.dexlib2.iface.Method>> dexMethods = new HashMap<>();
            for (Object entry : report.getJSONArray("methods")) {
                JSONObject row = (JSONObject) entry;
                if (!row.getBoolean("artifact_verified")) continue;
                String name = row.getString("input_dex");
                if (!name.matches("classes[0-9]*\\.dex") || !hashes.has(name)) throw new IllegalArgumentException("报告引用了未恢复的 DEX");
                if (!dexMethods.containsKey(name)) {
                    // 每个 DEX 只清点一次；真实应用的上万条报告不能反复扫描整份 DEX。
                    DexBackedDexFile file = new DexBackedDexFile(Opcodes.getDefault(), Files.readAllBytes(root.resolve(name)));
                    Map<String, com.android.tools.smali.dexlib2.iface.Method> methods = new HashMap<>();
                    for (var cls : file.getClasses()) for (var method : cls.getMethods()) {
                        if (methods.put(Pvm2Report.descriptor(method), method) != null) throw new IllegalStateException("DEX 方法签名重复");
                    }
                    dexMethods.put(name, methods);
                }
                var method = dexMethods.get(name).get(row.getString("descriptor"));
                if (method == null) throw new IllegalStateException("恢复 DEX 中缺少方法");
                int index = row.getInt("final_method_index"), dexIndex = row.getInt("final_dex_index");
                if (!TrueVmpTrampoline.matches(method, dexIndex, index, selection.getString("bridge"), selection.getString("bridge_method"))
                        || !recovered.containsKey(dexIndex + ":" + index)) throw new IllegalStateException("跳板与镜像不一致");
                trampolines++;
            }
        }
        JSONObject nativeFiles = recoverNative(apk, root, cert, ikm);
        JSONObject result = new JSONObject().put("apk_sha256", hash(Files.readAllBytes(apk)))
                .put("entries", hashes).put("recovered_images", images).put("verified_trampolines", trampolines)
                .put("recovered_native_libraries", nativeFiles)
                .put("elapsed_ms", (System.nanoTime() - begin) / 1000000)
                .put("limitation", "包内公开材料可恢复 DEX 与 VM 镜像；恢复镜像不等于完成所有方法语义还原");
        Files.writeString(root.resolve("recovery.json"), result.toString(2) + "\n");
        System.out.println("恢复检查：条目=" + count + "，VM 镜像=" + images.length() + "，跳板=" + trampolines + "，SO=" + nativeFiles.length());
        Arrays.fill(ikm, (byte) 0);
    }
}
