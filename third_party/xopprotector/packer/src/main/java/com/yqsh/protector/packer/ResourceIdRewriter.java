package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchElement;
import com.android.tools.smali.dexlib2.iface.instruction.WideLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction31i;
import com.android.tools.smali.dexlib2.iface.instruction.formats.PackedSwitchPayload;
import com.android.tools.smali.dexlib2.iface.instruction.formats.SparseSwitchPayload;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
import com.android.tools.smali.dexlib2.iface.value.IntEncodedValue;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableArrayPayload;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableSparseSwitchPayload;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableSwitchElement;
import com.android.tools.smali.dexlib2.immutable.value.ImmutableIntEncodedValue;
import com.android.tools.smali.dexlib2.rewriter.DexRewriter;
import com.android.tools.smali.dexlib2.rewriter.EncodedValueRewriter;
import com.android.tools.smali.dexlib2.rewriter.InstructionRewriter;
import com.android.tools.smali.dexlib2.rewriter.Rewriter;
import com.android.tools.smali.dexlib2.rewriter.RewriterModule;
import com.android.tools.smali.dexlib2.rewriter.Rewriters;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * Reassigns entry IDs inside each existing resource type and rewrites DEX integer references.
 * Package/type bytes and the complete set of IDs stay unchanged, so aapt2 can rebuild the table
 * without creating sparse or cross-type IDs.
 */
public final class ResourceIdRewriter {
    public static final class Result {
        public final Map<Integer, Integer> mapping;
        public final int pinned;
        public final int dexFiles;

        Result(Map<Integer, Integer> mapping, int pinned, int dexFiles) {
            this.mapping = mapping;
            this.pinned = pinned;
            this.dexFiles = dexFiles;
        }
    }

    private ResourceIdRewriter() {
    }

    public static Result rewrite(File unpackRoot) throws Exception {
        File publicXml = new File(unpackRoot, "res/values/public.xml");
        if (!publicXml.isFile()) {
            throw new IOException("resource ID reorder requires res/values/public.xml");
        }
        Document document = parseXml(publicXml);
        NodeList nodes = document.getElementsByTagName("public");
        Map<Integer, Element> entries = new LinkedHashMap<>();
        Map<Integer, List<Integer>> byType = new LinkedHashMap<>();
        Set<Integer> semanticPins = new HashSet<>();
        for (int i = 0; i < nodes.getLength(); i++) {
            Element element = (Element) nodes.item(i);
            String value = element.getAttribute("id");
            if (!value.matches("0x[0-9a-fA-F]{8}")) continue;
            int id = (int) Long.parseLong(value.substring(2), 16);
            if (entries.put(id, element) != null) {
                throw new IOException(String.format("duplicate resource ID 0x%08x", id));
            }
            byType.computeIfAbsent(id >>> 16, ignored -> new ArrayList<>()).add(id);
            // Android 要求 R.styleable 的属性 ID 数组保持升序。仅替换数组元素而不同时
            // 重排所有 styleable_* 索引常量会破坏 Material/AppCompat 的属性查询。
            if ("attr".equals(element.getAttribute("type"))) semanticPins.add(id);
        }
        if (entries.isEmpty()) throw new IOException("public.xml contains no resource IDs");

        Set<Integer> ids = entries.keySet();
        List<File> dexFiles = listDexFiles(unpackRoot);
        Set<Integer> pinned = new HashSet<>(semanticPins);
        for (File dex : dexFiles) collectDexPins(dex, ids, pinned);
        collectOpaquePins(new File(unpackRoot, "lib"), ids, pinned);
        collectOpaquePins(new File(unpackRoot, "assets"), ids, pinned);

        SecureRandom random = new SecureRandom();
        Map<Integer, Integer> mapping = new LinkedHashMap<>();
        for (List<Integer> group : byType.values()) {
            List<Integer> movable = new ArrayList<>();
            for (int id : group) if (!pinned.contains(id)) movable.add(id);
            if (movable.size() < 2) continue;
            List<Integer> shuffled = new ArrayList<>(movable);
            Collections.shuffle(shuffled, random);
            if (shuffled.equals(movable)) Collections.rotate(shuffled, 1);
            for (int i = 0; i < movable.size(); i++) {
                int oldId = movable.get(i);
                int newId = shuffled.get(i);
                if (oldId != newId) mapping.put(oldId, newId);
            }
        }
        // A tiny app can legitimately have fewer than two movable entries in every type.
        // There is no safe permutation in that case, so report a no-op instead of making
        // strict mode unusable for an otherwise valid APK.
        if (mapping.isEmpty()) return new Result(Map.of(), pinned.size(), dexFiles.size());

        for (Map.Entry<Integer, Integer> entry : mapping.entrySet()) {
            entries.get(entry.getKey()).setAttribute(
                    "id", String.format("0x%08x", entry.getValue()));
        }
        writeXml(document, publicXml);
        for (File dex : dexFiles) rewriteDex(dex, mapping);
        return new Result(mapping, pinned.size(), dexFiles.size());
    }

    private static Document parseXml(File file) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory.newDocumentBuilder().parse(file);
    }

    private static void writeXml(Document document, File file) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        var transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "utf-8");
        transformer.transform(new DOMSource(document), new StreamResult(file));
    }

    private static List<File> listDexFiles(File root) throws IOException {
        try (Stream<Path> stream = Files.list(root.toPath())) {
            return stream.filter(Files::isRegularFile)
                    .map(Path::toFile)
                    .filter(file -> file.getName().matches("classes(\\d*)?\\.dex"))
                    .sorted(Comparator.comparing(File::getName))
                    .toList();
        }
    }

    private static DexBackedDexFile readDex(File file) throws IOException {
        try (BufferedInputStream input = new BufferedInputStream(new FileInputStream(file))) {
            return DexBackedDexFile.fromInputStream(Opcodes.getDefault(), input);
        }
    }

    private static void collectDexPins(File file, Set<Integer> ids, Set<Integer> pinned)
            throws IOException {
        DexBackedDexFile dex = readDex(file);
        for (ClassDef cls : dex.getClasses()) {
            for (Method method : cls.getMethods()) {
                MethodImplementation implementation = method.getImplementation();
                if (implementation == null) continue;
                for (Instruction instruction : implementation.getInstructions()) {
                    if (instruction instanceof PackedSwitchPayload payload) {
                        for (SwitchElement element : payload.getSwitchElements()) {
                            if (ids.contains(element.getKey())) pinned.add(element.getKey());
                        }
                    } else if (instruction instanceof NarrowLiteralInstruction literal
                            && !(instruction instanceof Instruction31i)) {
                        int value = literal.getNarrowLiteral();
                        if (ids.contains(value)) pinned.add(value);
                    } else if (instruction instanceof WideLiteralInstruction literal) {
                        long value = literal.getWideLiteral();
                        if (value >= Integer.MIN_VALUE && value <= 0xffffffffL
                                && ids.contains((int) value)) pinned.add((int) value);
                    }
                }
            }
        }
    }

    private static void collectOpaquePins(File root, Set<Integer> ids, Set<Integer> pinned)
            throws IOException {
        if (!root.isDirectory()) return;
        try (Stream<Path> stream = Files.walk(root.toPath())) {
            for (Path path : stream.filter(Files::isRegularFile).toList()) {
                try (BufferedInputStream input = new BufferedInputStream(
                        new FileInputStream(path.toFile()))) {
                    int b0 = -1, b1 = -1, b2 = -1;
                    int b3;
                    while ((b3 = input.read()) >= 0) {
                        if (b0 >= 0) {
                            int value = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
                            if (ids.contains(value)) pinned.add(value);
                        }
                        b0 = b1;
                        b1 = b2;
                        b2 = b3;
                    }
                }
            }
        }
    }

    private static void rewriteDex(File file, Map<Integer, Integer> mapping) throws IOException {
        DexBackedDexFile dex = readDex(file);
        RewriterModule module = new RewriterModule() {
            @Override public Rewriter<Instruction> getInstructionRewriter(Rewriters rewriters) {
                InstructionRewriter base = new InstructionRewriter(rewriters);
                return instruction -> rewriteInstruction(base.rewrite(instruction), mapping);
            }

            @Override public Rewriter<EncodedValue> getEncodedValueRewriter(Rewriters rewriters) {
                EncodedValueRewriter base = new EncodedValueRewriter(rewriters);
                return value -> {
                    if (value instanceof IntEncodedValue integer) {
                        Integer replacement = mapping.get(integer.getValue());
                        if (replacement != null) return new ImmutableIntEncodedValue(replacement);
                    }
                    return base.rewrite(value);
                };
            }
        };
        var rewritten = new DexRewriter(module).getDexFileRewriter().rewrite(dex);
        DexPool pool = new DexPool(Opcodes.getDefault());
        for (ClassDef cls : rewritten.getClasses()) pool.internClass(cls);
        File temp = new File(file.getParentFile(), file.getName() + ".rid.tmp");
        pool.writeTo(new FileDataStore(temp));
        Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }

    private static Instruction rewriteInstruction(
            Instruction instruction, Map<Integer, Integer> mapping) {
        if (instruction instanceof Instruction31i literal) {
            Integer replacement = mapping.get(literal.getNarrowLiteral());
            if (replacement != null) {
                return new ImmutableInstruction31i(
                        instruction.getOpcode(), literal.getRegisterA(), replacement);
            }
        }
        if (instruction instanceof SparseSwitchPayload payload) {
            List<ImmutableSwitchElement> elements = new ArrayList<>();
            boolean changed = false;
            for (SwitchElement element : payload.getSwitchElements()) {
                int key = mapping.getOrDefault(element.getKey(), element.getKey());
                changed |= key != element.getKey();
                elements.add(new ImmutableSwitchElement(key, element.getOffset()));
            }
            if (changed) {
                elements.sort(Comparator.comparingInt(ImmutableSwitchElement::getKey));
                return new ImmutableSparseSwitchPayload(elements);
            }
        }
        if (instruction instanceof ArrayPayload payload && payload.getElementWidth() == 4) {
            List<Number> values = new ArrayList<>();
            boolean changed = false;
            for (Number number : payload.getArrayElements()) {
                int value = number.intValue();
                int replacement = mapping.getOrDefault(value, value);
                changed |= replacement != value;
                values.add(replacement);
            }
            if (changed) return new ImmutableArrayPayload(4, values);
        }
        return instruction;
    }
}
