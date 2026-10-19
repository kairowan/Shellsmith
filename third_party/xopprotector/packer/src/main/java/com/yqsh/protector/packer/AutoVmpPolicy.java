package com.yqsh.protector.packer;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import java.util.List;
import java.util.Locale;

/**
 * Resolve and match auto True-VMP policy per {@code doc/auto-true-vmp-contract.md}.
 */
public final class AutoVmpPolicy {
    private static final Opcodes OPCODES = Opcodes.getDefault();

    private AutoVmpPolicy() {
    }

    /** Resolved effective flags + whether each axis came from CLI vs default. */
    public static final class Resolved {
        public final boolean paymentEffective;
        public final boolean industryEffective;
        public final boolean paymentFromCli;
        public final boolean industryFromCli;

        public Resolved(boolean paymentEffective, boolean industryEffective,
                        boolean paymentFromCli, boolean industryFromCli) {
            this.paymentEffective = paymentEffective;
            this.industryEffective = industryEffective;
            this.paymentFromCli = paymentFromCli;
            this.industryFromCli = industryFromCli;
        }
    }

    public static Resolved resolve(ProtectOptions.AutoVmpMode payment,
                                   ProtectOptions.AutoVmpMode industry,
                                   ProtectPolicy.Profile profile) {
        if (payment == null) {
            payment = ProtectOptions.AutoVmpMode.UNSET;
        }
        if (industry == null) {
            industry = ProtectOptions.AutoVmpMode.UNSET;
        }
        if (profile == null) {
            profile = ProtectPolicy.Profile.BALANCED;
        }
        boolean paymentCli = payment != ProtectOptions.AutoVmpMode.UNSET;
        boolean industryCli = industry != ProtectOptions.AutoVmpMode.UNSET;
        boolean paymentEff = switch (payment) {
            case ON -> true;
            case OFF -> false;
            case UNSET -> true;
        };
        boolean industryEff = switch (industry) {
            case ON -> true;
            case OFF -> false;
            case UNSET -> profile == ProtectPolicy.Profile.INDUSTRY;
        };
        return new Resolved(paymentEff, industryEff, paymentCli, industryCli);
    }

    /**
     * Apply aggregate {@code --auto-true-vmp} onto unset axes only when building
     * initial modes; fine-grained flags should be applied afterward via
     * {@link #applyPairedFlag}.
     */
    public static ProtectOptions.AutoVmpMode[] fromAggregate(String value) {
        if (value == null) {
            throw new IllegalArgumentException("--auto-true-vmp requires payment|industry|both|off");
        }
        String v = value.trim().toLowerCase(Locale.US);
        return switch (v) {
            case "off" -> new ProtectOptions.AutoVmpMode[]{
                    ProtectOptions.AutoVmpMode.OFF, ProtectOptions.AutoVmpMode.OFF};
            case "payment" -> new ProtectOptions.AutoVmpMode[]{
                    ProtectOptions.AutoVmpMode.ON, ProtectOptions.AutoVmpMode.OFF};
            case "industry" -> new ProtectOptions.AutoVmpMode[]{
                    ProtectOptions.AutoVmpMode.OFF, ProtectOptions.AutoVmpMode.ON};
            case "both" -> new ProtectOptions.AutoVmpMode[]{
                    ProtectOptions.AutoVmpMode.ON, ProtectOptions.AutoVmpMode.ON};
            default -> throw new IllegalArgumentException(
                    "--auto-true-vmp must be payment|industry|both|off, got: " + value);
        };
    }

    /**
     * Apply a paired on/off flag. Conflicting on+off on the same axis fails.
     *
     * @param axisLabel short name for errors, e.g. {@code payment} or {@code industry}
     */
    public static ProtectOptions.AutoVmpMode applyPairedFlag(
            ProtectOptions.AutoVmpMode current,
            ProtectOptions.AutoVmpMode next,
            String axisLabel) {
        if (next == null || next == ProtectOptions.AutoVmpMode.UNSET) {
            return current == null ? ProtectOptions.AutoVmpMode.UNSET : current;
        }
        if (current == null) {
            current = ProtectOptions.AutoVmpMode.UNSET;
        }
        if (current != ProtectOptions.AutoVmpMode.UNSET && current != next) {
            throw new IllegalArgumentException(
                    "conflicting --" + axisLabel + "-auto-vmp / --no-" + axisLabel
                            + "-auto-vmp flags");
        }
        return next;
    }

    public static boolean shouldTrueVmp(String typeDescriptor,
                                        boolean paymentEffective,
                                        boolean industryEffective,
                                        List<String> trueVmpPrefixes,
                                        String appPackagePrefix) {
        // 类前缀只决定选择范围；兼容性必须在读取方法体后判断。
        return matchesRequestedScope(typeDescriptor, paymentEffective, industryEffective,
                        trueVmpPrefixes, appPackagePrefix);
    }

    /** 报告与实际转换共用，精确必保清单也不能绕过方法兼容检查。 */
    static String exclusionReason(ClassDef owner, Method method) {
        String reason = exclusionReason(owner.getType());
        int flags = method.getAccessFlags();
        // 生成桥接与合成方法保持原有接收者和调用约定。
        if ((flags & (0x40 | 0x1000)) != 0 || (owner.getAccessFlags() & 0x1000) != 0
                || "compiler_generated_bridge".equals(reason)) return "compiler_generated_bridge";
        // 直接父类和接口仍暴露框架契约时，混淆后的类名不能使回调漏过检查。
        if (reason == null && owner.getSuperclass() != null)
            reason = exclusionReason(owner.getSuperclass());
        if (reason == null) for (String contract : owner.getInterfaces()) {
            reason = exclusionReason(contract);
            if (reason != null) break;
        }
        if (reason == null && PlaybackCompatibility.keepOnArt(owner.getType(), method.getName()))
            reason = "playback_compatibility";
        if (reason == null) return null;
        if (method.getImplementation() == null || method.getName().startsWith("<")) return reason;
        String restriction = independentMethodRestriction(method, "ui_runtime_glue".equals(reason));
        return restriction == null ? null : reason + ":" + restriction;
    }

    private static String independentMethodRestriction(Method method, boolean component) {
        int flags = method.getAccessFlags();
        var code = method.getImplementation();
        if ((flags & (0x20 | 0x20000)) != 0) return "synchronization";
        // 跳板保留原声明、访问标志和 this，虚分派仍由 ART 完成；继承/接口本身不构成拒绝理由。
        // ponytail: hashCode/finalize 仍留在 ART，避免运行时重入；扩展需单独验证 GC 与内部对象操作。
        if ((flags & (0x2 | 0x8)) == 0 && (method.getName().equals("hashCode")
                || method.getName().equals("finalize"))) return "virtual_contract";
        // 组件的字段、调用、数组与异常统一交给共用编译器校验；跳板保留 ART 入口与 this。
        // ponytail: 媒体及数据框架的专用兼容规则仍只放行叶子方法，扩展须有对应框架回归。
        if (component) return null;
        // 异常表交给 Pvm2Safety 和编译器校验；move-exception/throw 支持捕获、finally 和重新抛出。
        // ponytail: 仅放行无状态访问、外部调用的叶子方法；引用和异常复用已有类型化运行时。
        // 字段、数组元素、调用等仍留在 ART；扩展需验证对象状态与框架语义，不能直接移除命名规则。
        for (var instruction : code.getInstructions()) {
            Opcode opcode = instruction.getOpcode();
            if (opcode == Opcode.PACKED_SWITCH_PAYLOAD || opcode == Opcode.SPARSE_SWITCH_PAYLOAD) continue;
            Short value = OPCODES.getOpcodeValue(opcode);
            if (value == null) return "non_leaf_instruction";
            int op = Short.toUnsignedInt(value);
            if (!(op <= 0x09 || (op >= 0x0d && op <= 0x11) || (op >= 0x12 && op <= 0x19)
                    || (op >= 0x27 && op <= 0x3d) || (op >= 0x7b && op <= 0xe2))) return "non_leaf_instruction";
        }
        return null;
    }

    /** 兼容性排除只影响执行准入，不能从用户选择范围的覆盖率分母中消失。 */
    static String exclusionReason(String typeDescriptor) {
        // D8/R8 bridge bodies only forward captured state to real business methods.
        // Moving them behind JNI changes callback receiver/lifecycle semantics on ART.
        if (isCompilerGeneratedBridge(typeDescriptor)) {
            return "compiler_generated_bridge";
        }
        // Room/LiveData/Retrofit/Glide are runtime infrastructure rather than
        // business algorithms. Their generated state machines, cursor mapping,
        // reflection and callback contracts are version/ROM sensitive; keeping
        // them on ART prevents an empty local list or missing resource callback
        // when the app's own code is virtualized.
        if (isDataAndResourceRuntimeGlue(typeDescriptor)) {
            return "data_resource_runtime_glue";
        }
        // 组件分类用于保留特殊契约；普通方法继续进入共用编译器，不按名称限制为叶子方法。
        if (isUiRuntimeGlue(typeDescriptor)) {
            return "ui_runtime_glue";
        }
        return null;
    }

    public static boolean matchesRequestedScope(String typeDescriptor,
                                                boolean paymentEffective,
                                                boolean industryEffective,
                                                List<String> trueVmpPrefixes,
                                                String appPackagePrefix) {
        if (paymentEffective && PaymentVmpRules.matches(typeDescriptor)) {
            return true;
        }
        if (industryEffective && IndustryVmpRules.matches(typeDescriptor, appPackagePrefix)) {
            return true;
        }
        if (trueVmpPrefixes == null || trueVmpPrefixes.isEmpty()) {
            return false;
        }
        for (String prefix : trueVmpPrefixes) {
            if (prefix != null && typeDescriptor != null && typeDescriptor.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    static boolean isCompilerGeneratedBridge(String typeDescriptor) {
        return typeDescriptor != null
                && (typeDescriptor.contains("$$ExternalSyntheticLambda")
                || typeDescriptor.contains("$ExternalSyntheticLambda")
                || typeDescriptor.contains("$$ExternalSyntheticOutline")
                || typeDescriptor.contains("$$Lambda$")
                || typeDescriptor.contains("$$inlined$")
                || hasAnonymousClassSegment(typeDescriptor));
    }

    private static boolean hasAnonymousClassSegment(String typeDescriptor) {
        for (int i = typeDescriptor.indexOf('$'); i >= 0; i = typeDescriptor.indexOf('$', i + 1)) {
            int cursor = i + 1;
            if (cursor >= typeDescriptor.length()
                    || !Character.isDigit(typeDescriptor.charAt(cursor))) {
                continue;
            }
            while (cursor < typeDescriptor.length()
                    && Character.isDigit(typeDescriptor.charAt(cursor))) {
                cursor++;
            }
            if (cursor == typeDescriptor.length()
                    || typeDescriptor.charAt(cursor) == '$'
                    || typeDescriptor.charAt(cursor) == ';') {
                return true;
            }
        }
        return false;
    }

    static boolean isUiRuntimeGlue(String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.length() < 3
                || ProtectPolicy.isAndroidComponent(typeDescriptor)) {
            return true;
        }
        String lower = typeDescriptor.toLowerCase(Locale.ROOT);
        String[] pathSegments = {
                "/activity/", "/fragment/", "/dialog/", "/adapter/", "/widget/",
                "/view/", "/ui/", "/navigation/", "/navigator/", "/router/"
        };
        for (String segment : pathSegments) {
            if (lower.contains(segment)) {
                return true;
            }
        }
        String simple = ProtectPolicy.simpleName(typeDescriptor);
        String[] suffixes = {
                "Ac", "Fg", "Dialog", "Popup", "PopupWindow", "Adapter", "View",
                "ViewHolder", "ScreenKt", "Router", "Navigator"
        };
        for (String suffix : suffixes) {
            if (simple.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    static boolean isDataAndResourceRuntimeGlue(String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.length() < 3) {
            return true;
        }
        String lower = typeDescriptor.toLowerCase(Locale.ROOT);
        String[] pathSegments = {
                "/data/", "/database/", "/dao/", "/repository/", "/viewmodel/",
                "/http/", "/net/", "/network/", "/glide/", "/image/", "/images/",
                "/storage/", "/resource/", "/resources/", "/assets/", "/serialization/",
                // Application helpers are commonly called from adapters/views and
                // resource loaders. Their nullable receiver and resource-ID
                // semantics are safer on ART than inside the PVM2 bridge. Include
                // the frequent misspelling "hepler" used by older app packages.
                "/helper/", "/helpers/", "/hepler/",
                // Device/permission code is a platform callback boundary. BLE
                // scanners, GATT state dispatch and runtime permission results
                // must retain ordinary ART receiver/exception semantics.
                "/device/manager/", "/device/ble/", "/bluetooth/", "/ble/", "/gatt/",
                "/scanner/", "/permission/", "/permissions/", "/location/"
        };
        for (String segment : pathSegments) {
            if (lower.contains(segment)) {
                return true;
            }
        }
        String simple = ProtectPolicy.simpleName(typeDescriptor);
        String[] suffixes = {
                "Dao", "Dao_Impl", "Database", "Database_Impl", "Repository",
                "RepositoryImpl", "ViewModel", "ViewModel$", "Interceptor", "GlideModule",
                "Permission", "PermissionManager", "PermissionHelper", "BleManager",
                "BluetoothManager", "GattCallback", "ScanCallback", "Scanner",
                "DeviceManager", "LocationProvider"
        };
        for (String suffix : suffixes) {
            if (simple.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    public static String formatPolicyLine(Resolved r,
                                          ProtectPolicy.Profile profile,
                                          int prefixCount,
                                          String appPackagePrefix) {
        String profileName = profile == null ? "balanced" : profile.name().toLowerCase(Locale.US);
        String scope = (appPackagePrefix == null || appPackagePrefix.isEmpty())
                ? "none"
                : appPackagePrefix;
        return "True-VMP policy: payment=" + onOff(r.paymentEffective)
                + " industry=" + onOff(r.industryEffective)
                + " prefixes=" + prefixCount
                + " industry_scope=" + scope
                + " (profile=" + profileName
                + ", payment_src=" + (r.paymentFromCli ? "cli" : "default")
                + ", industry_src=" + (r.industryFromCli ? "cli" : "default")
                + ")";
    }

    private static String onOff(boolean v) {
        return v ? "on" : "off";
    }
}
