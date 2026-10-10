package com.yqsh.protector.packer;

import java.util.List;
import java.util.Locale;

/**
 * Resolve and match auto True-VMP policy per {@code doc/auto-true-vmp-contract.md}.
 */
public final class AutoVmpPolicy {

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
        // D8/R8 bridge bodies only forward captured state to real business methods.
        // Moving them behind JNI changes callback receiver/lifecycle semantics on ART.
        if (isCompilerGeneratedBridge(typeDescriptor)) {
            return false;
        }
        // Room/LiveData/Retrofit/Glide are runtime infrastructure rather than
        // business algorithms. Their generated state machines, cursor mapping,
        // reflection and callback contracts are version/ROM sensitive; keeping
        // them on ART prevents an empty local list or missing resource callback
        // when the app's own code is virtualized.
        if (isDataAndResourceRuntimeGlue(typeDescriptor)) {
            return false;
        }
        // UI and navigation glue is callback/lifecycle driven. It contributes little
        // protection value and must keep Android/AndroidX receiver semantics on ART.
        if (isUiRuntimeGlue(typeDescriptor)) {
            return false;
        }
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
