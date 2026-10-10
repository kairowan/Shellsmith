package com.yqsh.protector.packer;

import java.util.Locale;

/**
 * Industry / tools auto True-VMP markers for {@link ProtectPolicy.Profile#INDUSTRY}.
 * Matches sensitive business types by path segment / simple-name tokens — not
 * Android components and not major SDK prefixes.
 *
 * <p>Production matching requires the type to live under the app Manifest
 * package prefix ({@link #matches(String, String)}) so third-party libs
 * (zip4j, LitePal, …) are not swept in by crypto-ish class names.
 *
 * <p>Path-segment matches are limited to license-ish tokens. Crypto-ish tokens
 * apply only to the <em>simple class name</em> (camelCase pieces) so libraries
 * under {@code …/crypto/…} (SpongyCastle, AWS, …) are not swept in.
 */
public final class IndustryVmpRules {

    /** Allowed as a full package path segment (lower case). */
    private static final String[] PATH_TOKENS = {
            "license",
            "licence",
            "activate",
            "activation",
            "dongle",
            "licmgr",
            "licmanager",
            "softlock",
            "hardlock",
            "sncheck",
            "serialcheck",
            "deviceid",
            "machinecode",
    };

    /** Allowed only on simple-name / camelCase pieces (lower case). */
    private static final String[] NAME_TOKENS = {
            "license",
            "licence",
            "activate",
            "activation",
            "dongle",
            "encrypt",
            "decrypt",
            "cipher",
            "crypto",
            "checksum",
            "deviceid",
            "machinecode",
            "sncheck",
            "serialcheck",
            "licmgr",
            "licmanager",
            "softlock",
            "hardlock",
    };

    private IndustryVmpRules() {
    }

    /**
     * Token-only match (no app-package gate). Prefer
     * {@link #matches(String, String)} in production.
     *
     * @param typeDescriptor e.g. {@code Lcom/zhd/ts/license/LicenseChecker;}
     */
    public static boolean matches(String typeDescriptor) {
        return matchesTokens(typeDescriptor);
    }

    /**
     * Industry auto True-VMP: type must be under {@code appPackagePrefix}
     * (e.g. {@code Lcom/foo/bar/} from Manifest package) <em>and</em> match
     * license/crypto tokens. Empty/null prefix → never matches.
     */
    public static boolean matches(String typeDescriptor, String appPackagePrefix) {
        if (appPackagePrefix == null || appPackagePrefix.isEmpty()) {
            return false;
        }
        if (typeDescriptor == null || !typeDescriptor.startsWith(appPackagePrefix)) {
            return false;
        }
        return matchesTokens(typeDescriptor);
    }

    private static boolean matchesTokens(String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.length() < 3) {
            return false;
        }
        if (ProtectPolicy.isAndroidComponent(typeDescriptor)) {
            return false;
        }
        if (ProtectPolicy.isGeneratedNoise(typeDescriptor)) {
            return false;
        }
        if (ProtectPolicy.isSdkOrFramework(typeDescriptor)) {
            return false;
        }

        int start = typeDescriptor.startsWith("L") ? 1 : 0;
        int end = typeDescriptor.endsWith(";") ? typeDescriptor.length() - 1 : typeDescriptor.length();
        if (start >= end) {
            return false;
        }
        String body = typeDescriptor.substring(start, end);

        int lastSlash = body.lastIndexOf('/');
        String simple = lastSlash >= 0 ? body.substring(lastSlash + 1) : body;
        int dollar = simple.indexOf('$');
        if (dollar >= 0) {
            simple = simple.substring(0, dollar);
        }

        // Path segments (excluding simple name): license-ish only.
        int segStart = 0;
        int pathEnd = lastSlash >= 0 ? lastSlash : 0;
        for (int i = 0; i <= pathEnd; i++) {
            char c = i < pathEnd ? body.charAt(i) : '/';
            if (c == '/' || i == pathEnd) {
                if (i > segStart) {
                    String seg = body.substring(segStart, i).toLowerCase(Locale.US);
                    if (hit(seg, PATH_TOKENS)) {
                        return true;
                    }
                }
                segStart = i + 1;
            }
        }

        // Simple class name: full lower equals or camelCase token.
        if (hit(simple.toLowerCase(Locale.US), NAME_TOKENS)) {
            return true;
        }
        return camelTokenHit(simple);
    }

    private static boolean hit(String segLower, String[] tokens) {
        for (String t : tokens) {
            if (segLower.equals(t)) {
                return true;
            }
        }
        return false;
    }

    private static boolean camelTokenHit(String seg) {
        int n = seg.length();
        int start = 0;
        for (int i = 1; i <= n; i++) {
            boolean boundary = i == n;
            if (!boundary) {
                char prev = seg.charAt(i - 1);
                char cur = seg.charAt(i);
                boundary = (Character.isLowerCase(prev) && Character.isUpperCase(cur))
                        || (Character.isDigit(prev) && Character.isLetter(cur))
                        || (Character.isLetter(prev) && Character.isDigit(cur));
                if (!boundary && i + 1 < n
                        && Character.isUpperCase(prev)
                        && Character.isUpperCase(cur)
                        && Character.isLowerCase(seg.charAt(i + 1))) {
                    boundary = true;
                }
            }
            if (boundary && i > start) {
                if (hit(seg.substring(start, i).toLowerCase(Locale.US), NAME_TOKENS)) {
                    return true;
                }
                start = i;
            }
        }
        return false;
    }
}
