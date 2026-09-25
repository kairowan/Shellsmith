package dev.mocika.shield.featurefixture.conditional;

public final class ConditionalProbe {
    private ConditionalProbe() {}

    public static String assetPath() {
        return "conditional/mocika_conditional_asset.txt";
    }

    public static native int nativeScore(int value);
}

