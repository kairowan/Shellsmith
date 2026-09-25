package dev.mocika.shield.featurefixture.feature;

public final class FeatureProbe {
    private FeatureProbe() {}

    public static String message(int value) {
        int doubled;
        synchronized (FeatureProbe.class) {
            doubled = value * 2;
        }
        return "feature-" + doubled;
    }
}
