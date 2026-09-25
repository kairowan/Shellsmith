package dev.mocika.shield.featurefixture.ondemand;

public final class OnDemandProbe {
    private OnDemandProbe() {}

    public static int score(int value) {
        return (value * 31) ^ 0x5a5a;
    }
}

