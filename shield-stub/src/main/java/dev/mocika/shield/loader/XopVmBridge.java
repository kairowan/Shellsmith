package dev.mocika.shield.loader;

/** Host-owned bridge targeted by Xop transform-only PVM2 trampolines. */
public final class XopVmBridge {
    private XopVmBridge() {}

    public static Object interpret(int dexIndex, int methodIndex, Object[] args) {
        return Ld.v(dexIndex, methodIndex, args);
    }
}
