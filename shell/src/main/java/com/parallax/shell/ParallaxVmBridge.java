package com.parallax.shell;

/**
 * Tiny JNI trampoline target for high-value methods moved out of DEX.
 * Release R8 mapping renames this class to Parallax16.
 */
public final class ParallaxVmBridge {
    private ParallaxVmBridge() {}

    public static native int hvi0(int methodId);
    public static native int hvi1(int methodId, int a0);
    public static native int hvi2(int methodId, int a0, int a1);
    public static native int hvi3(int methodId, int a0, int a1, int a2);
    public static native int hvi4(int methodId, int a0, int a1, int a2, int a3);

    public static native void hvv0(int methodId);
    public static native void hvv1(int methodId, int a0);
    public static native void hvv2(int methodId, int a0, int a1);
    public static native void hvv3(int methodId, int a0, int a1, int a2);
    public static native void hvv4(int methodId, int a0, int a1, int a2, int a3);
}
