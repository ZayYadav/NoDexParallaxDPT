package parallax.vm;

/**
 * Fixed, tiny JNI trampoline surface for methods compiled into the native Parallax VM.
 * High-value app methods call these entrypoints after their original Dalvik bodies have
 * been removed before the normal DPT hollowing pass.
 */
public final class Parallax16 {
    private Parallax16() {}

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
