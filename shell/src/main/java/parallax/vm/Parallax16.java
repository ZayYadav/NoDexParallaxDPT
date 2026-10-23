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

    public static native long hvj0(int methodId);
    public static native long hvj1(int methodId, long a0);
    public static native long hvj2(int methodId, long a0, long a1);
    public static native long hvj3(int methodId, long a0, long a1, long a2);
    public static native long hvj4(int methodId, long a0, long a1, long a2, long a3);

    public static native void hvjv0(int methodId);
    public static native void hvjv1(int methodId, long a0);
    public static native void hvjv2(int methodId, long a0, long a1);
    public static native void hvjv3(int methodId, long a0, long a1, long a2);
    public static native void hvjv4(int methodId, long a0, long a1, long a2, long a3);

    public static native float hvf0(int methodId);
    public static native float hvf1(int methodId, float a0);
    public static native float hvf2(int methodId, float a0, float a1);
    public static native float hvf3(int methodId, float a0, float a1, float a2);
    public static native float hvf4(int methodId, float a0, float a1, float a2, float a3);

    public static native void hvfv0(int methodId);
    public static native void hvfv1(int methodId, float a0);
    public static native void hvfv2(int methodId, float a0, float a1);
    public static native void hvfv3(int methodId, float a0, float a1, float a2);
    public static native void hvfv4(int methodId, float a0, float a1, float a2, float a3);

    public static native double hvd0(int methodId);
    public static native double hvd1(int methodId, double a0);
    public static native double hvd2(int methodId, double a0, double a1);
    public static native double hvd3(int methodId, double a0, double a1, double a2);
    public static native double hvd4(int methodId, double a0, double a1, double a2, double a3);

    public static native void hvdv0(int methodId);
    public static native void hvdv1(int methodId, double a0);
    public static native void hvdv2(int methodId, double a0, double a1);
    public static native void hvdv3(int methodId, double a0, double a1, double a2);
    public static native void hvdv4(int methodId, double a0, double a1, double a2, double a3);
}
