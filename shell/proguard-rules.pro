-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

-applymapping stub-obfuscation.map

# Release shell ABI anchors. Keep their implementations intact while still allowing
# the deterministic stub-obfuscation.map names (Parallax1, Parallax3..15,
# JangamBhai and Darkdevel) to be applied. Class-only keep rules allowed R8 full
# mode to optimize a package-private anchor out of the final DEX on some builds.
-keep,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo { *; }
-keep class com.parallax.shell.Parallax2 { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxGate { *; }
-keep,allowobfuscation class com.parallax.shell.Global { *; }
-keep,allowobfuscation class com.parallax.shell.Parallax { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxBhaiKiSecurity { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxBhaiya { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxDialogBhaiya { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxHu { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxHuMaalik { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxJaRaha { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxKaBhaiJangu { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxKiShadiKarwaDo { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxLovers { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxVirtualBhaiya { *; }
-keep,allowobfuscation class com.parallax.shell.JangamMeraBhaiHai { *; }
-keep,allowobfuscation class com.parallax.shell.ParallaxHuYaarBhai { *; }

-keepclassmembers class com.parallax.shell.ParallaxGate {
    public static void g(int, int, int, int);
}

-keep class parallax.vm.Parallax16 {
    public static native int hvi0(int);
    public static native int hvi1(int, int);
    public static native int hvi2(int, int, int);
    public static native int hvi3(int, int, int, int);
    public static native int hvi4(int, int, int, int, int);
    public static native void hvv0(int);
    public static native void hvv1(int, int);
    public static native void hvv2(int, int, int);
    public static native void hvv3(int, int, int, int);
    public static native void hvv4(int, int, int, int, int);
}

-keepclassmembers,allowoptimization class com.parallax.shell.ParallaxKiSettingKarwaDo {
    public <init>();
    public native *** *(...);
    public *** *(...);
    protected *** *(...);
}

-keepclassmembers class com.parallax.shell.Parallax2 {
    public <init>();
    public *** instantiate*(...);
}

# Legacy source-level factory alias is intentionally disposable. Parallax2 is
# the literal framework ABI now, so retaining this alias would collide with the
# historical applymapping target.
-keep,allowshrinking,allowoptimization,allowobfuscation class com.parallax.shell.ParallaxKoLadkiChahiye

-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo {
    private void prepare(android.content.Context);
    private void replaceApplication();
    private static int nextState(int, int);
    private static volatile int flowNoise;
}

-repackageclasses com.parallax.shell
