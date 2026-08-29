-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

-applymapping stub-obfuscation.map

# Release shell ABI anchors. Keep implementations intact while allowing the exact
# deterministic names in stub-obfuscation.map to move every retained shell/VM class
# into the single Parallax.Enc runtime namespace.
-keep,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo { *; }
-keep,allowobfuscation class com.parallax.shell.Parallax2 { *; }
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

# The Java source name is deliberately descriptive only at build time. R8 maps this
# exact native bridge to Parallax.Enc.CrackWarTeamMC; native member names stay fixed.
-keep,allowobfuscation class parallax.vm.Parallax16 {
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

# Legacy source-level factory alias is intentionally disposable. Parallax2 is the
# literal framework ABI now, so retaining this alias would add a duplicate entry.
-keep,allowshrinking,allowoptimization,allowobfuscation class com.parallax.shell.ParallaxKoLadkiChahiye

-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo {
    private void prepare(android.content.Context);
    private void replaceApplication();
    private static int nextState(int, int);
    private static volatile int flowNoise;
}

# Any surviving helper/desugaring classes that are not explicitly mapped above are
# still forced into the same release namespace.
-repackageclasses Parallax.Enc
