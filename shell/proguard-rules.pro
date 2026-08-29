-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

# Deterministic release-only stub names. Source names remain type-safe for development,
# while the release DEX uses Parallax1..Parallax15 plus JangamBhai and Darkdevel.
-applymapping stub-obfuscation.map

# Keep every requested stub class as a distinct class boundary. `allowobfuscation` lets
# -applymapping assign the final names, while deliberately NOT allowing class-level
# optimization prevents R8 horizontal/vertical class merging from deleting Parallax2,
# Parallax3 or any of the named anchors. Ordinary member code can still be optimized and
# renamed unless an ABI rule below pins it.
-keep,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo
-keep,allowobfuscation class com.parallax.shell.ParallaxKoLadkiChahiye
-keep,allowobfuscation class com.parallax.shell.ParallaxGate
-keep,allowobfuscation class com.parallax.shell.Global
-keep,allowobfuscation class com.parallax.shell.Parallax
-keep,allowobfuscation class com.parallax.shell.ParallaxBhaiKiSecurity
-keep,allowobfuscation class com.parallax.shell.ParallaxBhaiya
-keep,allowobfuscation class com.parallax.shell.ParallaxDialogBhaiya
-keep,allowobfuscation class com.parallax.shell.ParallaxHu
-keep,allowobfuscation class com.parallax.shell.ParallaxHuMaalik
-keep,allowobfuscation class com.parallax.shell.ParallaxJaRaha
-keep,allowobfuscation class com.parallax.shell.ParallaxKaBhaiJangu
-keep,allowobfuscation class com.parallax.shell.ParallaxKiShadiKarwaDo
-keep,allowobfuscation class com.parallax.shell.ParallaxLovers
-keep,allowobfuscation class com.parallax.shell.ParallaxVirtualBhaiya
-keep,allowobfuscation class com.parallax.shell.JangamMeraBhaiHai
-keep,allowobfuscation class com.parallax.shell.ParallaxHuYaarBhai

# The packer injects calls to Parallax3.g(...) into the ORIGINAL app DEX. That caller is
# outside R8's program graph, so both the mapped class boundary and the member name/signature
# are external ABI and must stay exact.
-keepclassmembers class com.parallax.shell.ParallaxGate {
    public static void g(int, int, int, int);
}

# Dynamic RegisterNatives uses these Java method names/signatures, so the member ABI must
# remain stable even though the Application class is renamed to Parallax1.
-keepclassmembers,allowoptimization class com.parallax.shell.ParallaxKiSettingKarwaDo {
    public <init>();
    public native *** *(...);
    public *** *(...);
    protected *** *(...);
}

# Preserve framework entry methods for the mapped component factory. The class itself is
# kept distinct above so Android can instantiate Parallax2 from the protected manifest.
-keepclassmembers class com.parallax.shell.ParallaxKoLadkiChahiye {
    public <init>();
    public *** instantiate*(...);
}

# Existing hand-written state machines remain opaque at source level. Non-ABI members in
# other classes are still eligible for R8 name shrinking/optimization.
-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo {
    private void prepare(android.content.Context);
    private void replaceApplication();
    private static int nextState(int, int);
    private static volatile int flowNoise;
}

-repackageclasses com.parallax.shell
