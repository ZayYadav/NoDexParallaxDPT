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

# Framework/JNI entry classes must survive shrinking but their class names are deliberately
# allowed to follow the mapping above.
-keep,allowoptimization,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo
-keep,allowoptimization,allowobfuscation class com.parallax.shell.ParallaxKoLadkiChahiye
-keep,allowoptimization,allowobfuscation class com.parallax.shell.ParallaxGate

# The packer injects calls to Parallax3.g(...) into the original app DEX. Keep the method
# name/signature stable while allowing the containing class itself to become Parallax3.
-keepclassmembers class com.parallax.shell.ParallaxGate {
    public static void g(int, int, int, int);
}

# Dynamic RegisterNatives uses these Java method names/signatures, so the member ABI must
# remain stable even though the Application class is renamed to Parallax1.
-keepclassmembers,allowoptimization class com.parallax.shell.ParallaxKiSettingKarwaDo {
    public <init>();
    public native <methods>;
    public native *** *(...);
    public *** *(...);
    protected *** *(...);
}

# Preserve framework entry methods for the mapped component factory. Internal helpers can
# still be optimized/renamed by R8.
-keepclassmembers class com.parallax.shell.ParallaxKoLadkiChahiye {
    public <init>();
    public *** instantiate*(...);
}

# Explicit special anchors requested for the final stub DEX. They may be optimized but are
# retained and class-obfuscated according to stub-obfuscation.map.
-keep,allowoptimization,allowobfuscation class com.parallax.shell.JangamMeraBhaiHai
-keep,allowoptimization,allowobfuscation class com.parallax.shell.ParallaxHuYaarBhai

# Existing hand-written state machines are kept as source-level opaque control flow. R8 is
# still free to optimize ordinary helpers and rename non-ABI members.
-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo {
    private void prepare(android.content.Context);
    private void replaceApplication();
    private static int nextState(int, int);
    private static volatile int flowNoise;
}

-repackageclasses com.parallax.shell
