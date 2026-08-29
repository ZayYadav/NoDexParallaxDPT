-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

# Deterministic release-only stub names. Most source classes remain descriptive and are
# mapped into the Parallax series. Parallax2 is intentionally a source-level class because
# Android instantiates it from the protected manifest before ordinary app code is running.
-applymapping stub-obfuscation.map

# Keep every requested stub class as a distinct class boundary. `allowobfuscation` lets
# -applymapping assign the final names, while deliberately NOT allowing class-level
# optimization prevents R8 horizontal/vertical class merging from deleting external ABIs.
-keep,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo
-keep class com.parallax.shell.Parallax2
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
# outside R8's program graph, so both the mapped class boundary and member signature are ABI.
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

# Android calls these methods by framework dispatch on the manifest-instantiated Parallax2.
-keepclassmembers class com.parallax.shell.Parallax2 {
    public <init>();
    public *** instantiate*(...);
}

# The legacy source-name alias exists only so older internal source references can compile.
# It is not an external ABI and should not survive with its descriptive descriptor.
-keep,allowshrinking,allowoptimization,allowobfuscation class com.parallax.shell.ParallaxKoLadkiChahiye

# Existing hand-written state machines remain opaque at source level. Non-ABI members in
# other classes are still eligible for R8 name shrinking/optimization.
-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKiSettingKarwaDo {
    private void prepare(android.content.Context);
    private void replaceApplication();
    private static int nextState(int, int);
    private static volatile int flowNoise;
}

-repackageclasses com.parallax.shell
