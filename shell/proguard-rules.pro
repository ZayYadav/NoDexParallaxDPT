# Single-class Parallax bootstrap rules.
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

# The manifest and native RegisterNatives path require this exact class name.
# Do not allow optimization here: the source intentionally contains flattened
# dispatcher/state-machine control flow and R8 must not reconstruct it.
-keep class com.parallax.shell.ParallaxKoChummiDedo

# Android lifecycle overrides and JNI methods must keep their callable names/signatures.
# Keeping them without allowoptimization also preserves their flattened bodies.
-keepclassmembers class com.parallax.shell.ParallaxKoChummiDedo {
    public <init>();
    public *** *(...);
    protected *** *(...);
}

# Private implementation details stay present and non-optimized so the flattened graph
# survives into classes.dex, but their field/method names may still be aggressively
# renamed by R8. This gives the one surviving smali both CFF and symbol obfuscation.
-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKoChummiDedo {
    private *** *;
    private *** *(...);
}

# All legacy helper/bridge/factory classes remain shrinkable and should disappear from
# the release DEX when unreferenced. The output invariant is still one shell class.
-repackageclasses com.parallax.shell
