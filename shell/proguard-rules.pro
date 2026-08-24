-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

# Main bootstrap remains shrinkable/optimizable where safe.
-keep,allowoptimization class com.parallax.shell.ParallaxKoChummiDedo

# These framework-facing warning-path classes intentionally keep their odd names and
# hand-written state-machine/string-decoder bodies. Do not let R8 flatten them back into
# straight-line code or rename their framework entry points.
-keep class com.parallax.shell.ParallaxTGUser { *; }
-keep class com.parallax.shell.ParallaxKiGF { *; }
-keep class com.parallax.shell.ParallaxInstaUser { *; }
-keep class com.parallax.shell.ParallaxYTUser { *; }
-keep class com.parallax.shell.ParallaxSnapUser { *; }

-keepclassmembers,allowoptimization class com.parallax.shell.ParallaxKoChummiDedo {
    public <init>();
    public *** *(...);
    protected *** *(...);
}

-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKoChummiDedo {
    private void prepare(android.content.Context);
    private void replaceApplication();
    private static int nextState(int, int);
    private static volatile int flowNoise;
}

-repackageclasses com.parallax.shell
