-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

# Framework/manifest/native entry points must keep their class names. R8 may still
# optimize method bodies so the blocked-mode protection bootstrap remains compact.
-keep,allowoptimization class com.parallax.shell.ParallaxKoChummiDedo
-keep,allowoptimization class com.parallax.shell.ParallaxProtectionFactory
-keep,allowoptimization class com.parallax.shell.ParallaxProtectionActivity
-keep,allowoptimization class com.parallax.shell.ParallaxBlockedProvider
-keep,allowoptimization class com.parallax.shell.ParallaxBlockedService
-keep,allowoptimization class com.parallax.shell.ParallaxBlockedReceiver

-keepclassmembers,allowoptimization class com.parallax.shell.ParallaxKoChummiDedo {
    public <init>();
    public *** *(...);
    protected *** *(...);
}

# Preserve the opaque dispatcher around the sensitive bootstrap paths while allowing
# ordinary implementation details to be optimized/obfuscated.
-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKoChummiDedo {
    private void prepare(android.content.Context);
    private void replaceApplication();
    private static int nextState(int, int);
    private static volatile int flowNoise;
}

-repackageclasses com.parallax.shell
