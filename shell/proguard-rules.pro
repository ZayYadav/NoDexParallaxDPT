-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

# The manifest/native registration requires this exact class and its public/protected
# entry-point names, but R8 may optimize their bodies for a smaller single-class DEX.
-keep,allowoptimization class com.parallax.shell.ParallaxKoChummiDedo

-keepclassmembers,allowoptimization class com.parallax.shell.ParallaxKoChummiDedo {
    public <init>();
    public *** *(...);
    protected *** *(...);
}

# Preserve the compact opaque dispatcher only around the two sensitive bootstrap paths.
# Private names may still be obfuscated, while ordinary helpers remain fully shrinkable.
-keepclassmembers,allowobfuscation class com.parallax.shell.ParallaxKoChummiDedo {
    private void prepare(android.content.Context);
    private void replaceApplication();
    private static int nextState(int, int);
    private static volatile int flowNoise;
}

-repackageclasses com.parallax.shell
