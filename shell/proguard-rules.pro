# Single-class Parallax bootstrap rules.
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

# This is the only shell class that must survive release shrinking. It is both the
# Android Application entry point and the JNI registration target.
-keep,allowoptimization class com.parallax.shell.ParallaxKoChummiDedo { *; }

# All legacy helper/bridge/factory classes are intentionally shrinkable and should
# disappear from the release DEX when unreferenced.
-repackageclasses com.parallax.shell
