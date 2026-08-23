# Tiny Parallax bootstrap rules.
# Logging is stripped from release builds.
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

# Keep the manifest/JNI entry-point names stable, but allow R8 to optimize their bodies.
-keep,allowoptimization class com.parallax.shell.ParallaxKoChummiDedo { *; }
-keep,allowoptimization class com.parallax.shell.ParallaxLovers { *; }
-keep,allowoptimization class com.parallax.shell.ParallaxJaRaha {
    public static native <methods>;
    public static void loadShellLibs(java.lang.String);
}

# Everything else is intentionally shrinkable. Optional Java-side protection UI/helpers
# are not part of the tiny bootstrap and should disappear when unreferenced.
-repackageclasses com.parallax.shell
