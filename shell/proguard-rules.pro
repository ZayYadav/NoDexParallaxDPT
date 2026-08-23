# Parallax shell rules.
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int e(...);
    public static int w(...);
    public static int i(...);
    public static int v(...);
}

-repackageclasses com.parallax.shell

-keep class com.parallax.shell.ParallaxJaRaha { *; }
-keep class com.parallax.shell.ParallaxKoChummiDedo { *; }
-keep class com.parallax.shell.ParallaxLovers { *; }
-keep class com.parallax.shell.ParallaxLovers$* { *; }

# Requested branded protection entry points keep their class names.
-keepnames class com.parallax.shell.ParallaxHuMaalik
-keepnames class com.parallax.shell.ParallaxKaBhaiJangu
-keepnames class com.parallax.shell.ParallaxVirtualBhaiya
-keepnames class com.parallax.shell.ParallaxBhaiKiSecurity
-keepnames class com.parallax.shell.ParallaxBhaiya

# JNI symbol uses the exact class/method name; keep just that member stable.
-keepclassmembers class com.parallax.shell.ParallaxBhaiya {
    private static native int nativeEnvironmentState();
}

# Preserve the requested public security class name while allowing member optimization.
-keepnames class com.parallax.shell.ParallaxHuYaarBhai

-keep class com.parallax.parallax.ParallaxAaGaya { *; }
