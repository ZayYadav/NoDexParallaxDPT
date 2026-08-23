package com.parallax.shell;

import com.parallax.parallax.BuildConfig;

/** Minimal bootstrap state/constants. Keep this class dependency-free so R8 can strip
 * optional Java-side protection/UI helpers from the shell dex. */
public final class Global {
    public static final String ZIP_LIB_DIR = "ParallaxLoveU";
    public static final String LIB_DIR = "libs";
    public static final String SHELL_SO_NAME = BuildConfig.SO_NAME;

    public static volatile boolean sIsReplacedClassLoader = false;
    public static volatile boolean sNeedCalledApplication = true;

    private Global() {
    }
}
