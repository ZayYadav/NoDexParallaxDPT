package com.parallax.shell;

import androidx.annotation.Keep;

import com.parallax.parallax.BuildConfig;

/**
 * Created by parallax
 */
@Keep
public class Global {
    public static final String ZIP_LIB_DIR = ParallaxHuYaarBhai.z(984398091, 213, 91, 167, 154, 121, 241, 61, 14, 110, 26, 167, 25, 207);
    public static final String LIB_DIR = ParallaxHuYaarBhai.z(1298259859, 115, 51, 154, 14, 253, 248, 166, 159, 102, 71, 134, 151, 180);
    public static final String SHELL_SO_NAME = BuildConfig.SO_NAME;

    @Keep
    public volatile static boolean sIsReplacedClassLoader = false;

    @Keep
    public volatile static boolean sNeedCalledApplication = true;

    @Keep
    public volatile static boolean sRootBlocked = false;

    @Keep
    public volatile static int sProtectionBlockReason = ParallaxBhaiya.CLEAR;
}
