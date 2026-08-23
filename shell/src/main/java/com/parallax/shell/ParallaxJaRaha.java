package com.parallax.shell;

import com.parallax.shell.util.EnvUtils;

import java.io.File;

/** Tiny JNI bridge. Runtime work stays in the existing native library. */
public final class ParallaxJaRaha {
    private ParallaxJaRaha() {
    }

    public static native void craoc(String applicationClassName);
    public static native void ia();
    public static native String rcf();
    public static native void cbde(ClassLoader targetClassLoader);
    public static native void rde(ClassLoader classLoader, String elementName);
    public static native String gap();
    public static native String gdp();
    public static native Object ra(String originApplicationClassName);
    public static native String rapn();
    public static native void clinit();

    public static void loadShellLibs(String workspacePath) {
        String abi = EnvUtils.getAbiDirName();
        File lib = new File(new File(new File(workspacePath, Global.LIB_DIR), abi), Global.SHELL_SO_NAME);
        System.load(lib.getAbsolutePath());
    }
}
