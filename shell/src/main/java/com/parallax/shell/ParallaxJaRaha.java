package com.parallax.shell;

import android.util.Log;

import androidx.annotation.Keep;

import com.parallax.shell.util.EnvUtils;

import java.io.File;

/** Native bridge used by the Parallax shell. */
@Keep
public class ParallaxJaRaha {
    private static final String TAG = "parallax_" + ParallaxJaRaha.class.getSimpleName();

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
        final String[] allowLibNames = {Global.SHELL_SO_NAME};
        try {
            String abiDirName = EnvUtils.getAbiDirName();
            File shellLibsFile = new File(workspacePath + File.separator + Global.LIB_DIR + File.separator + abiDirName);
            File[] files = shellLibsFile.listFiles();
            if (files != null) {
                for (File shellLibPath : files) {
                    String fullLibPath = shellLibPath.getAbsolutePath();
                    for (String libName : allowLibNames) {
                        String libSuffix = File.separator + libName;
                        if (fullLibPath.endsWith(libSuffix)) {
                            Log.d(TAG, "loadShellLibs: " + fullLibPath);
                            System.load(fullLibPath);
                        }
                    }
                }
            }
        } catch (Throwable e) {
            Log.w(TAG, e);
        }
    }
}
