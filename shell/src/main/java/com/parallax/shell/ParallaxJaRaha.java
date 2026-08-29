package com.parallax.shell;

import com.parallax.shell.util.EnvUtils;

import java.io.File;

/**
 * Thin Java bridge retained as the deterministic Parallax11 shell ABI anchor.
 * Native methods are owned by the dynamically registered bootstrap Application;
 * keeping this class non-native lets R8 apply its fixed Parallax11 mapping safely.
 */
public final class ParallaxJaRaha {
    private ParallaxJaRaha() {
    }

    public static void craoc(String applicationClassName) {
        ParallaxKiSettingKarwaDo.craoc(applicationClassName);
    }

    public static void ia() {
        ParallaxKiSettingKarwaDo.ia();
    }

    public static String rcf() {
        return ParallaxKiSettingKarwaDo.rcf();
    }

    public static void cbde(ClassLoader targetClassLoader) {
        ParallaxKiSettingKarwaDo.cbde(targetClassLoader);
    }

    public static void rde(ClassLoader classLoader, String elementName) {
        ParallaxKiSettingKarwaDo.rde(classLoader, elementName);
    }

    public static String gap() {
        return ParallaxKiSettingKarwaDo.gap();
    }

    public static String gdp() {
        return ParallaxKiSettingKarwaDo.gdp();
    }

    public static Object ra(String originApplicationClassName) {
        return ParallaxKiSettingKarwaDo.ra(originApplicationClassName);
    }

    public static String rapn() {
        return ParallaxKiSettingKarwaDo.rapn();
    }

    public static void clinit() {
        ParallaxKiSettingKarwaDo.clinit();
    }

    public static void loadShellLibs(String workspacePath) {
        String abi = EnvUtils.getAbiDirName();
        File lib = new File(new File(new File(workspacePath, Global.LIB_DIR), abi), Global.SHELL_SO_NAME);
        System.load(lib.getAbsolutePath());
    }
}
