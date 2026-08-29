package com.parallax.parallax.builder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import com.parallax.parallax.config.Const;
import com.parallax.parallax.config.ShellConfig;

import org.junit.Before;
import org.junit.Test;

public class BootstrapManifestNamesTest {

    private static final String SHELL_PACKAGE = "Parallax.Enc";
    private static final String APPLICATION = SHELL_PACKAGE + ".Parallax1";
    private static final String FACTORY = SHELL_PACKAGE + ".Parallax2";

    @Before
    public void setUp() {
        ShellConfig.getInstance().init(SHELL_PACKAGE);
    }

    @Test
    public void apkManifestBootstrapNamesMatchCurrentShellClasses() {
        Apk apk = new Apk.Builder().build();
        assertEquals(APPLICATION, apk.getProxyApplicationName());
        assertEquals(FACTORY, apk.getProxyComponentFactory());
        assertFalse(apk.getProxyApplicationName().contains("ParallaxKiSettingKarwaDo"));
    }

    @Test
    public void aabManifestBootstrapNamesMatchCurrentShellClasses() {
        Aab aab = new Aab.Builder().build();
        assertEquals(APPLICATION, aab.getProxyApplicationName());
        assertEquals(FACTORY, aab.getProxyComponentFactory());
        assertFalse(aab.getProxyApplicationName().contains("ParallaxKoLadkiChahiye"));
    }

    @Test
    public void jniBootstrapClassNameMatchesApplicationClass() {
        assertEquals("Parallax1", Const.KEY_JNI_BASE_CLASS_NAME);
        assertEquals("Parallax2", Const.KEY_COMPONENT_FACTORY_BASE_CLASS_NAME);
        assertEquals("Parallax3", Const.KEY_GATE_BASE_CLASS_NAME);
        assertEquals("LParallax/Enc/Parallax1;",
                ShellConfig.getInstance().getJniClassNameSig());
    }

    @Test
    public void staleProtectionNamespaceCannotOverrideReleaseAbi() {
        ShellConfig.getInstance().init("com.parallax.protection");
        assertEquals(SHELL_PACKAGE, ShellConfig.getInstance().getShellPackageName());
        assertEquals(APPLICATION, new Apk.Builder().build().getProxyApplicationName());
    }
}
