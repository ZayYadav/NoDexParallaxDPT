package com.parallax.parallax.builder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import com.parallax.parallax.config.Const;
import com.parallax.parallax.config.ShellConfig;

import org.junit.Before;
import org.junit.Test;

public class BootstrapManifestNamesTest {

    private static final String SHELL_PACKAGE = "com.parallax.protection";
    private static final String APPLICATION = SHELL_PACKAGE + ".ParallaxKiSettingKarwaDo";
    private static final String FACTORY = SHELL_PACKAGE + ".ParallaxKoLadkiChahiye";

    @Before
    public void setUp() {
        ShellConfig.getInstance().init(SHELL_PACKAGE);
    }

    @Test
    public void apkManifestBootstrapNamesMatchCurrentShellClasses() {
        Apk apk = new Apk.Builder().build();
        assertEquals(APPLICATION, apk.getProxyApplicationName());
        assertEquals(FACTORY, apk.getProxyComponentFactory());
        assertFalse(apk.getProxyApplicationName().contains("ParallaxKoChummiDedo"));
    }

    @Test
    public void aabManifestBootstrapNamesMatchCurrentShellClasses() {
        Aab aab = new Aab.Builder().build();
        assertEquals(APPLICATION, aab.getProxyApplicationName());
        assertEquals(FACTORY, aab.getProxyComponentFactory());
        assertFalse(aab.getProxyApplicationName().contains("ParallaxKoChummiDedo"));
    }

    @Test
    public void jniBootstrapClassNameMatchesApplicationClass() {
        assertEquals("ParallaxKiSettingKarwaDo", Const.KEY_JNI_BASE_CLASS_NAME);
        assertEquals("Lcom/parallax/protection/ParallaxKiSettingKarwaDo;",
                ShellConfig.getInstance().getJniClassNameSig());
    }
}
