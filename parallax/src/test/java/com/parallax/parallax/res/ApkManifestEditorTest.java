package com.parallax.parallax.res;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

public class ApkManifestEditorTest {

    @Test
    public void releaseApplicationNameIsNotRewrittenToSourceClassName() {
        String releaseName = "Parallax.Enc.Parallax1";
        String resolved = ApkManifestEditor.resolveApplicationName(releaseName);

        assertEquals(releaseName, resolved);
        assertFalse(resolved.contains("ParallaxKiSettingKarwaDo"));
    }

    @Test
    public void releaseComponentFactoryNameIsNotRewrittenToLegacyAlias() {
        String releaseName = "Parallax.Enc.Parallax2";
        String resolved = ApkManifestEditor.resolveAppComponentFactoryName(releaseName);

        assertEquals(releaseName, resolved);
        assertFalse(resolved.contains("ParallaxKoLadkiChahiye"));
    }
}
