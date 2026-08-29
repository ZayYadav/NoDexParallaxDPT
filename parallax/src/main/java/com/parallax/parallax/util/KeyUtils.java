package com.parallax.parallax.util;

import com.parallax.parallax.dex.HighValueVmCoordinator;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

public class KeyUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static byte[] generateIV(byte[] key) {
        byte[] newKey = new byte[key.length];
        System.arraycopy(key, 0, newKey, 0, newKey.length);
        newKey[3] = 0x2f;
        newKey[9] = 0x76;
        return newKey;
    }

    public static byte[] generateKey() {
        // This 16-byte value is patched into the native shell and is the root secret for
        // build-bound payload derivations. Keep every bit random. Older code overwrote two
        // bytes after generation, unnecessarily reducing entropy without adding security.
        byte[] key = new byte[16];
        SECURE_RANDOM.nextBytes(key);

        // APK.process() generates this key on the main thread after unzip and before the
        // worker-based DPT extraction pass. That is the fail-closed choke point for the
        // optional high-value VM tier: selected original method bodies are replaced by tiny
        // Parallax16 trampolines here, then the normal hollowing pipeline only ever sees
        // those trampolines. Unsupported or unmatched selections abort the build.
        if (HighValueVmCoordinator.isEnabled()) {
            try {
                HighValueVmCoordinator.prepareCurrentWorkspace(key);
            } catch (IOException e) {
                Arrays.fill(key, (byte) 0);
                throw new IllegalStateException("High-value native VM preparation failed", e);
            }
        }
        return key;
    }
}
