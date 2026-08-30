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
        // build-bound payload derivations. Keep every bit random.
        byte[] key = new byte[16];
        SECURE_RANDOM.nextBytes(key);

        // APK protection now performs conservative zero-config VM routing here. Explicit
        // --high-value-methods rules still retain strict/fail-closed behavior. AAB reaches
        // this method before its DEX workspace exists, so the coordinator safely no-ops there.
        try {
            HighValueVmCoordinator.prepareCurrentWorkspace(key);
        } catch (IOException e) {
            Arrays.fill(key, (byte) 0);
            throw new IllegalStateException("Native VM preparation failed", e);
        }
        return key;
    }
}
