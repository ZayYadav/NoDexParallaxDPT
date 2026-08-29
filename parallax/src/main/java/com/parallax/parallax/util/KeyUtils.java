package com.parallax.parallax.util;

import java.security.SecureRandom;

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
        return key;
    }
}
