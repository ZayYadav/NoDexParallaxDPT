package com.parallax.parallax.util;

import java.security.SecureRandom;
import java.util.Arrays;

public class KeyUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static byte[] lastGeneratedKey;

    public static byte[] generateIV(byte[] key) {
        byte[] newKey = new byte[key.length];
        System.arraycopy(key, 0, newKey, 0, newKey.length);
        newKey[3] = 0x2f;
        newKey[9] = 0x76;
        return newKey;
    }

    public static synchronized byte[] generateKey() {
        // This 16-byte value is patched into the native shell and is the root secret for
        // build-bound payload derivations. Keep every bit random. Older code overwrote two
        // bytes after generation, unnecessarily reducing entropy without adding security.
        byte[] key = new byte[16];
        SECURE_RANDOM.nextBytes(key);

        // The high-value VM transform runs from the pre-extraction DEX injector, after the
        // APK pipeline has generated this key but before the native SO is patched. Retain one
        // short-lived defensive copy so that tier can seal Parallax.vm with the exact same
        // build secret. consumeLastGeneratedKey() destroys this extra copy after one use.
        if (lastGeneratedKey != null) Arrays.fill(lastGeneratedKey, (byte) 0);
        lastGeneratedKey = key.clone();
        return key;
    }

    public static synchronized byte[] consumeLastGeneratedKey() {
        if (lastGeneratedKey == null) return null;
        byte[] result = lastGeneratedKey.clone();
        Arrays.fill(lastGeneratedKey, (byte) 0);
        lastGeneratedKey = null;
        return result;
    }
}
