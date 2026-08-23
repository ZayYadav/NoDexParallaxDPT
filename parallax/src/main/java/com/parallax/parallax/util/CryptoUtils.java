package com.parallax.parallax.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {
    private static final byte[] CONFIG_MAGIC = new byte[] {'P', 'A', 'R', '1'};
    public static final String RC4Transform = "RC4";
    private static final String HMAC_SHA256 = "HmacSHA256";

    public static byte[] rc4Crypt(byte[] key, byte[] in) {
        try {
            Cipher cipher = Cipher.getInstance(RC4Transform);
            SecretKeySpec spec = new SecretKeySpec(key, RC4Transform);
            cipher.init(Cipher.ENCRYPT_MODE,spec);
            return cipher.doFinal(in);
        } catch (Exception e) {
        }

        return null;
    }

    /**
     * Derive AES-256 key by HMAC-SHA256(randomKey, UTF-8(keyMaterial)).
     */
    public static byte[] hmacSha256(byte[] key, String keyMaterial) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("hmac key is empty");
        }
        if (keyMaterial == null || keyMaterial.isEmpty()) {
            throw new IllegalArgumentException("key material is empty");
        }
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            byte[] result = mac.doFinal(keyMaterial.getBytes(StandardCharsets.UTF_8));
            if (result == null || result.length != 32) {
                throw new IllegalStateException("unexpected hmac length");
            }
            return result;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("hmac-sha256 failed", e);
        }
    }

    public static byte[] aesEncrypt(byte[] key, byte[] iv, byte[] in) {
        try {
            Key secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec,ivParameterSpec);
            return cipher.doFinal(in);
        }
        catch (Exception e){
        }
        return null;
    }

    /**
     * Encrypt and authenticate a configuration payload. The versioned envelope is
     * {@code "PAR1" || AES-256-CBC(ciphertext) || HMAC-SHA256(header || ciphertext)}.
     * Separate encryption and authentication keys prevent key reuse across primitives.
     */
    public static byte[] encryptAuthenticatedConfig(byte[] masterKey, byte[] iv, byte[] in) {
        byte[] encryptionKey = hmacSha256(masterKey, "Parallax/config/encryption/v1");
        byte[] authenticationKey = hmacSha256(masterKey, "Parallax/config/authentication/v1");
        byte[] ciphertext = aesEncrypt(encryptionKey, iv, in);
        if (ciphertext == null) {
            throw new IllegalStateException("config encryption failed");
        }
        byte[] authenticated = new byte[CONFIG_MAGIC.length + ciphertext.length];
        System.arraycopy(CONFIG_MAGIC, 0, authenticated, 0, CONFIG_MAGIC.length);
        System.arraycopy(ciphertext, 0, authenticated, CONFIG_MAGIC.length, ciphertext.length);
        byte[] tag = hmacSha256(authenticationKey, authenticated);
        byte[] envelope = new byte[authenticated.length + tag.length];
        System.arraycopy(authenticated, 0, envelope, 0, authenticated.length);
        System.arraycopy(tag, 0, envelope, authenticated.length, tag.length);
        return envelope;
    }

    public static byte[] hmacSha256(byte[] key, byte[] input) {
        if (key == null || key.length == 0 || input == null) {
            throw new IllegalArgumentException("invalid hmac input");
        }
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac.doFinal(input);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("hmac-sha256 failed", e);
        }
    }
}
