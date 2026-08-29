package com.parallax.parallax;

import com.parallax.parallax.util.CryptoUtils;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CodeItemPayloadCryptoTest {

    private static final byte[] AAD =
            "Parallax/codeitem/payload/v2".getBytes(StandardCharsets.US_ASCII);

    @Test
    public void aesGcmSealedVaultRoundTrips() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (0x31 + i);
        }
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) (0x70 + i);
        }
        byte[] plaintext = "method-body-vault".getBytes(StandardCharsets.UTF_8);

        byte[] sealed = CryptoUtils.aesGcmEncrypt(key, nonce, AAD, plaintext);
        Assert.assertEquals(plaintext.length + 16, sealed.length);
        Assert.assertFalse(Arrays.equals(plaintext,
                Arrays.copyOf(sealed, Math.min(plaintext.length, sealed.length))));

        Assert.assertArrayEquals(plaintext, decrypt(key, nonce, AAD, sealed));
    }

    @Test
    public void aesGcmRejectsCiphertextOrTagTampering() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        Arrays.fill(key, (byte) 0x42);
        Arrays.fill(nonce, (byte) 0x24);
        byte[] sealed = CryptoUtils.aesGcmEncrypt(
                key, nonce, AAD, "protected".getBytes(StandardCharsets.UTF_8));

        sealed[sealed.length - 1] ^= 0x01;
        try {
            decrypt(key, nonce, AAD, sealed);
            Assert.fail("tampered AES-GCM payload must not authenticate");
        } catch (GeneralSecurityException expected) {
            // Authentication failure is the required behavior.
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void aesGcmRejectsWrongNonceSize() {
        CryptoUtils.aesGcmEncrypt(new byte[32], new byte[8], AAD, new byte[] {1});
    }

    private static byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] sealed)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(sealed);
    }
}
