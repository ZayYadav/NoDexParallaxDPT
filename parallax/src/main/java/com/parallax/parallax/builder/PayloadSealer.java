package com.parallax.parallax.builder;

import com.parallax.parallax.config.Const;
import com.parallax.parallax.util.CryptoUtils;
import com.parallax.parallax.util.LogUtils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/** Shared authenticated payload sealing contract for APK and AAB protection. */
final class PayloadSealer {
    private static final String DEX_AUTH_COMMENT_PREFIX = "PXH1:";
    private static final String DEX_AUTH_LABEL = "Parallax/dex/authentication/v1";
    private static final int DEX_AUTH_TAG_HEX_LENGTH = 64;

    private static final byte[] CODE_ITEM_MAGIC = new byte[] {'P', 'C', 'I', '3'};
    private static final String CODE_ITEM_KEY_LABEL = "Parallax/codeitem/encryption/v3";
    private static final String CODE_ITEM_AAD_PREFIX = "Parallax/codeitem/payload/v3/";
    private static final int CODE_ITEM_LENGTH_SIZE = 4;
    private static final int CODE_ITEM_NONCE_SIZE = 12;

    private static final long MAX_METHOD_VAULT_BYTES = 512L * 1024L * 1024L;
    private static final long MAX_DEX_ARCHIVE_BYTES = 768L * 1024L * 1024L;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PayloadSealer() {}

    static void sealCodeItemPayload(AndroidPackage pkg, String packageDir, byte[] masterKey)
            throws IOException {
        validateMasterKey(masterKey);
        File codeItemFile = new File(pkg.getOutAssetsDir(packageDir),
                Const.KEY_CODE_ITEM_STORE_NAME);
        if (!codeItemFile.isFile() || codeItemFile.length() < 4
                || codeItemFile.length() > MAX_METHOD_VAULT_BYTES) {
            throw new IOException("protected method-body vault missing or outside size policy");
        }

        byte[] plaintext = null;
        byte[] compressed = null;
        byte[] payloadKey = null;
        byte[] nonce = null;
        byte[] aad = null;
        byte[] ciphertext = null;
        byte[] envelope = null;
        try {
            plaintext = Files.readAllBytes(codeItemFile.toPath());
            compressed = compress(plaintext);
            payloadKey = CryptoUtils.hmacSha256(masterKey, CODE_ITEM_KEY_LABEL);
            nonce = new byte[CODE_ITEM_NONCE_SIZE];
            RANDOM.nextBytes(nonce);
            aad = (CODE_ITEM_AAD_PREFIX + plaintext.length)
                    .getBytes(StandardCharsets.US_ASCII);
            ciphertext = CryptoUtils.aesGcmEncrypt(payloadKey, nonce, aad, compressed);

            envelope = new byte[CODE_ITEM_MAGIC.length + CODE_ITEM_LENGTH_SIZE
                    + nonce.length + ciphertext.length];
            int cursor = 0;
            System.arraycopy(CODE_ITEM_MAGIC, 0, envelope, cursor, CODE_ITEM_MAGIC.length);
            cursor += CODE_ITEM_MAGIC.length;
            writeBigEndianInt(envelope, cursor, plaintext.length);
            cursor += CODE_ITEM_LENGTH_SIZE;
            System.arraycopy(nonce, 0, envelope, cursor, nonce.length);
            cursor += nonce.length;
            System.arraycopy(ciphertext, 0, envelope, cursor, ciphertext.length);

            atomicWrite(codeItemFile, envelope);
            LogUtils.info("Method-body vault PCI3 sealed: raw=%d compressed=%d sealed=%d",
                    plaintext.length, compressed.length, envelope.length);
        } finally {
            zero(plaintext);
            zero(compressed);
            zero(payloadKey);
            zero(nonce);
            zero(aad);
            zero(ciphertext);
            zero(envelope);
        }
    }

    static void compactAndAuthenticateDexPayload(
            AndroidPackage pkg, String packageDir, byte[] masterKey) throws IOException {
        validateMasterKey(masterKey);
        File payload = new File(pkg.getOutAssetsDir(packageDir), Const.KEY_DEXES_STORE_NAME);
        if (!payload.isFile() || payload.length() <= 0
                || payload.length() > MAX_DEX_ARCHIVE_BYTES) {
            throw new IOException("protected DEX archive missing or outside size policy");
        }

        String placeholder = DEX_AUTH_COMMENT_PREFIX + "0".repeat(DEX_AUTH_TAG_HEX_LENGTH);
        File compact = new File(payload.getParentFile(), payload.getName() + ".compact");
        try {
            try (ZipFile source = new ZipFile(payload);
                 ZipOutputStream output = new ZipOutputStream(
                         new BufferedOutputStream(new FileOutputStream(compact)))) {
                output.setLevel(Deflater.BEST_COMPRESSION);
                output.setComment(placeholder);
                Enumeration<? extends ZipEntry> entries = source.entries();
                byte[] buffer = new byte[32768];
                int count = 0;
                while (entries.hasMoreElements()) {
                    ZipEntry sourceEntry = entries.nextElement();
                    if (sourceEntry.isDirectory()) {
                        continue;
                    }
                    if (++count > 128) {
                        throw new IOException("too many protected DEX entries");
                    }
                    ZipEntry target = new ZipEntry(sourceEntry.getName());
                    output.putNextEntry(target);
                    try (InputStream input = new BufferedInputStream(source.getInputStream(sourceEntry))) {
                        int read;
                        while ((read = input.read(buffer)) != -1) {
                            output.write(buffer, 0, read);
                        }
                    }
                    output.closeEntry();
                }
                output.finish();
            }

            if (!compact.isFile() || compact.length() <= 0
                    || compact.length() > MAX_DEX_ARCHIVE_BYTES) {
                throw new IOException("compacted DEX archive outside size policy");
            }
            authenticateDexZip(compact, masterKey, placeholder);
            moveReplace(compact, payload);
            if (!payload.isFile() || payload.length() <= 0) {
                throw new IOException("authenticated DEX archive replacement failed");
            }
        } finally {
            Files.deleteIfExists(compact.toPath());
        }
    }

    private static void authenticateDexZip(
            File compact, byte[] masterKey, String placeholder) throws IOException {
        byte[] zipBytes = null;
        byte[] authenticationKey = null;
        byte[] authenticatedPrefix = null;
        byte[] tag = null;
        try {
            zipBytes = Files.readAllBytes(compact.toPath());
            byte[] placeholderBytes = placeholder.getBytes(StandardCharsets.US_ASCII);
            int eocdOffset = zipBytes.length - placeholderBytes.length - 22;
            if (eocdOffset < 0
                    || (zipBytes[eocdOffset] & 0xff) != 0x50
                    || (zipBytes[eocdOffset + 1] & 0xff) != 0x4b
                    || (zipBytes[eocdOffset + 2] & 0xff) != 0x05
                    || (zipBytes[eocdOffset + 3] & 0xff) != 0x06) {
                throw new IOException("protected DEX EOCD missing");
            }

            int commentLength = (zipBytes[eocdOffset + 20] & 0xff)
                    | ((zipBytes[eocdOffset + 21] & 0xff) << 8);
            if (commentLength != placeholderBytes.length
                    || eocdOffset + 22 + commentLength != zipBytes.length) {
                throw new IOException("protected DEX comment layout invalid");
            }

            authenticationKey = CryptoUtils.hmacSha256(masterKey, DEX_AUTH_LABEL);
            authenticatedPrefix = Arrays.copyOf(zipBytes, eocdOffset + 20);
            tag = CryptoUtils.hmacSha256(authenticationKey, authenticatedPrefix);
            String finalComment = DEX_AUTH_COMMENT_PREFIX + hex(tag);
            byte[] finalCommentBytes = finalComment.getBytes(StandardCharsets.US_ASCII);
            if (finalCommentBytes.length != placeholderBytes.length) {
                throw new IOException("protected DEX authentication tag length invalid");
            }
            System.arraycopy(finalCommentBytes, 0, zipBytes,
                    eocdOffset + 22, finalCommentBytes.length);
            atomicWrite(compact, zipBytes);
        } finally {
            zero(zipBytes);
            zero(authenticationKey);
            zero(authenticatedPrefix);
            zero(tag);
        }
    }

    private static byte[] compress(byte[] plaintext) throws IOException {
        ByteArrayOutputStream output =
                new ByteArrayOutputStream(Math.max(256, plaintext.length / 2));
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        try (DeflaterOutputStream stream =
                     new DeflaterOutputStream(output, deflater, 32768)) {
            stream.write(plaintext);
            stream.finish();
        } finally {
            deflater.end();
        }
        return output.toByteArray();
    }

    private static void atomicWrite(File target, byte[] data) throws IOException {
        File parent = target.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new IOException("cannot create payload directory");
        }
        File temp = new File(parent, "." + target.getName() + ".sealed.tmp");
        try (FileOutputStream output = new FileOutputStream(temp, false)) {
            output.write(data);
            output.flush();
            output.getFD().sync();
        }
        moveReplace(temp, target);
    }

    private static void moveReplace(File source, File target) throws IOException {
        try {
            Files.move(source.toPath(), target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void validateMasterKey(byte[] key) {
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("per-APK master key must be 16 bytes");
        }
    }

    private static String hex(byte[] data) {
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            out[i * 2] = alphabet[value >>> 4];
            out[i * 2 + 1] = alphabet[value & 0x0f];
        }
        return new String(out);
    }

    private static void writeBigEndianInt(byte[] target, int offset, int value) {
        target[offset] = (byte) ((value >>> 24) & 0xff);
        target[offset + 1] = (byte) ((value >>> 16) & 0xff);
        target[offset + 2] = (byte) ((value >>> 8) & 0xff);
        target[offset + 3] = (byte) (value & 0xff);
    }

    private static void zero(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
