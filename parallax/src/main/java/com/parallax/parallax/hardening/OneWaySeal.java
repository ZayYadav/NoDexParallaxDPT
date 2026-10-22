package com.parallax.parallax.hardening;

import com.parallax.parallax.builder.AndroidPackage;
import com.parallax.parallax.config.Const;
import com.parallax.parallax.util.LogUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Build-time half of the one-way seal. It refuses inputs that are already protected,
 * records the original DEX identities, audits the finished APK for recoverable original
 * bytecode, and erases every intermediate artifact instead of leaving it for undelete.
 */
public final class OneWaySeal {

    private static final int DEX_HEADER_SIZE = 112;
    private static final long MAX_SCAN_ENTRY_SIZE = 64L * 1024L * 1024L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int WIPE_BUFFER_SIZE = 64 * 1024;

    private OneWaySeal() {
    }

    public static final class Session {
        private final String inputPath;
        private final String inputSha256;
        private final Map<String, String> inputDexSha256;
        private final List<byte[]> inputDexHeaders;

        private Session(String inputPath,
                        String inputSha256,
                        Map<String, String> inputDexSha256,
                        List<byte[]> inputDexHeaders) {
            this.inputPath = inputPath;
            this.inputSha256 = inputSha256;
            this.inputDexSha256 = inputDexSha256;
            this.inputDexHeaders = inputDexHeaders;
        }

        public void finish(String outputPath) throws IOException {
            if (outputPath == null || outputPath.isEmpty()) {
                throw new IOException("One-way seal: protection finished without an output path");
            }
            File output = new File(outputPath);
            if (!output.isFile() || output.length() == 0) {
                throw new IOException("One-way seal: protected APK is missing: " + outputPath);
            }

            try {
                audit(output);
                writeSeal(output);
            } catch (IOException failure) {
                secureDelete(output);
                throw failure;
            }
        }

        private void audit(File output) throws IOException {
            try (ZipFile zip = new ZipFile(output)) {
                assertShellMarkers(zip);
                assertSingleDex(zip);
                assertNoOriginalDexBytes(zip);
            }
        }

        private void assertShellMarkers(ZipFile zip) throws IOException {
            if (zip.getEntry("assets/" + Const.KEY_SHELL_CONFIG_STORE_NAME) == null) {
                throw new IOException("One-way seal audit failed: encrypted shell config is missing");
            }
            if (zip.getEntry("assets/" + Const.KEY_CODE_ITEM_STORE_NAME) == null) {
                throw new IOException("One-way seal audit failed: encrypted method vault is missing");
            }
            boolean foundLoader = false;
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (name.startsWith("assets/" + Const.KEY_LIBS_DIR_NAME + "/") && name.endsWith(".so")) {
                    foundLoader = true;
                    break;
                }
            }
            if (!foundLoader) {
                throw new IOException("One-way seal audit failed: native loader library is missing");
            }
        }

        private void assertSingleDex(ZipFile zip) throws IOException {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.matches("classes\\d*\\.dex") && !"classes.dex".equals(name)) {
                    throw new IOException("One-way seal audit failed: recoverable keep-classes dex present: " + name);
                }
            }
            ZipEntry bootstrap = zip.getEntry("classes.dex");
            if (bootstrap == null || bootstrap.getSize() == 0) {
                throw new IOException("One-way seal audit failed: bootstrap classes.dex is missing");
            }
        }

        private void assertNoOriginalDexBytes(ZipFile zip) throws IOException {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                long size = entry.getSize();
                if (size > MAX_SCAN_ENTRY_SIZE) {
                    // classes.dex is the only entry that can carry the combined payload; if it
                    // is too large to inspect, the seal cannot prove the invariant and fails.
                    if ("classes.dex".equals(entry.getName())) {
                        throw new IOException("One-way seal audit failed: classes.dex is too large to verify ("
                                + size + " bytes)");
                    }
                    LogUtils.warn("One-way seal: skipping opaque large entry from bytecode scan: %s (%d bytes)",
                            entry.getName(), size);
                    continue;
                }
                byte[] data;
                try (InputStream input = zip.getInputStream(entry)) {
                    data = input.readAllBytes();
                }
                for (byte[] header : inputDexHeaders) {
                    if (indexOf(data, header) >= 0) {
                        throw new IOException("One-way seal audit failed: original DEX bytes are recoverable from "
                                + entry.getName());
                    }
                }
                String digest = sha256(data);
                for (Map.Entry<String, String> original : inputDexSha256.entrySet()) {
                    if (original.getValue().equals(digest)) {
                        throw new IOException("One-way seal audit failed: original DEX is present as "
                                + entry.getName() + " (source " + original.getKey() + ")");
                    }
                }
            }
        }

        private void writeSeal(File output) throws IOException {
            String outputSha256 = sha256(output);
            StringBuilder seal = new StringBuilder();
            seal.append("ONE-WAY SEAL v1\n");
            seal.append("created=").append(Instant.now()).append('\n');
            seal.append("input=").append(inputPath).append('\n');
            seal.append("input_sha256=").append(inputSha256).append('\n');
            for (Map.Entry<String, String> dex : inputDexSha256.entrySet()) {
                seal.append("input_").append(dex.getKey()).append("_sha256=")
                        .append(dex.getValue()).append('\n');
            }
            seal.append("output=").append(output.getAbsolutePath()).append('\n');
            seal.append("output_sha256=").append(outputSha256).append('\n');
            seal.append("checks=already-protected,keep-classes,original-dex-bytes,shell-markers\n");

            File sealFile = new File(output.getAbsolutePath() + Const.ONE_WAY_SEAL_SUFFIX);
            Files.write(sealFile.toPath(), seal.toString().getBytes(StandardCharsets.UTF_8));
            LogUtils.info("One-way seal written: %s", sealFile.getAbsolutePath());
            LogUtils.info("One-way seal output SHA-256: %s", outputSha256);
        }
    }

    public static Session begin(AndroidPackage pkg) throws IOException {
        File input = new File(pkg.getFilePath());
        if (!input.isFile()) {
            throw new IOException("One-way seal: input APK does not exist: " + input.getAbsolutePath());
        }

        try (ZipFile zip = new ZipFile(input)) {
            assertNotAlreadyProtected(zip);
            Map<String, String> dexHashes = new LinkedHashMap<>();
            List<byte[]> dexHeaders = new ArrayList<>();
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() || !name.matches("classes\\d*\\.dex")) {
                    continue;
                }
                byte[] header;
                try (InputStream stream = zip.getInputStream(entry)) {
                    header = stream.readNBytes(DEX_HEADER_SIZE);
                }
                if (header.length != DEX_HEADER_SIZE
                        || header[0] != 'd' || header[1] != 'e' || header[2] != 'x' || header[3] != '\n') {
                    throw new IOException("One-way seal: input entry is not a valid DEX: " + name);
                }
                dexHeaders.add(header);
                dexHashes.put(name, sha256(entryBytes(zip, entry)));
            }
            if (dexHeaders.isEmpty()) {
                throw new IOException("One-way seal: input APK has no classes*.dex files");
            }
            String inputSha256 = sha256(input);
            LogUtils.info("One-way seal armed: %s (%d DEX file(s))", input.getAbsolutePath(), dexHeaders.size());
            return new Session(input.getAbsolutePath(), inputSha256, dexHashes, dexHeaders);
        }
    }

    private static void assertNotAlreadyProtected(ZipFile zip) throws IOException {
        boolean hasConfig = zip.getEntry("assets/" + Const.KEY_SHELL_CONFIG_STORE_NAME) != null;
        boolean hasVault = zip.getEntry("assets/" + Const.KEY_CODE_ITEM_STORE_NAME) != null;
        boolean hasLoader = false;
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            String name = entries.nextElement().getName();
            if (name.startsWith("assets/" + Const.KEY_LIBS_DIR_NAME + "/") && name.endsWith(".so")) {
                hasLoader = true;
                break;
            }
        }
        if (hasConfig || (hasVault && hasLoader)) {
            throw new IOException("One-way seal refused: input APK is already Parallax-protected. "
                    + "Protecting it a second time can corrupt the bootstrap and cannot restore the original. "
                    + "Use the unprotected source APK.");
        }
    }

    private static byte[] entryBytes(ZipFile zip, ZipEntry entry) throws IOException {
        try (InputStream input = zip.getInputStream(entry)) {
            return input.readAllBytes();
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || haystack.length < needle.length) {
            return -1;
        }
        final int last = haystack.length - needle.length;
        final byte first = needle[0];
        outer:
        for (int i = 0; i <= last; i++) {
            if (haystack[i] != first) {
                continue;
            }
            for (int j = 1; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    public static void secureDelete(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        try {
            if (Files.isSymbolicLink(file.toPath())) {
                // Never follow a link out of the protection workspace.
                file.delete();
                return;
            }
            if (file.isDirectory()) {
                File[] children = file.listFiles();
                if (children != null) {
                    Arrays.sort(children);
                    for (int i = children.length - 1; i >= 0; i--) {
                        secureDelete(children[i]);
                    }
                }
                if (!file.delete()) {
                    LogUtils.warn("One-way seal: could not delete directory %s", file.getAbsolutePath());
                }
                return;
            }

            long length = file.length();
            if (length > 0) {
                try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
                    byte[] buffer = new byte[WIPE_BUFFER_SIZE];
                    long remaining = length;
                    while (remaining > 0) {
                        RANDOM.nextBytes(buffer);
                        int chunk = (int) Math.min(buffer.length, remaining);
                        raf.write(buffer, 0, chunk);
                        remaining -= chunk;
                    }
                    raf.getFD().sync();
                }
            }
            if (!file.delete()) {
                LogUtils.warn("One-way seal: could not delete %s", file.getAbsolutePath());
            }
        } catch (IOException e) {
            LogUtils.warn("One-way seal: secure delete failed for %s: %s", file.getAbsolutePath(), e.getMessage());
            file.delete();
        }
    }

    public static String sha256(File file) throws IOException {
        try (InputStream input = Files.newInputStream(file.toPath())) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[WIPE_BUFFER_SIZE];
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            return toHex(digest.digest());
        } catch (Exception e) {
            throw new IOException("SHA-256 failed for " + file, e);
        }
    }

    private static String sha256(byte[] data) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHex(digest.digest(data));
        } catch (Exception e) {
            throw new IOException("SHA-256 failed", e);
        }
    }

    private static String toHex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte value : data) {
            out.append(String.format(Locale.US, "%02x", value));
        }
        return out.toString();
    }
}
