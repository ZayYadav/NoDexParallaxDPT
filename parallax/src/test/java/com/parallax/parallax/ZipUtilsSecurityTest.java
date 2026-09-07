package com.parallax.parallax;

import com.parallax.parallax.util.ZipUtils;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

public class ZipUtilsSecurityTest {

    private static Path maliciousZip(Path dir, String entryName) throws Exception {
        Path zip = dir.resolve("malicious.zip");
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zip.toFile()))) {
            out.putNextEntry(new ZipEntry(entryName));
            out.write("blocked".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.closeEntry();
        }
        return zip;
    }

    @Test
    public void extractApkRejectsDotDotTraversal() throws Exception {
        Path root = Files.createTempDirectory("parallax-zip-slip-");
        Path out = root.resolve("out");
        Path escaped = root.resolve("escape.txt");
        Path zip = maliciousZip(root, "../escape.txt");

        try {
            ZipUtils.extractAPK(zip.toString(), out.toString());
            fail("malicious traversal archive must fail closed");
        } catch (IllegalStateException expected) {
            // expected
        }

        assertFalse("archive must not escape extraction root", Files.exists(escaped));
    }

    @Test
    public void unzipRejectsBackslashTraversal() throws Exception {
        Path root = Files.createTempDirectory("parallax-zip-slip-backslash-");
        Path out = root.resolve("out");
        Path escaped = root.resolve("escape.txt");
        Path zip = maliciousZip(root, "..\\escape.txt");

        try {
            ZipUtils.unZip(zip.toString(), out.toString());
            fail("malicious traversal archive must fail closed");
        } catch (IllegalStateException expected) {
            // expected
        }

        assertFalse("archive must not escape extraction root", Files.exists(escaped));
    }
}
