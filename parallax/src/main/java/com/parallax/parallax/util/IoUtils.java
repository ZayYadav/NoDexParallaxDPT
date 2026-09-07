package com.parallax.parallax.util;

/**
 * Fail-closed binary I/O helpers used by the protector.
 */
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public final class IoUtils {

    private IoUtils() {}

    public static byte[] readFile(String file, long offset, int len) {
        if (file == null || offset < 0 || len < 0) {
            throw new IllegalArgumentException("invalid file read range");
        }
        byte[] data = new byte[len];
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            if (offset > input.length() || input.length() - offset < len) {
                throw new IOException("requested range exceeds file length");
            }
            input.seek(offset);
            input.readFully(data);
            return data;
        } catch (IOException e) {
            throw new IllegalStateException("binary file read failed: " + new File(file).getName(), e);
        }
    }

    public static void writeFile(String dest, byte[] data, long offset) {
        if (dest == null || data == null || offset < 0) {
            throw new IllegalArgumentException("invalid ranged file write");
        }
        try (RandomAccessFile output = new RandomAccessFile(new File(dest), "rw")) {
            if (offset > output.length()) {
                throw new IOException("write offset exceeds file length");
            }
            output.seek(offset);
            output.write(data);
            output.getFD().sync();
        } catch (IOException e) {
            throw new IllegalStateException("binary file patch failed: " + new File(dest).getName(), e);
        }
    }

    public static byte[] readFile(String file) {
        if (file == null) {
            throw new IllegalArgumentException("file path is null");
        }
        try {
            return Files.readAllBytes(Path.of(file));
        } catch (IOException e) {
            throw new IllegalStateException("file read failed: " + new File(file).getName(), e);
        }
    }

    public static void writeFile(String dest, byte[] data) {
        writeFile(dest, data, false);
    }

    public static void appendFile(String dest, byte[] data) {
        writeFile(dest, data, true);
    }

    public static void writeFile(String dest, byte[] data, boolean append) {
        if (dest == null || data == null) {
            throw new IllegalArgumentException("invalid file write");
        }
        File target = new File(dest);
        File parent = target.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs() && !parent.isDirectory()) {
            throw new IllegalStateException("cannot create output directory");
        }
        try (FileOutputStream output = new FileOutputStream(target, append)) {
            output.write(data);
            output.flush();
            output.getFD().sync();
        } catch (IOException e) {
            throw new IllegalStateException("file write failed: " + target.getName(), e);
        }
    }

    public static void copyFile(String src, String dest) {
        if (src == null || dest == null) {
            throw new IllegalArgumentException("invalid file copy");
        }
        try {
            Files.copy(Path.of(src), Path.of(dest), StandardCopyOption.REPLACE_EXISTING);
            if (Files.size(Path.of(src)) != Files.size(Path.of(dest))) {
                throw new IOException("copied size mismatch");
            }
        } catch (IOException e) {
            throw new IllegalStateException("file copy failed", e);
        }
    }

    public static void close(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ignored) {
                // Cleanup-only helper. Data-path operations use try-with-resources above.
            }
        }
    }
}
