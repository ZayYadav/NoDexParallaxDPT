package com.parallax.parallax.hardening;

import com.parallax.parallax.builder.AndroidPackage;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class OneWaySealTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void alreadyProtectedInputIsRejected() throws Exception {
        File input = new File(temporaryFolder.getRoot(), "already-protected.apk");
        writeZip(input, new Entry("classes.dex", fakeDex(1)),
                new Entry("assets/ItsParallaxBaby", "config".getBytes(StandardCharsets.UTF_8)),
                new Entry("assets/Parallax.love", "vault".getBytes(StandardCharsets.UTF_8)),
                new Entry("assets/ParallaxLoveU/arm64/ParallaxLover.so", "elf".getBytes(StandardCharsets.UTF_8)));

        try {
            OneWaySeal.begin(new TestPackage(input.getAbsolutePath()));
            Assert.fail("already protected APK must be rejected");
        } catch (IOException expected) {
            Assert.assertTrue(expected.getMessage().contains("already Parallax-protected"));
        }
    }

    @Test
    public void cleanInputStartsSession() throws Exception {
        File input = new File(temporaryFolder.getRoot(), "clean.apk");
        writeZip(input, new Entry("classes.dex", fakeDex(7)));

        OneWaySeal.Session session = OneWaySeal.begin(new TestPackage(input.getAbsolutePath()));
        Assert.assertNotNull(session);
    }

    @Test
    public void auditAcceptsSealedOutput() throws Exception {
        File input = new File(temporaryFolder.getRoot(), "clean.apk");
        writeZip(input, new Entry("classes.dex", fakeDex(7)));
        OneWaySeal.Session session = OneWaySeal.begin(new TestPackage(input.getAbsolutePath()));

        File output = new File(temporaryFolder.getRoot(), "protected.apk");
        writeZip(output,
                new Entry("classes.dex", fakeDex(99)),
                new Entry("assets/ItsParallaxBaby", "config".getBytes(StandardCharsets.UTF_8)),
                new Entry("assets/Parallax.love", "vault".getBytes(StandardCharsets.UTF_8)),
                new Entry("assets/ParallaxLoveU/arm64/ParallaxLover.so", "elf".getBytes(StandardCharsets.UTF_8)));

        session.finish(output.getAbsolutePath());

        Assert.assertTrue(output.isFile());
        File seal = new File(output.getAbsolutePath() + ".oneway");
        Assert.assertTrue(seal.isFile());
        String text = new String(Files.readAllBytes(seal.toPath()), StandardCharsets.UTF_8);
        Assert.assertTrue(text.contains("ONE-WAY SEAL v1"));
        Assert.assertTrue(text.contains("checks=already-protected,keep-classes,original-dex-bytes,shell-markers"));
    }

    @Test
    public void auditRejectsLeakedOriginalDex() throws Exception {
        byte[] original = fakeDex(7);
        File input = new File(temporaryFolder.getRoot(), "clean.apk");
        writeZip(input, new Entry("classes.dex", original));
        OneWaySeal.Session session = OneWaySeal.begin(new TestPackage(input.getAbsolutePath()));

        byte[] leak = new byte[original.length + 64];
        System.arraycopy(original, 0, leak, 32, original.length);
        File output = new File(temporaryFolder.getRoot(), "leaky.apk");
        writeZip(output,
                new Entry("classes.dex", fakeDex(99)),
                new Entry("assets/leak.bin", leak),
                new Entry("assets/ItsParallaxBaby", "config".getBytes(StandardCharsets.UTF_8)),
                new Entry("assets/Parallax.love", "vault".getBytes(StandardCharsets.UTF_8)),
                new Entry("assets/ParallaxLoveU/arm64/ParallaxLover.so", "elf".getBytes(StandardCharsets.UTF_8)));

        try {
            session.finish(output.getAbsolutePath());
            Assert.fail("leaked original DEX must be rejected");
        } catch (IOException expected) {
            Assert.assertTrue(expected.getMessage().contains("original DEX bytes"));
        }
        Assert.assertFalse("unsafe output must be erased", output.exists());
    }

    @Test
    public void auditRejectsKeepClassesDex() throws Exception {
        File input = new File(temporaryFolder.getRoot(), "clean.apk");
        writeZip(input, new Entry("classes.dex", fakeDex(7)));
        OneWaySeal.Session session = OneWaySeal.begin(new TestPackage(input.getAbsolutePath()));

        File output = new File(temporaryFolder.getRoot(), "keep.apk");
        writeZip(output,
                new Entry("classes.dex", fakeDex(99)),
                new Entry("classes2.dex", fakeDex(100)),
                new Entry("assets/ItsParallaxBaby", "config".getBytes(StandardCharsets.UTF_8)),
                new Entry("assets/Parallax.love", "vault".getBytes(StandardCharsets.UTF_8)),
                new Entry("assets/ParallaxLoveU/arm64/ParallaxLover.so", "elf".getBytes(StandardCharsets.UTF_8)));

        try {
            session.finish(output.getAbsolutePath());
            Assert.fail("keep-classes dex must be rejected");
        } catch (IOException expected) {
            Assert.assertTrue(expected.getMessage().contains("keep-classes"));
        }
    }

    @Test
    public void secureDeleteRemovesFile() throws Exception {
        File target = new File(temporaryFolder.getRoot(), "secret.bin");
        byte[] payload = new byte[8192];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) i;
        }
        Files.write(target.toPath(), payload);

        OneWaySeal.secureDelete(target);

        Assert.assertFalse(target.exists());
    }

    @Test
    public void secureDeleteRecursesDirectories() throws Exception {
        File directory = temporaryFolder.newFolder("workspace");
        File nested = new File(directory, "nested");
        Assert.assertTrue(nested.mkdirs());
        Files.write(new File(directory, "a.dex").toPath(), fakeDex(1));
        Files.write(new File(nested, "b.dex").toPath(), fakeDex(2));

        OneWaySeal.secureDelete(directory);

        Assert.assertFalse(directory.exists());
    }

    private static byte[] fakeDex(int marker) {
        byte[] dex = new byte[160];
        dex[0] = 'd';
        dex[1] = 'e';
        dex[2] = 'x';
        dex[3] = '\n';
        dex[4] = '0';
        dex[5] = '3';
        dex[6] = '5';
        dex[7] = 0;
        // Real DEX headers differ in checksum/signature/file_size; make each fixture's
        // 112-byte header unique so the leak scan does not trip on a shared prefix.
        dex[32] = (byte) marker;
        dex[33] = (byte) (marker >>> 8);
        dex[36] = (byte) (marker * 31);
        for (int i = 112; i < dex.length; i++) {
            dex[i] = (byte) (marker + i);
        }
        return dex;
    }

    private static void writeZip(File file, Entry... entries) throws IOException {
        try (ZipOutputStream output = new ZipOutputStream(new FileOutputStream(file))) {
            for (Entry entry : entries) {
                output.putNextEntry(new ZipEntry(entry.name));
                output.write(entry.data);
                output.closeEntry();
            }
        }
    }

    private static final class Entry {
        final String name;
        final byte[] data;

        Entry(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }
    }

    private static final class TestPackage extends AndroidPackage {
        TestPackage(String path) {
            super(new TestBuilder(path));
        }

        @Override
        public void protect() {
        }

        @Override
        protected File getOutAssetsDir(String packageDir) {
            return new File(packageDir, "assets");
        }

        @Override
        public String getLibDir(String packageDir) {
            return packageDir + File.separator + "lib";
        }

        @Override
        public String getDexDir(String packageDir) {
            return packageDir;
        }

        @Override
        protected String getManifestFilePath(String packageOutDir) {
            return packageOutDir + File.separator + "AndroidManifest.xml";
        }

        @Override
        public void writeProxyAppName(String manifestDir) {
        }

        @Override
        public void writeProxyComponentFactoryName(String manifestDir) {
        }

        @Override
        public void setExtractNativeLibs(String manifestDir) {
        }

        @Override
        public void setDebuggable(String manifestDir, boolean debuggable) {
        }

        @Override
        public void saveApplicationName(String packageOutDir) {
        }

        @Override
        public void saveAppComponentFactory(String packageOutDir) {
        }

        @Override
        protected boolean sign(String packagePath, String keyStorePath, String signedPackagePath,
                               String keyAlias, String storePassword, String keyPassword) {
            return false;
        }

        private static final class TestBuilder extends AndroidPackage.Builder {
            TestBuilder(String path) {
                filePath(path);
            }

            @Override
            public AndroidPackage build() {
                return null;
            }
        }
    }
}
