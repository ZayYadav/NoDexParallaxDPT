package com.parallax.parallax.builder;

import com.android.apksigner.ApkSignerTool;
import com.parallax.parallax.config.Const;
import com.parallax.parallax.config.ShellConfig;
import com.parallax.parallax.res.ApkManifestEditor;
import com.parallax.parallax.util.DexUtils;
import com.parallax.parallax.util.FileUtils;
import com.parallax.parallax.util.KeyUtils;
import com.parallax.parallax.util.LogUtils;
import com.parallax.parallax.util.ZipUtils;
import com.wind.meditor.core.FileProcesser;
import com.wind.meditor.property.AttributeItem;
import com.wind.meditor.property.ModificationProperty;
import com.wind.meditor.utils.NodeValue;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class Apk extends AndroidPackage {

    public static class Builder extends AndroidPackage.Builder {
        @Override
        public Apk build() {
            return new Apk(this);
        }
    }

    protected Apk(Builder builder) {
        super(builder);
    }

    @Override
    public String getProxyApplicationName() {
        return String.format(Locale.US, "%s.%s", ShellConfig.getInstance().getShellPackageName(), "ParallaxKoChummiDedo");
    }

    @Override
    public String getProxyComponentFactory() {
        // Keep the shell DEX single-class. The framework factory is available before the
        // protected app's classes are restored by the Application bootstrap.
        return "android.app.AppComponentFactory";
    }

    @Override
    protected File getOutAssetsDir(String packageDir) {
        return FileUtils.getDir(packageDir, "assets");
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
    protected boolean sign(String packagePath, String keyStorePath, String signedPackagePath, String keyAlias, String storePassword, String KeyPassword) {
        ArrayList<String> commandList = new ArrayList<>();
        commandList.add("sign");
        commandList.add("--ks");
        commandList.add(keyStorePath);
        commandList.add("--ks-key-alias");
        commandList.add(keyAlias);
        commandList.add("--ks-pass");
        commandList.add("pass:" + storePassword);
        commandList.add("--key-pass");
        commandList.add("pass:" + KeyPassword);
        commandList.add("--out");
        commandList.add(signedPackagePath);
        commandList.add("--v1-signing-enabled");
        commandList.add("true");
        commandList.add("--v2-signing-enabled");
        commandList.add("true");
        commandList.add("--v3-signing-enabled");
        commandList.add("true");
        commandList.add(packagePath);

        String[] commandArray = commandList.toArray(new String[0]);
        try {
            ApkSignerTool.main(commandArray);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public void writeProxyAppName(String manifestDir) {
        String inManifestPath = manifestDir + File.separator + "AndroidManifest.xml";
        String outManifestPath = manifestDir + File.separator + "AndroidManifest_new.xml";
        ApkManifestEditor.writeApplicationName(inManifestPath, outManifestPath, getProxyApplicationName());
        File inManifestFile = new File(inManifestPath);
        File outManifestFile = new File(outManifestPath);
        inManifestFile.delete();
        outManifestFile.renameTo(inManifestFile);
    }

    @Override
    public void writeProxyComponentFactoryName(String manifestDir) {
        String inManifestPath = manifestDir + File.separator + "AndroidManifest.xml";
        String outManifestPath = manifestDir + File.separator + "AndroidManifest_new.xml";
        ApkManifestEditor.writeAppComponentFactory(inManifestPath, outManifestPath, getProxyComponentFactory());
        File inManifestFile = new File(inManifestPath);
        File outManifestFile = new File(outManifestPath);
        inManifestFile.delete();
        outManifestFile.renameTo(inManifestFile);
    }

    @Override
    public void setExtractNativeLibs(String manifestDir) {
        String inManifestPath = manifestDir + File.separator + "AndroidManifest.xml";
        String outManifestPath = manifestDir + File.separator + "AndroidManifest_new.xml";
        ModificationProperty property = new ModificationProperty();
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.EXTRACTNATIVELIBS, "true"));
        FileProcesser.processManifestFile(inManifestPath, outManifestPath, property);
        File inManifestFile = new File(inManifestPath);
        File outManifestFile = new File(outManifestPath);
        inManifestFile.delete();
        outManifestFile.renameTo(inManifestFile);
    }

    @Override
    public void setDebuggable(String manifestDir, boolean debuggable) {
        String inManifestPath = manifestDir + File.separator + "AndroidManifest.xml";
        String outManifestPath = manifestDir + File.separator + "AndroidManifest_new.xml";
        ApkManifestEditor.writeDebuggable(inManifestPath, outManifestPath, debuggable ? "true" : "false");
        File inManifestFile = new File(inManifestPath);
        File outManifestFile = new File(outManifestPath);
        inManifestFile.delete();
        outManifestFile.renameTo(inManifestFile);
    }

    @Override
    public void saveApplicationName(String packageOutDir) {
        String androidManifestFile = getManifestFilePath(packageOutDir);
        ShellConfig shellConfig = ShellConfig.getInstance();
        String appName = ApkManifestEditor.getApplicationName(androidManifestFile);
        appName = appName == null ? "" : appName;
        appName = appName.startsWith(".") ? appName.substring(1) : appName;
        shellConfig.setApplicationName(appName);
    }

    @Override
    public void saveAppComponentFactory(String packageOutDir) {
        String androidManifestFile = getManifestFilePath(packageOutDir);
        ShellConfig shellConfig = ShellConfig.getInstance();
        String acfName = ApkManifestEditor.getAppComponentFactory(androidManifestFile);
        acfName = acfName == null ? "" : acfName;
        shellConfig.setAppComponentFactoryName(acfName);
    }

    /**
     * Install only the executable bootstrap DEX. The protected app DEX archive is kept as
     * a separate asset instead of being appended behind classes.dex. That makes the stub
     * a real tiny DEX and lets the payload be compressed independently.
     */
    private static void installTinyShellDex(Apk apk, String packageDir) throws IOException {
        File shellDexFile = new File(apk.getProxyDexPath());
        File renameDexFile = new File(apk.getRenameDexPath());
        File sourceDex = shellDexFile;
        ShellConfig shellConfig = ShellConfig.getInstance();

        boolean needRename = !org.apache.commons.lang3.StringUtils.isBlank(shellConfig.getShellPackageName())
                && !Const.DEFAULT_SHELL_PACKAGE_NAME.equals(shellConfig.getShellPackageName());
        if (needRename) {
            DexUtils.renamePackageName(shellDexFile, renameDexFile, shellConfig.getSlashShellPackageName());
            sourceDex = renameDexFile;
        }

        File targetDex = new File(apk.getDexDir(packageDir), "classes.dex");
        Files.copy(sourceDex.toPath(), targetDex.toPath(), StandardCopyOption.REPLACE_EXISTING);
        LogUtils.info("Tiny shell DEX installed: %d bytes", targetDex.length());

        if (renameDexFile.exists()) {
            renameDexFile.delete();
        }
    }

    /**
     * The hollowed DEX files are already stored in a private ZIP. Re-encode those entries
     * with BEST_COMPRESSION, then append the four-byte ZIP length trailer expected by the
     * native loader. The outer APK stores this private asset verbatim, so compression is
     * paid only once and the public classes.dex remains tiny.
     */
    private static void compactDexPayload(Apk apk, String packageDir) throws IOException {
        File payload = new File(apk.getOutAssetsDir(packageDir), Const.KEY_DEXES_STORE_NAME);
        if (!payload.isFile()) {
            throw new IOException("Protected DEX payload is missing: " + payload);
        }

        File compact = new File(payload.getParentFile(), payload.getName() + ".compact");
        try (ZipFile sourceZip = new ZipFile(payload);
             ZipOutputStream output = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(compact)))) {
            output.setLevel(Deflater.BEST_COMPRESSION);
            Enumeration<? extends ZipEntry> entries = sourceZip.entries();
            byte[] buffer = new byte[32768];
            while (entries.hasMoreElements()) {
                ZipEntry sourceEntry = entries.nextElement();
                if (sourceEntry.isDirectory()) {
                    continue;
                }
                ZipEntry targetEntry = new ZipEntry(sourceEntry.getName());
                output.putNextEntry(targetEntry);
                try (InputStream input = new BufferedInputStream(sourceZip.getInputStream(sourceEntry))) {
                    int read;
                    while ((read = input.read(buffer)) != -1) {
                        output.write(buffer, 0, read);
                    }
                }
                output.closeEntry();
            }
        }

        long zipLength = compact.length();
        if (zipLength <= 0 || zipLength > Integer.MAX_VALUE) {
            compact.delete();
            throw new IOException("Invalid protected DEX payload size: " + zipLength);
        }
        try (FileOutputStream trailer = new FileOutputStream(compact, true)) {
            trailer.write(FileUtils.intToByte((int) zipLength));
        }

        long oldSize = payload.length();
        Files.move(compact.toPath(), payload.toPath(), StandardCopyOption.REPLACE_EXISTING);
        LogUtils.info("DEX payload compacted: %d -> %d bytes", oldSize, payload.length());
    }

    /**
     * Shell artifacts are built for four ABIs, but a protected APK usually ships only one
     * or two. When the input APK declares native ABI directories, remove shell variants
     * that can never be selected on that package. If the app has no native libraries we
     * keep all shell ABIs to preserve universal-device compatibility.
     */
    private static void pruneUnusedShellAbis(Apk apk, String packageDir) {
        File appLibRoot = new File(apk.getLibDir(packageDir));
        File[] appAbiDirs = appLibRoot.listFiles(File::isDirectory);
        if (appAbiDirs == null || appAbiDirs.length == 0) {
            return;
        }

        Set<String> required = new HashSet<>();
        for (File abiDir : appAbiDirs) {
            String abi = abiDir.getName();
            if ("arm64-v8a".equals(abi)) {
                required.add("arm64");
            } else if ("armeabi-v7a".equals(abi) || "armeabi".equals(abi)) {
                required.add("arm");
            } else if ("x86".equals(abi) || "x86_64".equals(abi)) {
                required.add(abi);
            }
        }
        if (required.isEmpty()) {
            return;
        }

        File shellLibRoot = new File(apk.getOutAssetsDir(packageDir), Const.KEY_LIBS_DIR_NAME);
        File[] shellAbiDirs = shellLibRoot.listFiles(File::isDirectory);
        if (shellAbiDirs == null) {
            return;
        }
        for (File abiDir : shellAbiDirs) {
            if (!required.contains(abiDir.getName())) {
                LogUtils.info("Size optimization: remove unused shell ABI %s", abiDir.getName());
                FileUtils.deleteRecurse(abiDir);
            }
        }
    }

    /**
     * Zero-DEX APKs are already native-only packages. Injecting the Java shell into such
     * an APK would turn it into a DEX package and can also break a NativeActivity-style
     * lifecycle. Preserve the original manifest, native libraries and resources and only
     * run the package finalization pipeline (optional debug flag, zipalign and signing).
     *
     * This mode deliberately does not pretend to apply DEX hollowing: there is no DEX
     * payload to transform. The important invariant is that a zero-DEX input stays
     * zero-DEX in the output.
     */
    private static void processZeroDexApk(Apk apk, File apkFile, String apkMainProcessPath) {
        LogUtils.info("Native-only APK detected: no classes*.dex found.");
        LogUtils.info("Zero-DEX mode: preserving manifest/components/libs; shell DEX injection is skipped.");

        if (apk.isDebuggable()) {
            LogUtils.info("Make zero-DEX apk debuggable.");
            apk.setDebuggable(apkMainProcessPath, true);
        }

        apk.buildPackage(apkFile.getAbsolutePath(), apkMainProcessPath, FileUtils.getUserDir());
    }

    private static void process(Apk apk) {
        File apkFile = new File(apk.getFilePath());
        String apkMainProcessPath = apk.getWorkspaceDir().getAbsolutePath();
        LogUtils.info("Workspace path: " + apkMainProcessPath);
        ZipUtils.unZip(apk.getFilePath(), apkMainProcessPath);

        String packageName = ApkManifestEditor.getPackageName(apkMainProcessPath + File.separator + "AndroidManifest.xml");
        apk.setPackageName(packageName);
        apk.resolveDefaultShellPackageName();

        // Native-only / zero-DEX packages must stay zero-DEX. Do this check before any
        // shell manifest rewrite, shell library copy, encrypted config write or stub DEX
        // generation.
        if (apk.getDexFiles(apk.getDexDir(apkMainProcessPath)).isEmpty()) {
            try {
                processZeroDexApk(apk, apkFile, apkMainProcessPath);
            } finally {
                File workspace = new File(apkMainProcessPath);
                if (workspace.exists()) {
                    FileUtils.deleteRecurse(workspace);
                }
            }
            LogUtils.info("All done (zero-DEX mode).");
            return;
        }

        byte[] encKey = KeyUtils.generateKey();

        try {
            apk.saveApplicationName(apkMainProcessPath);
            apk.writeProxyAppName(apkMainProcessPath);
            if (apk.isAppComponentFactory()) {
                apk.saveAppComponentFactory(apkMainProcessPath);
                apk.writeProxyComponentFactoryName(apkMainProcessPath);
            }
            if (apk.isDebuggable()) {
                LogUtils.info("Make apk debuggable.");
                apk.setDebuggable(apkMainProcessPath, true);
            }
            apk.setExtractNativeLibs(apkMainProcessPath);

            String assetsPath = apk.getOutAssetsDir(apkMainProcessPath).getAbsolutePath();
            apk.extractDexCode(apkMainProcessPath, assetsPath);
            apk.addJunkCodeDex(apkMainProcessPath);
            apk.compressDexFiles(apkMainProcessPath);
            compactDexPayload(apk, apkMainProcessPath);
            apk.deleteAllDexFiles(apkMainProcessPath);
            installTinyShellDex(apk, apkMainProcessPath);
            apk.addKeepDexes(apkMainProcessPath);
            FileUtils.deleteRecurse(apk.getKeepDexTempDir(apkMainProcessPath));

            apk.copyNativeLibs(apkMainProcessPath);
            pruneUnusedShellAbis(apk, apkMainProcessPath);
            apk.encryptSoFiles(apkMainProcessPath, encKey);
            apk.writeConfig(apkMainProcessPath, encKey);
            apk.buildPackage(apkFile.getAbsolutePath(), apkMainProcessPath, FileUtils.getUserDir());
            LogUtils.info("All done.");
        } catch (Exception e) {
            throw new IllegalStateException("APK protection failed", e);
        } finally {
            File apkMainProcessFile = new File(apkMainProcessPath);
            if (apkMainProcessFile.exists()) {
                FileUtils.deleteRecurse(apkMainProcessFile);
            }
        }
    }

    @Override
    public void protect() throws IOException {
        super.protect();
        process(this);
    }
}
