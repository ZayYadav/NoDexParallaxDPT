package com.parallax.parallax.builder;

import com.android.apksigner.ApkSignerTool;
import com.parallax.parallax.config.ShellConfig;
import com.parallax.parallax.util.FileUtils;
import com.parallax.parallax.util.KeyUtils;
import com.parallax.parallax.util.LogUtils;
import com.parallax.parallax.res.ApkManifestEditor;
import com.parallax.parallax.util.ZipUtils;
import com.wind.meditor.core.FileProcesser;
import com.wind.meditor.property.AttributeItem;
import com.wind.meditor.property.ModificationProperty;
import com.wind.meditor.utils.NodeValue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Locale;

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
        apk.deleteAllDexFiles(apkMainProcessPath);
        apk.combineDexZipWithShellDex(apkMainProcessPath);
        apk.addKeepDexes(apkMainProcessPath);
        FileUtils.deleteRecurse(apk.getKeepDexTempDir(apkMainProcessPath));

        apk.copyNativeLibs(apkMainProcessPath);
        apk.encryptSoFiles(apkMainProcessPath, encKey);
        apk.writeConfig(apkMainProcessPath, encKey);
        apk.buildPackage(apkFile.getAbsolutePath(), apkMainProcessPath, FileUtils.getUserDir());

        File apkMainProcessFile = new File(apkMainProcessPath);
        if (apkMainProcessFile.exists()) {
            FileUtils.deleteRecurse(apkMainProcessFile);
        }
        LogUtils.info("All done.");
    }

    @Override
    public void protect() throws IOException {
        super.protect();
        process(this);
    }
}
