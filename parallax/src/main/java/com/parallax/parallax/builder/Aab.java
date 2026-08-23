package com.parallax.parallax.builder;

import com.parallax.parallax.config.ShellConfig;
import com.parallax.parallax.res.AabManifestEditor;
import com.parallax.parallax.util.FileUtils;
import com.parallax.parallax.util.KeyUtils;
import com.parallax.parallax.util.LogUtils;
import com.parallax.parallax.util.ZipUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class Aab extends AndroidPackage {

    public static class Builder extends AndroidPackage.Builder {
        @Override
        public Aab build() {
            return new Aab(this);
        }
    }

    protected Aab(Aab.Builder builder) {
        super(builder);
    }

    @Override
    public String getProxyApplicationName() {
        return String.format(Locale.US, "%s.%s", ShellConfig.getInstance().getShellPackageName(), "ParallaxKoChummiDedo");
    }

    @Override
    public String getProxyComponentFactory() {
        return String.format(Locale.US, "%s.%s", ShellConfig.getInstance().getShellPackageName(), "ParallaxLovers");
    }

    @Override
    public void writeProxyAppName(String manifestDir) {
        String inManifestPath = manifestDir + File.separator + "AndroidManifest.xml";
        String outManifestPath = manifestDir + File.separator + "AndroidManifest_new.xml";
        AabManifestEditor.writeApplicationName(inManifestPath, outManifestPath, getProxyApplicationName());
        File inManifestFile = new File(inManifestPath);
        File outManifestFile = new File(outManifestPath);
        inManifestFile.delete();
        outManifestFile.renameTo(inManifestFile);
    }

    @Override
    public void writeProxyComponentFactoryName(String manifestDir) {
        String inManifestPath = manifestDir + File.separator + "AndroidManifest.xml";
        String outManifestPath = manifestDir + File.separator + "AndroidManifest_new.xml";
        AabManifestEditor.writeAppComponentFactory(inManifestPath, outManifestPath, getProxyComponentFactory());
        File inManifestFile = new File(inManifestPath);
        File outManifestFile = new File(outManifestPath);
        inManifestFile.delete();
        outManifestFile.renameTo(inManifestFile);
    }

    @Override
    public void setExtractNativeLibs(String manifestDir) {
        String inManifestPath = manifestDir + File.separator + "AndroidManifest.xml";
        String outManifestPath = manifestDir + File.separator + "AndroidManifest_new.xml";
        AabManifestEditor.writeApplicationExtractNativeLibs(inManifestPath, outManifestPath, "true");
        File inManifestFile = new File(inManifestPath);
        File outManifestFile = new File(outManifestPath);
        inManifestFile.delete();
        outManifestFile.renameTo(inManifestFile);
    }

    @Override
    public void setDebuggable(String manifestDir, boolean debuggable) {
        String inManifestPath = manifestDir + File.separator + "AndroidManifest.xml";
        String outManifestPath = manifestDir + File.separator + "AndroidManifest_new.xml";
        AabManifestEditor.writeDebuggable(inManifestPath, outManifestPath, String.valueOf(debuggable));
        File inManifestFile = new File(inManifestPath);
        File outManifestFile = new File(outManifestPath);
        inManifestFile.delete();
        outManifestFile.renameTo(inManifestFile);
    }

    @Override
    protected File getOutAssetsDir(String packageDir) {
        return FileUtils.getDir(getBaseDir(packageDir), "assets");
    }

    protected String getManifestFileDir(String packageOutDir) {
        return getBaseDir(packageOutDir) + File.separator + "manifest";
    }

    @Override
    protected String getManifestFilePath(String packageOutDir) {
        return getManifestFileDir(packageOutDir) + File.separator + "AndroidManifest.xml";
    }

    @Override
    public void saveApplicationName(String packageOutDir) {
        String androidManifestFile = getManifestFilePath(packageOutDir);
        String appName = AabManifestEditor.getApplicationName(androidManifestFile);
        appName = appName == null ? "" : appName;
        appName = appName.startsWith(".") ? appName.substring(1) : appName;
        ShellConfig.getInstance().setApplicationName(appName);
    }

    @Override
    public void saveAppComponentFactory(String packageOutDir) {
        String androidManifestFile = getManifestFilePath(packageOutDir);
        String acfName = AabManifestEditor.getAppComponentFactory(androidManifestFile);
        acfName = acfName == null ? "" : acfName;
        ShellConfig.getInstance().setAppComponentFactoryName(acfName);
    }

    public String getBaseDir(String packageDir) {
        return packageDir + File.separator + "base";
    }

    @Override
    public String getLibDir(String packageDir) {
        return getBaseDir(packageDir) + File.separator + "lib";
    }

    @Override
    public String getDexDir(String packageDir) {
        return getBaseDir(packageDir) + File.separator + "dex";
    }

    @Override
    protected boolean sign(String packagePath, String keyStorePath, String signedPackagePath, String keyAlias, String storePassword, String KeyPassword) {
        List<String> command = new ArrayList<>();
        command.add(FileUtils.getJarSignerCommand());
        command.add("-keystore");
        command.add(keyStorePath);
        command.add("-storepass");
        command.add(storePassword);
        command.add("-keypass");
        command.add(KeyPassword);
        command.add("-signedjar");
        command.add(signedPackagePath);
        command.add(packagePath);
        command.add(keyAlias);

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            try (InputStream inputStream = process.getInputStream()) {
                inputStream.readAllBytes();
            }
            return process.waitFor() == 0;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private static void process(Aab aab) {
        File aabFile = new File(aab.getFilePath());
        byte[] encKey = KeyUtils.generateKey();
        String aabMainProcessPath = aab.getWorkspaceDir().getAbsolutePath();
        LogUtils.info("Workspace path: " + aabMainProcessPath);
        ZipUtils.unZip(aab.getFilePath(), aabMainProcessPath);
        String manifestFilePath = aab.getManifestFilePath(aabMainProcessPath);
        String manifestFileDir = aab.getManifestFileDir(aabMainProcessPath);

        String packageName = AabManifestEditor.getPackageName(manifestFilePath);
        aab.setPackageName(packageName);
        aab.resolveDefaultShellPackageName();

        aab.saveApplicationName(aabMainProcessPath);
        aab.writeProxyAppName(manifestFileDir);
        if (aab.isAppComponentFactory()) {
            aab.saveAppComponentFactory(aabMainProcessPath);
            aab.writeProxyComponentFactoryName(manifestFileDir);
        }
        if (aab.isDebuggable()) {
            LogUtils.info("Make aab debuggable.");
            aab.setDebuggable(manifestFileDir, true);
        }
        aab.setExtractNativeLibs(manifestFileDir);

        String assetsPath = aab.getOutAssetsDir(aabMainProcessPath).getAbsolutePath();
        aab.extractDexCode(aabMainProcessPath, assetsPath);
        aab.addJunkCodeDex(aabMainProcessPath);
        aab.compressDexFiles(aabMainProcessPath);
        aab.deleteAllDexFiles(aabMainProcessPath);
        aab.combineDexZipWithShellDex(aabMainProcessPath);
        aab.addKeepDexes(aabMainProcessPath);
        FileUtils.deleteRecurse(aab.getKeepDexTempDir(aabMainProcessPath));

        aab.copyNativeLibs(aabMainProcessPath);
        aab.encryptSoFiles(aabMainProcessPath, encKey);
        aab.writeConfig(aabMainProcessPath, encKey);
        aab.buildPackage(aabFile.getAbsolutePath(), aabMainProcessPath, FileUtils.getUserDir());

        File aabMainProcessFile = new File(aabMainProcessPath);
        if (aabMainProcessFile.exists()) {
            FileUtils.deleteRecurse(aabMainProcessFile);
        }
        LogUtils.info("All done.");
    }

    @Override
    public void protect() throws IOException {
        super.protect();
        process(this);
    }
}
