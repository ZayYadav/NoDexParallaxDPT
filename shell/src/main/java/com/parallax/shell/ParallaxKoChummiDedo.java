package com.parallax.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import com.parallax.parallax.BuildConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Single-class shell bootstrap. Android lifecycle entry, native bridge and the tiny
 * library extractor deliberately live in this one class so release R8 emits exactly
 * one shell class definition.
 */
public final class ParallaxKoChummiDedo extends Application {
    private static final String ZIP_LIB_DIR = "ParallaxLoveU";
    private static final String LIB_DIR = "libs";
    private static final String SHELL_SO_NAME = BuildConfig.SO_NAME;

    private boolean classLoaderReady;
    private boolean needRealApplication = true;
    private String realApplicationName = "";
    private Application realApplication;

    // Registered from JNI_OnLoad after the encrypted shell config is read.
    public static native void craoc(String applicationClassName);
    public static native void ia();
    public static native String rcf();
    public static native void cbde(ClassLoader targetClassLoader);
    public static native void rde(ClassLoader classLoader, String elementName);
    public static native String gap();
    public static native String gdp();
    public static native Object ra(String originApplicationClassName);
    public static native String rapn();
    public static native void clinit();

    private static String abiDirName() {
        try {
            Class<?> clazz = Class.forName("dalvik.system.VMRuntime");
            Method getRuntime = clazz.getDeclaredMethod("getRuntime");
            Object runtime = getRuntime.invoke(null);
            Method vmInstructionSet = clazz.getDeclaredMethod("vmInstructionSet");
            Object value = vmInstructionSet.invoke(runtime);
            if (value instanceof String) {
                return (String) value;
            }
        } catch (Throwable ignored) {
        }

        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0
                ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
        if (abi.startsWith("arm64")) return "arm64";
        if (abi.startsWith("armeabi") || abi.startsWith("arm")) return "arm";
        if (abi.equals("x86_64")) return "x86_64";
        if (abi.startsWith("x86")) return "x86";
        return "arm64";
    }

    private static long crc32(File file) {
        CRC32 crc = new CRC32();
        byte[] buffer = new byte[8192];
        try (InputStream in = new FileInputStream(file)) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                crc.update(buffer, 0, read);
            }
            return crc.getValue();
        } catch (Throwable ignored) {
            return -1L;
        }
    }

    private static File extractShellLibrary(String sourceDir, String dataDir) {
        String abi = abiDirName();
        File outDir = new File(new File(dataDir, LIB_DIR), abi);
        if (!outDir.isDirectory() && !outDir.mkdirs() && !outDir.isDirectory()) {
            throw new IllegalStateException("cannot create shell library directory");
        }

        File out = new File(outDir, SHELL_SO_NAME);
        String entryName = "assets/" + ZIP_LIB_DIR + "/" + abi + "/" + SHELL_SO_NAME;

        try (ZipFile zip = new ZipFile(sourceDir)) {
            ZipEntry entry = zip.getEntry(entryName);
            if (entry == null) {
                throw new IllegalStateException("missing shell library for " + abi);
            }

            if (out.isFile() && crc32(out) == entry.getCrc()) {
                return out;
            }

            byte[] buffer = new byte[8192];
            try (InputStream in = zip.getInputStream(entry);
                 FileOutputStream output = new FileOutputStream(out, false)) {
                int read;
                while ((read = in.read(buffer)) != -1) {
                    output.write(buffer, 0, read);
                }
                output.flush();
            }
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("cannot extract shell library", e);
        }
    }

    private void prepare(Context base) {
        if (!classLoaderReady) {
            ApplicationInfo info = base.getApplicationInfo();
            if (info == null) {
                throw new IllegalStateException("application info is null");
            }

            File shellLibrary = extractShellLibrary(info.sourceDir, info.dataDir);
            System.load(shellLibrary.getAbsolutePath());
            ia();
            cbde(base.getClassLoader());
            classLoaderReady = true;
        }
        realApplicationName = rapn();
    }

    private void replaceApplication() {
        if (!needRealApplication || realApplicationName == null || realApplicationName.isEmpty()) {
            return;
        }
        Object app = ra(realApplicationName);
        if (app instanceof Application) {
            realApplication = (Application) app;
            craoc(realApplicationName);
            needRealApplication = false;
        }
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        prepare(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        replaceApplication();
    }

    @Override
    public Context createPackageContext(String packageName, int flags)
            throws PackageManager.NameNotFoundException {
        if (realApplicationName != null && !realApplicationName.isEmpty()) {
            replaceApplication();
            if (realApplication != null) {
                return realApplication;
            }
        }
        return super.createPackageContext(packageName, flags);
    }

    @Override
    public String getPackageName() {
        if (realApplicationName != null && !realApplicationName.isEmpty()) {
            return "";
        }
        return super.getPackageName();
    }
}
