package com.parallax.shell;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

import com.parallax.parallax.BuildConfig;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class ParallaxKiSettingKarwaDo extends Application
        implements Application.ActivityLifecycleCallbacks, Runnable {

    private static final int SECURITY_ROOT = 1;
    private static final int SECURITY_DEBUGGABLE = 1 << 1;
    private static final int SECURITY_TRACER = 1 << 2;
    private static final int SECURITY_HOOK_FRAMEWORK = 1 << 3;
    private static final int SECURITY_PAYLOAD_TAMPER = 1 << 4;
    private static final int SECURITY_RUNTIME_TAMPER = 1 << 5;
    private static final String ZIP_LIB_DIR = "ParallaxLoveU";
    private static final String SHELL_SO_NAME = BuildConfig.SO_NAME;

    private static volatile int flowNoise = 0x6D2B79F5;
    private static volatile int securityReason;
    private static volatile boolean replacingApplication;
    private static boolean classLoaderReady;
    private static boolean needRealApplication = true;
    private static String realApplicationName;
    private static String realComponentFactoryName;
    private static Application realApplication;

    private Handler protectionHandler;
    private boolean protectionPolling;

    public static native void craoc(String appName);
    public static native void ia();
    public static native String gap();
    public static native String gdp();
    public static native String rcf();
    public static native String rapn();
    public static native void cbde(ClassLoader classLoader);
    public static native void rde(ClassLoader classLoader, String elementName);
    public static native Object ra(String appName);
    public static native void clinit();
    public static native int securityStatus(Context context);
    public static native void scheduleExit(int delayMs);

    static boolean isProtectionBlocked() {
        return securityReason != 0;
    }

    static int getSecurityReason() {
        return securityReason;
    }

    static String getRealComponentFactoryName() {
        return realComponentFactoryName;
    }

    private static String text(int key, int... data) {
        char[] out = new char[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (char) (data[i] ^ key);
        }
        return new String(out);
    }

    private static int nextState(int realState, int decoyState) {
        int value = flowNoise;
        flowNoise = Integer.rotateLeft(value ^ 0x9E3779B9, 7) + 0x7F4A7C15;
        return ((value * (value + 1)) & 1) == 0 ? realState : decoyState;
    }

    private static String abiDirName() {
        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0
                ? Build.SUPPORTED_ABIS[0] : Build.CPU_ABI;
        if (abi == null) return "arm64";
        if (abi.startsWith("arm64")) return "arm64";
        if (abi.startsWith("armeabi")) return "arm";
        return abi;
    }

    private static File extractShellLibrary(String sourceDir, String dataDir) {
        File outDir = new File(dataDir, "files");
        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IllegalStateException("cannot create shell directory");
        }
        File out = new File(outDir, SHELL_SO_NAME);
        String entryName = "assets/" + ZIP_LIB_DIR + "/" + abiDirName() + "/" + SHELL_SO_NAME;
        try (ZipFile zip = new ZipFile(sourceDir)) {
            ZipEntry entry = zip.getEntry(entryName);
            if (entry == null) throw new IllegalStateException("missing shell library");
            try (InputStream in = zip.getInputStream(entry);
                 FileOutputStream output = new FileOutputStream(out, false)) {
                byte[] buffer = new byte[16384];
                int read;
                while ((read = in.read(buffer)) != -1) output.write(buffer, 0, read);
            }
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("cannot extract shell library", e);
        }
    }

    private void prepare(Context base) {
        int state = 0x11;
        ApplicationInfo info = null;
        File shellLibrary = null;
        for (;;) {
            switch (state) {
                case 0x11:
                    state = classLoaderReady ? nextState(0x55, 0x71) : nextState(0x22, 0x72);
                    break;
                case 0x22:
                    info = base.getApplicationInfo();
                    if (info == null) throw new IllegalStateException("application info is null");
                    shellLibrary = extractShellLibrary(info.sourceDir, info.dataDir);
                    System.load(shellLibrary.getAbsolutePath());
                    state = nextState(0x33, 0x73);
                    break;
                case 0x33:
                    securityReason = securityStatus(base);
                    state = securityReason != 0 ? nextState(0x66, 0x76) : nextState(0x44, 0x74);
                    if (securityReason == 0) ia();
                    break;
                case 0x44:
                    cbde(base.getClassLoader());
                    classLoaderReady = true;
                    state = nextState(0x55, 0x75);
                    break;
                case 0x55:
                    realApplicationName = rapn();
                    realComponentFactoryName = rcf();
                    return;
                case 0x66:
                    return;
                case 0x71:
                case 0x72:
                case 0x73:
                case 0x74:
                case 0x75:
                    state = classLoaderReady ? 0x55 : (info == null ? 0x22 : (shellLibrary == null ? 0x22 : 0x33));
                    break;
                case 0x76:
                    state = 0x66;
                    break;
                default:
                    state = 0x11;
                    break;
            }
        }
    }

    private void replaceApplication() {
        int state = 0x81;
        Object app = null;
        for (;;) {
            switch (state) {
                case 0x81:
                    state = securityReason == 0 && needRealApplication
                            && realApplicationName != null && !realApplicationName.isEmpty()
                            ? nextState(0x92, 0xB1) : nextState(0xA3, 0xB2);
                    break;
                case 0x92:
                    replacingApplication = true;
                    try {
                        app = ra(realApplicationName);
                    } finally {
                        // The old proxy needed an empty package name only during the narrow
                        // LoadedApk/Application swap. Keeping it empty after boot breaks SDKs,
                        // game engines and package-scoped services initialized much later.
                        replacingApplication = false;
                    }
                    if (app instanceof Application) {
                        realApplication = (Application) app;
                        needRealApplication = false;
                        craoc(realApplicationName);
                    }
                    state = nextState(0xA3, 0xB3);
                    break;
                case 0xA3:
                    return;
                case 0xB1:
                case 0xB2:
                case 0xB3:
                    state = app instanceof Application ? 0xA3 : 0x92;
                    break;
                default:
                    return;
            }
        }
    }

    static String protectionMessage() {
        int reason = securityReason;
        if ((reason & SECURITY_PAYLOAD_TAMPER) != 0) {
            return text(41,122,76,74,92,91,64,93,80,9,64,71,93,76,78,91,64,93,80,9,74,65,76,74,66,9,79,72,64,69,76,77,7,9,125,65,64,90,9,90,76,90,90,64,70,71,9,64,90,9,75,69,70,74,66,76,77,7);
        }
        if ((reason & SECURITY_ROOT) != 0) {
            return text(42,120,69,69,94,79,78,10,69,88,10,71,69,78,67,76,67,79,78,10,78,79,92,67,73,79,10,78,79,94,79,73,94,79,78,4,10,107,73,73,79,89,89,10,66,75,89,10,72,79,79,68,10,72,70,69,73,65,79,78,4);
        }
        if ((reason & SECURITY_HOOK_FRAMEWORK) != 0) {
            return text(43,98,69,88,95,89,94,70,78,69,95,74,95,66,68,69,11,77,89,74,70,78,92,68,89,64,11,79,78,95,78,72,95,78,79,5,11,106,72,72,78,88,88,11,67,74,88,11,73,78,78,69,11,73,71,68,72,64,78,79,5);
        }
        if ((reason & SECURITY_TRACER) != 0) {
            return text(44,104,73,78,89,75,75,73,94,12,67,94,12,88,94,77,79,73,94,12,72,73,88,73,79,88,73,72,2,12,109,79,79,73,95,95,12,68,77,95,12,78,73,73,66,12,78,64,67,79,71,73,72,2);
        }
        if ((reason & SECURITY_DEBUGGABLE) != 0) {
            return text(45,105,72,79,88,74,74,76,79,65,72,13,76,93,93,65,68,78,76,89,68,66,67,13,94,89,76,89,72,13,73,72,89,72,78,89,72,73,3,13,108,78,78,72,94,94,13,69,76,94,13,79,72,72,67,13,79,65,66,78,70,72,73,3);
        }
        if ((reason & SECURITY_RUNTIME_TAMPER) != 0) {
            return text(46,124,91,64,90,71,67,75,14,71,64,90,75,73,92,71,90,87,14,77,70,79,64,73,75,74,14,79,72,90,75,92,14,66,79,91,64,77,70,0,14,122,70,71,93,14,93,75,93,93,71,65,64,14,71,93,14,76,66,65,77,69,75,74,0);
        }
        return text(47,110,95,95,67,70,76,78,91,70,64,65,15,92,74,76,90,93,70,91,86,15,95,64,67,70,76,86,15,73,78,70,67,74,75,1,15,110,76,76,74,92,92,15,71,78,92,15,77,74,74,65,15,77,67,64,76,68,74,75,1);
    }

    private void startProtectionPolling() {
        if (protectionPolling) return;
        protectionPolling = true;
        protectionHandler = new Handler(Looper.getMainLooper());
        protectionHandler.postDelayed(this, 900L);
    }

    @Override
    public void run() {
        if (!protectionPolling || protectionHandler == null) return;
        try {
            int runtimeState = securityStatus(this);
            if (runtimeState != 0) {
                securityReason |= runtimeState;
                Activity activity = ParallaxKoLadkiChahiye.peekActivity();
                if (activity != null) Parallax.request(activity);
            }
        } catch (Throwable ignored) { }
        protectionHandler.postDelayed(this, 1000L);
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        prepare(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        registerActivityLifecycleCallbacks(this);
        startProtectionPolling();
        int state = securityReason != 0 ? nextState(0xC1, 0xD1) : nextState(0xC2, 0xD2);
        for (;;) {
            switch (state) {
                case 0xC1: return;
                case 0xC2: replaceApplication(); return;
                case 0xD1: state = 0xC1; break;
                case 0xD2: state = 0xC2; break;
                default: return;
            }
        }
    }

    @Override
    public Context createPackageContext(String packageName, int flags)
            throws PackageManager.NameNotFoundException {
        String ownPackage = super.getPackageName();
        if (securityReason == 0
                && packageName != null
                && packageName.equals(ownPackage)
                && realApplicationName != null
                && !realApplicationName.isEmpty()) {
            replaceApplication();
            if (realApplication != null) return realApplication;
        }
        // Foreign package lookups (Play Services, stores, WebView/provider packages, etc.)
        // must keep Android's normal PackageManager/Context behavior.
        return super.createPackageContext(packageName, flags);
    }

    @Override
    public String getPackageName() {
        if (replacingApplication) return "";
        return super.getPackageName();
    }

    private static void onProtectionActivity(Activity activity) {
        ParallaxKoLadkiChahiye.rememberActivity(activity);
        if (securityReason != 0) Parallax.request(activity);
    }

    @Override public void onActivityPreCreated(Activity activity, Bundle savedInstanceState) { onProtectionActivity(activity); }
    @Override public void onActivityCreated(Activity activity, Bundle savedInstanceState) { onProtectionActivity(activity); }
    @Override public void onActivityResumed(Activity activity) { onProtectionActivity(activity); }
    @Override public void onActivityStarted(Activity activity) { }
    @Override public void onActivityPaused(Activity activity) { }
    @Override public void onActivityStopped(Activity activity) { }
    @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) { }
    @Override public void onActivityDestroyed(Activity activity) { }
}
