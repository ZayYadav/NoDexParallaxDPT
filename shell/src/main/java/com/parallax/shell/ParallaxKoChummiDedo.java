package com.parallax.shell;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;

import com.parallax.parallax.BuildConfig;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class ParallaxKoChummiDedo extends Application
        implements Application.ActivityLifecycleCallbacks {

    private static final int SECURITY_ROOT = 1;
    private static final int SECURITY_DEBUGGABLE = 1 << 1;
    private static final int SECURITY_TRACER = 1 << 2;
    private static final int SECURITY_HOOK_FRAMEWORK = 1 << 3;
    private static final int SECURITY_PAYLOAD_TAMPER = 1 << 4;
    private static final String ZIP_LIB_DIR = "ParallaxLoveU";
    private static final String SHELL_SO_NAME = BuildConfig.SO_NAME;

    private static volatile int flowNoise = 0x6D2B79F5;
    private static boolean classLoaderReady;
    private static boolean needRealApplication = true;
    private static boolean protectionDialogShown;
    private static int securityReason;
    private static String realApplicationName;
    private static Application realApplication;

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

    private static int nextState(int realState, int decoyState) {
        int value = flowNoise;
        flowNoise = Integer.rotateLeft(value ^ 0x9E3779B9, 7) + 0x7F4A7C15;
        return ((value * (value + 1)) & 1) == 0 ? realState : decoyState;
    }

    private static String abiDirName() {
        String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0
                ? Build.SUPPORTED_ABIS[0] : Build.CPU_ABI;
        if (abi == null) {
            return "arm64";
        }
        if (abi.startsWith("arm64")) {
            return "arm64";
        }
        if (abi.startsWith("armeabi")) {
            return "arm";
        }
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
            if (entry == null) {
                throw new IllegalStateException("missing shell library");
            }
            try (InputStream in = zip.getInputStream(entry);
                 FileOutputStream output = new FileOutputStream(out, false)) {
                byte[] buffer = new byte[16384];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    output.write(buffer, 0, read);
                }
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
                    if (info == null) {
                        throw new IllegalStateException("application info is null");
                    }
                    shellLibrary = extractShellLibrary(info.sourceDir, info.dataDir);
                    System.load(shellLibrary.getAbsolutePath());
                    state = nextState(0x33, 0x73);
                    break;
                case 0x33:
                    securityReason = securityStatus(base);
                    if (securityReason != 0) {
                        state = nextState(0x66, 0x76);
                    } else {
                        ia();
                        state = nextState(0x44, 0x74);
                    }
                    break;
                case 0x44:
                    cbde(base.getClassLoader());
                    classLoaderReady = true;
                    state = nextState(0x55, 0x75);
                    break;
                case 0x55:
                    realApplicationName = rapn();
                    return;
                case 0x66:
                    // Fail closed before protected DEX/config loading on an unsafe runtime.
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
                    app = ra(realApplicationName);
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

    private static String protectionMessage() {
        int reason = securityReason;
        if ((reason & SECURITY_PAYLOAD_TAMPER) != 0) {
            return "Protected code integrity verification failed. This protected app will close in 6 seconds.";
        }
        if ((reason & SECURITY_ROOT) != 0) {
            return "Rooted or modified device detected. This protected app will close in 6 seconds.";
        }
        if ((reason & SECURITY_HOOK_FRAMEWORK) != 0) {
            return "Hook/instrumentation framework detected. This protected app will close in 6 seconds.";
        }
        if ((reason & SECURITY_TRACER) != 0) {
            return "Debugger/tracer detected. This protected app will close in 6 seconds.";
        }
        if ((reason & SECURITY_DEBUGGABLE) != 0) {
            return "Debuggable app state detected. This protected app will close in 6 seconds.";
        }
        return "Application integrity check failed. This protected app will close in 6 seconds.";
    }

    private static void showProtectionDialog(Activity activity) {
        if (securityReason == 0 || protectionDialogShown || activity == null || activity.isFinishing()) {
            return;
        }
        protectionDialogShown = true;
        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle("Parallax Protection")
                .setMessage(protectionMessage())
                .setCancelable(false)
                .create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.show();
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        prepare(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        int state = securityReason != 0 ? nextState(0xC1, 0xD1) : nextState(0xC2, 0xD2);
        for (;;) {
            switch (state) {
                case 0xC1:
                    registerActivityLifecycleCallbacks(this);
                    scheduleExit(6000);
                    return;
                case 0xC2:
                    replaceApplication();
                    return;
                case 0xD1:
                    state = 0xC1;
                    break;
                case 0xD2:
                    state = 0xC2;
                    break;
                default:
                    return;
            }
        }
    }

    @Override
    public Context createPackageContext(String packageName, int flags)
            throws PackageManager.NameNotFoundException {
        if (securityReason == 0 && realApplicationName != null && !realApplicationName.isEmpty()) {
            replaceApplication();
            if (realApplication != null) {
                return realApplication;
            }
        }
        return super.createPackageContext(packageName, flags);
    }

    @Override
    public String getPackageName() {
        if (securityReason == 0 && realApplicationName != null && !realApplicationName.isEmpty()) {
            return "";
        }
        return super.getPackageName();
    }

    @Override
    public void onActivityPreCreated(Activity activity, Bundle savedInstanceState) {
        showProtectionDialog(activity);
    }

    @Override
    public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        showProtectionDialog(activity);
    }

    @Override
    public void onActivityResumed(Activity activity) {
        showProtectionDialog(activity);
    }

    @Override
    public void onActivityStarted(Activity activity) {
    }

    @Override
    public void onActivityPaused(Activity activity) {
    }

    @Override
    public void onActivityStopped(Activity activity) {
    }

    @Override
    public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
    }

    @Override
    public void onActivityDestroyed(Activity activity) {
    }
}
