package com.parallax.shell;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.view.Window;
import android.view.WindowManager;
import android.widget.TextView;

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
 * Single-class shell bootstrap. Android lifecycle entry, native bridge, protection UI
 * and the tiny library extractor deliberately live in this one class so release R8
 * emits exactly one shell class definition.
 */
public final class ParallaxKoChummiDedo extends Application
        implements Application.ActivityLifecycleCallbacks {
    private static final String ZIP_LIB_DIR = "ParallaxLoveU";
    private static final String LIB_DIR = "libs";
    private static final String SHELL_SO_NAME = BuildConfig.SO_NAME;
    private static final String PROTECTION_TITLE = "Parallax Protection";

    private static final int SECURITY_ROOT = 1;
    private static final int SECURITY_DEBUGGABLE = 1 << 1;

    private boolean classLoaderReady;
    private boolean needRealApplication = true;
    private boolean protectionDialogShown;
    private int securityReason;
    private String realApplicationName = "";
    private Application realApplication;

    // Registered from JNI_OnLoad after the authenticated shell config is read.
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
    public static native int securityStatus(Context context);
    public static native void scheduleExit(int delayMs);

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

            long expectedCrc = entry.getCrc();
            if (out.isFile() && expectedCrc >= 0 && crc32(out) == expectedCrc) {
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

            if (expectedCrc >= 0 && crc32(out) != expectedCrc) {
                // Do not load a partially written or modified shell library.
                out.delete();
                throw new IllegalStateException("shell library checksum mismatch");
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

            // Native policy is evaluated before the real Application is allowed to run.
            securityReason = securityStatus(base);

            // Restore the protected app's classes so Android can resolve its declared
            // components. If blocked, the real Application itself is never replaced or run.
            ia();
            cbde(base.getClassLoader());
            classLoaderReady = true;
        }
        realApplicationName = rapn();
    }

    private void replaceApplication() {
        if (securityReason != 0 || !needRealApplication
                || realApplicationName == null || realApplicationName.isEmpty()) {
            return;
        }
        Object app = ra(realApplicationName);
        if (app instanceof Application) {
            realApplication = (Application) app;
            craoc(realApplicationName);
            needRealApplication = false;
        }
    }

    private String protectionMessage() {
        boolean rooted = (securityReason & SECURITY_ROOT) != 0;
        boolean debuggable = (securityReason & SECURITY_DEBUGGABLE) != 0;
        if (rooted && debuggable) {
            return "Rooted/modified environment and a debuggable application state were detected. "
                    + "For security, this app will close automatically.";
        }
        if (rooted) {
            return "A rooted or modified Android environment was detected. "
                    + "For security, this protected app cannot run on this device and will close automatically.";
        }
        if (debuggable) {
            return "Application integrity policy failed because a debuggable build state was detected. "
                    + "This app will close automatically.";
        }
        return "Application integrity verification failed. This app will close automatically.";
    }

    private void showProtectionDialog(Activity activity) {
        if (securityReason == 0 || protectionDialogShown || activity == null || activity.isFinishing()) {
            return;
        }
        protectionDialogShown = true;

        AlertDialog dialog = new AlertDialog.Builder(activity, android.R.style.Theme_Material_Dialog_Alert)
                .setIcon(android.R.drawable.ic_dialog_alert)
                .setTitle(PROTECTION_TITLE)
                .setMessage(protectionMessage())
                .setCancelable(false)
                .create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.show();

        float density = activity.getResources().getDisplayMetrics().density;
        Window window = dialog.getWindow();
        if (window != null) {
            GradientDrawable background = new GradientDrawable();
            background.setColor(Color.rgb(18, 20, 26));
            background.setCornerRadius(22.0f * density);
            background.setStroke(Math.max(1, (int) density), Color.rgb(86, 98, 122));
            window.setBackgroundDrawable(background);
            WindowManager.LayoutParams params = window.getAttributes();
            params.dimAmount = 0.72f;
            window.setAttributes(params);
            window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
        }

        int titleId = activity.getResources().getIdentifier("alertTitle", "id", "android");
        TextView title = titleId == 0 ? null : dialog.findViewById(titleId);
        if (title != null) {
            title.setTextColor(Color.WHITE);
            title.setTextSize(20.0f);
        }
        TextView message = dialog.findViewById(android.R.id.message);
        if (message != null) {
            message.setTextColor(Color.rgb(220, 224, 232));
            message.setTextSize(15.0f);
            message.setLineSpacing(0.0f, 1.12f);
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
        if (securityReason != 0) {
            registerActivityLifecycleCallbacks(this);
            // Native delayed shutdown also handles packages that never launch an Activity.
            scheduleExit(3500);
            return;
        }
        replaceApplication();
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

    // API 29+ invokes this before Activity.onCreate(), allowing the block UI to win the race
    // against normal app startup. Older Android versions fall back to onActivityCreated().
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
