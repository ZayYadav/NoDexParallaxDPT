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
 *
 * Critical bootstrap decisions intentionally use a dispatcher/state-machine form. The
 * release ProGuard rules keep those methods from being re-optimized while still allowing
 * private helper/field names to be obfuscated. This keeps the generated single smali
 * structurally flattened instead of letting R8 reconstruct straight-line branches.
 */
public final class ParallaxKoChummiDedo extends Application
        implements Application.ActivityLifecycleCallbacks {
    private static final String ZIP_LIB_DIR = "ParallaxLoveU";
    private static final String LIB_DIR = "libs";
    private static final String SHELL_SO_NAME = BuildConfig.SO_NAME;
    private static final String PROTECTION_TITLE = "Parallax Protection";

    private static final int SECURITY_ROOT = 1;
    private static final int SECURITY_DEBUGGABLE = 1 << 1;

    /*
     * Runtime-only noise used by flattened dispatch transitions. nextState() always
     * chooses the real edge (n * (n + 1) is even for every int), but the volatile read/
     * write and deliberately preserved method body stop the release optimizer from
     * collapsing the dispatcher into the original high-level branch graph.
     */
    private static volatile int flowNoise = 0x6D2B79F5;

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

    private static int nextState(int realState, int decoyState) {
        int value = flowNoise;
        flowNoise = Integer.rotateLeft(value ^ 0x9E3779B9, 7) + 0x7F4A7C15;
        return ((value * (value + 1)) & 1) == 0 ? realState : decoyState;
    }

    private static String abiDirName() {
        String result = null;
        String abi = null;
        int state = 0x31;
        while (true) {
            switch (state) {
                case 0x31:
                    try {
                        Class<?> clazz = Class.forName("dalvik.system.VMRuntime");
                        Method getRuntime = clazz.getDeclaredMethod("getRuntime");
                        Object runtime = getRuntime.invoke(null);
                        Method vmInstructionSet = clazz.getDeclaredMethod("vmInstructionSet");
                        Object value = vmInstructionSet.invoke(runtime);
                        if (value instanceof String) {
                            result = (String) value;
                            state = nextState(0x7D, 0x63);
                        } else {
                            state = nextState(0x52, 0x64);
                        }
                    } catch (Throwable ignored) {
                        state = nextState(0x52, 0x65);
                    }
                    break;
                case 0x52:
                    abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0
                            ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
                    state = nextState(0x18, 0x66);
                    break;
                case 0x18:
                    if (abi.startsWith("arm64")) {
                        result = "arm64";
                    } else if (abi.startsWith("armeabi") || abi.startsWith("arm")) {
                        result = "arm";
                    } else if (abi.equals("x86_64")) {
                        result = "x86_64";
                    } else if (abi.startsWith("x86")) {
                        result = "x86";
                    } else {
                        result = "arm64";
                    }
                    state = nextState(0x7D, 0x67);
                    break;
                case 0x63:
                case 0x64:
                case 0x65:
                case 0x66:
                case 0x67:
                    // Decoy dispatcher nodes. They are unreachable by construction but
                    // remain valid recovery edges if the flow state is ever corrupted.
                    state = result != null ? 0x7D : 0x52;
                    break;
                case 0x7D:
                    return result;
                default:
                    state = 0x52;
                    break;
            }
        }
    }

    private static long crc32(File file) {
        CRC32 crc = new CRC32();
        byte[] buffer = new byte[8192];
        try (InputStream in = new FileInputStream(file)) {
            int state = 0x14;
            int read = 0;
            while (true) {
                switch (state) {
                    case 0x14:
                        read = in.read(buffer);
                        state = read == -1 ? nextState(0x4A, 0x71) : nextState(0x2C, 0x72);
                        break;
                    case 0x2C:
                        crc.update(buffer, 0, read);
                        state = nextState(0x14, 0x73);
                        break;
                    case 0x71:
                    case 0x72:
                    case 0x73:
                        state = read == -1 ? 0x4A : 0x14;
                        break;
                    case 0x4A:
                        return crc.getValue();
                    default:
                        return -1L;
                }
            }
        } catch (Throwable ignored) {
            return -1L;
        }
    }

    private static File extractShellLibrary(String sourceDir, String dataDir) {
        String abi = null;
        File outDir = null;
        File out = null;
        String entryName = null;
        int state = 0x101;

        while (true) {
            switch (state) {
                case 0x101:
                    abi = abiDirName();
                    outDir = new File(new File(dataDir, LIB_DIR), abi);
                    state = nextState(0x127, 0x1E1);
                    break;
                case 0x127:
                    if (!outDir.isDirectory() && !outDir.mkdirs() && !outDir.isDirectory()) {
                        throw new IllegalStateException("cannot create shell library directory");
                    }
                    out = new File(outDir, SHELL_SO_NAME);
                    entryName = "assets/" + ZIP_LIB_DIR + "/" + abi + "/" + SHELL_SO_NAME;
                    state = nextState(0x14B, 0x1E2);
                    break;
                case 0x14B:
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
                            int copyState = 0x21;
                            int read = 0;
                            while (copyState != 0x4D) {
                                switch (copyState) {
                                    case 0x21:
                                        read = in.read(buffer);
                                        copyState = read == -1
                                                ? nextState(0x4D, 0x79)
                                                : nextState(0x38, 0x7A);
                                        break;
                                    case 0x38:
                                        output.write(buffer, 0, read);
                                        copyState = nextState(0x21, 0x7B);
                                        break;
                                    case 0x79:
                                    case 0x7A:
                                    case 0x7B:
                                        copyState = read == -1 ? 0x4D : 0x21;
                                        break;
                                    default:
                                        copyState = 0x4D;
                                        break;
                                }
                            }
                            output.flush();
                        }

                        if (expectedCrc >= 0 && crc32(out) != expectedCrc) {
                            out.delete();
                            throw new IllegalStateException("shell library checksum mismatch");
                        }
                        return out;
                    } catch (Exception e) {
                        throw new IllegalStateException("cannot extract shell library", e);
                    }
                case 0x1E1:
                case 0x1E2:
                    state = outDir == null ? 0x101 : 0x127;
                    break;
                default:
                    throw new IllegalStateException("invalid shell extraction state");
            }
        }
    }

    private void prepare(Context base) {
        int state = 0x201;
        ApplicationInfo info = null;
        File shellLibrary = null;

        while (true) {
            switch (state) {
                case 0x201:
                    state = classLoaderReady
                            ? nextState(0x26F, 0x2E1)
                            : nextState(0x219, 0x2E2);
                    break;
                case 0x219:
                    info = base.getApplicationInfo();
                    if (info == null) {
                        throw new IllegalStateException("application info is null");
                    }
                    state = nextState(0x22D, 0x2E3);
                    break;
                case 0x22D:
                    shellLibrary = extractShellLibrary(info.sourceDir, info.dataDir);
                    System.load(shellLibrary.getAbsolutePath());
                    state = nextState(0x241, 0x2E4);
                    break;
                case 0x241:
                    securityReason = securityStatus(base);
                    state = nextState(0x255, 0x2E5);
                    break;
                case 0x255:
                    ia();
                    cbde(base.getClassLoader());
                    classLoaderReady = true;
                    state = nextState(0x26F, 0x2E6);
                    break;
                case 0x26F:
                    realApplicationName = rapn();
                    return;
                case 0x2E1:
                case 0x2E2:
                case 0x2E3:
                case 0x2E4:
                case 0x2E5:
                case 0x2E6:
                    state = classLoaderReady ? 0x26F : (info == null ? 0x219 : 0x22D);
                    break;
                default:
                    state = 0x201;
                    break;
            }
        }
    }

    private void replaceApplication() {
        int state = 0x301;
        Object app = null;
        while (true) {
            switch (state) {
                case 0x301:
                    if (securityReason != 0 || !needRealApplication
                            || realApplicationName == null || realApplicationName.isEmpty()) {
                        state = nextState(0x36D, 0x3E1);
                    } else {
                        state = nextState(0x323, 0x3E2);
                    }
                    break;
                case 0x323:
                    app = ra(realApplicationName);
                    state = nextState(0x341, 0x3E3);
                    break;
                case 0x341:
                    if (app instanceof Application) {
                        realApplication = (Application) app;
                        craoc(realApplicationName);
                        needRealApplication = false;
                    }
                    state = nextState(0x36D, 0x3E4);
                    break;
                case 0x3E1:
                case 0x3E2:
                case 0x3E3:
                case 0x3E4:
                    state = 0x36D;
                    break;
                case 0x36D:
                    return;
                default:
                    return;
            }
        }
    }

    private String protectionMessage() {
        boolean rooted = false;
        boolean debuggable = false;
        String result = null;
        int state = 0x401;

        while (true) {
            switch (state) {
                case 0x401:
                    rooted = (securityReason & SECURITY_ROOT) != 0;
                    debuggable = (securityReason & SECURITY_DEBUGGABLE) != 0;
                    state = nextState(0x417, 0x4E1);
                    break;
                case 0x417:
                    if (rooted && debuggable) {
                        result = "Rooted/modified environment and a debuggable application state were detected. "
                                + "For security, this app will close automatically.";
                    } else if (rooted) {
                        result = "A rooted or modified Android environment was detected. "
                                + "For security, this protected app cannot run on this device and will close automatically.";
                    } else if (debuggable) {
                        result = "Application integrity policy failed because a debuggable build state was detected. "
                                + "This app will close automatically.";
                    } else {
                        result = "Application integrity verification failed. This app will close automatically.";
                    }
                    state = nextState(0x45B, 0x4E2);
                    break;
                case 0x4E1:
                case 0x4E2:
                    state = result == null ? 0x417 : 0x45B;
                    break;
                case 0x45B:
                    return result;
                default:
                    return "Application integrity verification failed. This app will close automatically.";
            }
        }
    }

    private void showProtectionDialog(Activity activity) {
        AlertDialog dialog = null;
        Window window = null;
        float density = 1.0f;
        int state = 0x501;

        while (true) {
            switch (state) {
                case 0x501:
                    if (securityReason == 0 || protectionDialogShown || activity == null || activity.isFinishing()) {
                        state = nextState(0x5F1, 0x5E1);
                    } else {
                        protectionDialogShown = true;
                        state = nextState(0x519, 0x5E2);
                    }
                    break;
                case 0x519:
                    dialog = new AlertDialog.Builder(activity, android.R.style.Theme_Material_Dialog_Alert)
                            .setIcon(android.R.drawable.ic_dialog_alert)
                            .setTitle(PROTECTION_TITLE)
                            .setMessage(protectionMessage())
                            .setCancelable(false)
                            .create();
                    dialog.setCanceledOnTouchOutside(false);
                    dialog.show();
                    density = activity.getResources().getDisplayMetrics().density;
                    window = dialog.getWindow();
                    state = nextState(0x537, 0x5E3);
                    break;
                case 0x537:
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
                    state = nextState(0x551, 0x5E4);
                    break;
                case 0x551:
                    int titleId = activity.getResources().getIdentifier("alertTitle", "id", "android");
                    TextView title = titleId == 0 ? null : dialog.findViewById(titleId);
                    if (title != null) {
                        title.setTextColor(Color.WHITE);
                        title.setTextSize(20.0f);
                    }
                    state = nextState(0x56B, 0x5E5);
                    break;
                case 0x56B:
                    TextView message = dialog.findViewById(android.R.id.message);
                    if (message != null) {
                        message.setTextColor(Color.rgb(220, 224, 232));
                        message.setTextSize(15.0f);
                        message.setLineSpacing(0.0f, 1.12f);
                    }
                    state = nextState(0x5F1, 0x5E6);
                    break;
                case 0x5E1:
                case 0x5E2:
                case 0x5E3:
                case 0x5E4:
                case 0x5E5:
                case 0x5E6:
                    state = dialog == null ? 0x5F1 : 0x56B;
                    break;
                case 0x5F1:
                    return;
                default:
                    return;
            }
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
        int state = 0x601;
        while (true) {
            switch (state) {
                case 0x601:
                    state = securityReason != 0
                            ? nextState(0x619, 0x6E1)
                            : nextState(0x63D, 0x6E2);
                    break;
                case 0x619:
                    registerActivityLifecycleCallbacks(this);
                    scheduleExit(3500);
                    state = nextState(0x65F, 0x6E3);
                    break;
                case 0x63D:
                    replaceApplication();
                    state = nextState(0x65F, 0x6E4);
                    break;
                case 0x6E1:
                case 0x6E2:
                case 0x6E3:
                case 0x6E4:
                    state = 0x65F;
                    break;
                case 0x65F:
                    return;
                default:
                    return;
            }
        }
    }

    @Override
    public Context createPackageContext(String packageName, int flags)
            throws PackageManager.NameNotFoundException {
        int state = 0x701;
        while (true) {
            switch (state) {
                case 0x701:
                    if (securityReason == 0 && realApplicationName != null && !realApplicationName.isEmpty()) {
                        state = nextState(0x71F, 0x7E1);
                    } else {
                        state = nextState(0x75B, 0x7E2);
                    }
                    break;
                case 0x71F:
                    replaceApplication();
                    state = realApplication != null
                            ? nextState(0x73D, 0x7E3)
                            : nextState(0x75B, 0x7E4);
                    break;
                case 0x73D:
                    return realApplication;
                case 0x75B:
                    return super.createPackageContext(packageName, flags);
                case 0x7E1:
                case 0x7E2:
                case 0x7E3:
                case 0x7E4:
                    state = realApplication != null ? 0x73D : 0x75B;
                    break;
                default:
                    return super.createPackageContext(packageName, flags);
            }
        }
    }

    @Override
    public String getPackageName() {
        int state = 0x801;
        while (true) {
            switch (state) {
                case 0x801:
                    state = securityReason == 0 && realApplicationName != null && !realApplicationName.isEmpty()
                            ? nextState(0x823, 0x8E1)
                            : nextState(0x847, 0x8E2);
                    break;
                case 0x823:
                    return "";
                case 0x847:
                    return super.getPackageName();
                case 0x8E1:
                case 0x8E2:
                    state = realApplicationName != null && !realApplicationName.isEmpty() ? 0x823 : 0x847;
                    break;
                default:
                    return super.getPackageName();
            }
        }
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
