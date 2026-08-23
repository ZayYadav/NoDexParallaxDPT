package com.parallax.shell;

import android.app.Activity;
import android.app.Application;
import android.app.Dialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Process;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.WeakHashMap;

/**
 * Parallax shell security gate.
 *
 * Security-sensitive strings are stored as encrypted byte constants and decoded
 * only when needed so release APK string tables do not expose readable markers.
 */
final class ParallaxHuYaarBhai {
    static final String ROOT_MESSAGE = z(1342016711, 232, 108, 215, 92, 206, 214, 196, 19, 157, 100, 105, 162, 158, 175, 136, 87, 245, 42, 182, 52, 106, 105, 75, 243, 150, 106, 84, 15, 90, 95, 107, 191, 41, 8, 101, 47, 150, 192, 133, 246);

    private static final String[] ROOT_PATHS = {
            z(1508175177, 57, 144, 201, 189, 109, 113, 225, 130, 200, 15, 240, 247, 33, 224),
            z(1740926551, 89, 61, 223, 214, 60, 156, 23, 204, 40, 118, 35, 96, 192, 254, 226),
            z(803369062, 25, 104, 204, 185, 22, 220, 236, 206),
            z(1779207234, 24, 214, 32, 239, 199, 115, 12, 246, 215, 7),
            z(1191935930, 235, 220, 212, 66, 45, 185, 25, 140, 251, 148, 54, 195, 18, 28),
            z(1582280913, 109, 202, 200, 102, 138, 172, 127, 44, 109, 59, 101, 198, 199, 69, 36, 8, 33, 202, 97, 111),
            z(1688269706, 102, 238, 147, 44, 80, 59, 51, 225, 69, 253, 167, 1, 36, 146, 165, 91, 156, 22, 208, 63, 131, 25, 137, 98, 216),
            z(1193241144, 21, 254, 166, 193, 127, 105, 218, 127, 68, 239, 45, 252, 245, 162, 73, 52, 235, 164, 6, 78, 159, 5, 249),
            z(1254362543, 186, 209, 205, 96, 35, 53, 110, 237, 244, 47, 97, 140, 147, 19, 224, 127),
            z(1623768376, 223, 17, 133, 44, 155, 206, 45, 161, 15, 180, 245, 106, 48, 192, 64, 8, 55),
            z(1884082683, 116, 84, 30, 217, 131, 67, 171, 8, 197, 148, 162, 79, 206),
            z(1887399019, 144, 53, 85, 254, 123, 247, 157, 14, 96, 240, 66, 119),
            z(1099843419, 161, 15, 177, 110, 108, 85, 217, 45, 60, 90, 238, 155, 25, 77, 207, 74, 206, 108, 134, 139, 79, 236),
            z(1492313105, 184, 210, 164, 13, 247, 252, 19, 23, 71, 220, 210, 193, 7),
    };

    private static final WeakHashMap<Activity, Dialog> ROOT_DIALOGS = new WeakHashMap<>();
    private static volatile int rootState = -1;
    private static volatile boolean legacyBlockerInstalled;

    private ParallaxHuYaarBhai() {
    }

    /**
     * Lightweight per-string stream transform used only for static string
     * obfuscation. The release build additionally runs through R8.
     */
    static String z(int seed, int... encrypted) {
        byte[] clear = new byte[encrypted.length];
        int state = seed;
        for (int i = 0; i < encrypted.length; i++) {
            state = state * 1103515245 + 12345;
            clear[i] = (byte) (encrypted[i] ^ ((state >>> 24) & 0xff));
        }
        return new String(clear, StandardCharsets.UTF_8);
    }

    static boolean isRootedDevice() {
        int cached = rootState;
        if (cached != -1) {
            return cached == 1;
        }

        boolean rooted = hasKnownRootPath() || hasSuInPath() || hasRootMountMarker();
        rootState = rooted ? 1 : 0;
        return rooted;
    }

    private static boolean hasKnownRootPath() {
        for (String path : ROOT_PATHS) {
            try {
                if (new File(path).exists()) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private static boolean hasSuInPath() {
        try {
            String path = System.getenv(z(1402350080, 131, 68, 221, 150));
            if (path == null || path.length() == 0) {
                return false;
            }
            String[] dirs = path.split(File.pathSeparator);
            String su = z(423393304, 86, 200);
            for (String dir : dirs) {
                if (dir != null && dir.length() != 0 && new File(dir, su).exists()) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hasRootMountMarker() {
        try (BufferedReader reader = new BufferedReader(new FileReader(z(1157822896, 55, 61, 254, 48, 142, 167, 163, 67, 239, 160, 15, 1, 97, 173, 60, 149, 22)))) {
            String line;
            final String magisk = z(1847400850, 244, 48, 59, 130, 231, 100);
            final String kernelSu = z(1958600229, 175, 239, 234, 13, 148, 80, 9, 154);
            final String modules = z(1623768376, 223, 17, 133, 44, 155, 206, 45, 161, 15, 180, 245, 106, 48, 192, 64, 8, 55);
            final String ksu = z(1884082683, 116, 84, 30, 217, 131, 67, 171, 8, 197, 148, 162, 79, 206);
            final String apatch = z(1674556566, 235, 217, 143, 69, 230, 40);
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains(magisk)
                        || lower.contains(kernelSu)
                        || lower.contains(modules)
                        || lower.contains(ksu)
                        || lower.contains(apatch)) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    static void installLegacyActivityBlocker(Application application) {
        if (legacyBlockerInstalled) {
            return;
        }
        synchronized (ParallaxHuYaarBhai.class) {
            if (legacyBlockerInstalled) {
                return;
            }
            legacyBlockerInstalled = true;
        }

        application.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
            @Override
            public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
                showRootDialog(activity);
            }

            @Override
            public void onActivityStarted(Activity activity) {
                showRootDialog(activity);
            }

            @Override
            public void onActivityResumed(Activity activity) {
                showRootDialog(activity);
            }

            @Override public void onActivityPaused(Activity activity) { }
            @Override public void onActivityStopped(Activity activity) { }
            @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) { }
            @Override public void onActivityDestroyed(Activity activity) { }
        });
    }

    static void showRootDialog(final Activity activity) {
        if (activity == null || activity.isFinishing()) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (activity.isFinishing()) {
                    return;
                }
                synchronized (ROOT_DIALOGS) {
                    Dialog existing = ROOT_DIALOGS.get(activity);
                    if (existing != null && existing.isShowing()) {
                        return;
                    }

                    final Dialog dialog = new Dialog(activity);
                    dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
                    dialog.setCancelable(false);
                    dialog.setCanceledOnTouchOutside(false);

                    FrameLayout frame = new FrameLayout(activity);
                    int outer = dp(activity, 20);
                    frame.setPadding(outer, 0, outer, 0);

                    LinearLayout card = new LinearLayout(activity);
                    card.setOrientation(LinearLayout.VERTICAL);
                    card.setGravity(Gravity.CENTER_HORIZONTAL);
                    int cardPadding = dp(activity, 24);
                    card.setPadding(cardPadding, cardPadding, cardPadding, cardPadding);

                    GradientDrawable cardBackground = new GradientDrawable();
                    cardBackground.setColor(Color.rgb(20, 21, 28));
                    cardBackground.setCornerRadius(dp(activity, 24));
                    cardBackground.setStroke(dp(activity, 1), Color.rgb(238, 75, 95));
                    card.setBackground(cardBackground);

                    TextView icon = new TextView(activity);
                    icon.setText(z(1808495703, 212));
                    icon.setTextColor(Color.WHITE);
                    icon.setTextSize(26);
                    icon.setTypeface(Typeface.DEFAULT_BOLD);
                    icon.setGravity(Gravity.CENTER);
                    GradientDrawable iconBackground = new GradientDrawable();
                    iconBackground.setShape(GradientDrawable.OVAL);
                    iconBackground.setColor(Color.rgb(238, 75, 95));
                    icon.setBackground(iconBackground);
                    LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(dp(activity, 54), dp(activity, 54));
                    card.addView(icon, iconParams);

                    TextView title = new TextView(activity);
                    title.setText(z(1687518700, 224, 235, 123, 104, 138, 76, 194, 253, 121, 161, 68, 68, 68, 15, 128, 15, 87));
                    title.setTextColor(Color.WHITE);
                    title.setTextSize(21);
                    title.setTypeface(Typeface.create(z(1513773003, 208, 50, 198, 253, 168, 111, 103, 66, 57, 147, 140, 217, 85, 110, 49, 126, 154), Typeface.BOLD));
                    title.setGravity(Gravity.CENTER);
                    LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    titleParams.topMargin = dp(activity, 18);
                    card.addView(title, titleParams);

                    TextView message = new TextView(activity);
                    message.setText(ROOT_MESSAGE);
                    message.setTextColor(Color.rgb(245, 245, 248));
                    message.setTextSize(16);
                    message.setGravity(Gravity.CENTER);
                    message.setLineSpacing(0, 1.15f);
                    LinearLayout.LayoutParams messageParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    messageParams.topMargin = dp(activity, 12);
                    card.addView(message, messageParams);

                    TextView detail = new TextView(activity);
                    detail.setText(z(683943634, 37, 47, 21, 139, 63, 235, 160, 29, 5, 60, 54, 190, 60, 218, 111, 178, 251, 213, 38, 83, 142, 242, 207, 210, 158, 77, 50, 58, 136, 90, 156, 97, 128, 30, 46, 12, 109, 59, 148, 26, 63, 13, 18, 106, 103, 197, 43, 15, 28, 75, 116, 172, 93, 70, 248, 121, 127, 9, 126, 180, 58, 245, 167, 233, 1, 8, 103, 106, 64, 197, 250, 201, 108, 75, 227, 16, 209, 216, 189, 187, 101, 172, 55, 47, 20, 64, 157, 121, 80, 243, 132, 43, 132));
                    detail.setTextColor(Color.rgb(176, 178, 190));
                    detail.setTextSize(13);
                    detail.setGravity(Gravity.CENTER);
                    detail.setLineSpacing(0, 1.2f);
                    LinearLayout.LayoutParams detailParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    detailParams.topMargin = dp(activity, 10);
                    card.addView(detail, detailParams);

                    Button closeButton = new Button(activity);
                    closeButton.setText(z(1104896450, 131, 220, 97, 193, 102, 103, 26, 215, 199));
                    closeButton.setAllCaps(false);
                    closeButton.setTextColor(Color.WHITE);
                    closeButton.setTextSize(15);
                    closeButton.setTypeface(Typeface.create(z(1513773003, 208, 50, 198, 253, 168, 111, 103, 66, 57, 147, 140, 217, 85, 110, 49, 126, 154), Typeface.BOLD));
                    closeButton.setPadding(dp(activity, 18), dp(activity, 11), dp(activity, 18), dp(activity, 11));
                    GradientDrawable buttonBackground = new GradientDrawable();
                    buttonBackground.setColor(Color.rgb(216, 55, 78));
                    buttonBackground.setCornerRadius(dp(activity, 16));
                    closeButton.setBackground(buttonBackground);
                    closeButton.setOnClickListener(new View.OnClickListener() {
                        @Override
                        public void onClick(View v) {
                            terminate(activity);
                        }
                    });
                    LinearLayout.LayoutParams buttonParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    buttonParams.topMargin = dp(activity, 22);
                    card.addView(closeButton, buttonParams);

                    frame.addView(card, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER));
                    dialog.setContentView(frame);
                    ROOT_DIALOGS.put(activity, dialog);
                    dialog.show();

                    Window window = dialog.getWindow();
                    if (window != null) {
                        window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
                        WindowManager.LayoutParams params = window.getAttributes();
                        params.width = WindowManager.LayoutParams.MATCH_PARENT;
                        params.height = WindowManager.LayoutParams.WRAP_CONTENT;
                        params.dimAmount = 0.78f;
                        window.setAttributes(params);
                        window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
                    }
                }
            }
        });
    }

    private static int dp(Activity activity, int value) {
        return Math.round(value * activity.getResources().getDisplayMetrics().density);
    }

    private static void terminate(Activity activity) {
        try {
            activity.finishAndRemoveTask();
        } catch (Throwable ignored) {
            activity.finish();
        }
        Process.killProcess(Process.myPid());
        System.exit(0);
    }
}
