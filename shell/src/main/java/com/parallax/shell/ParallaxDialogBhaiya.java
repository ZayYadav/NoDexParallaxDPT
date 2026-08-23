package com.parallax.shell;

import android.app.Activity;
import android.app.Application;
import android.app.Dialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
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

import java.util.WeakHashMap;

/** Styled protection dialogs. Display strings remain obfuscated in the DEX. */
final class ParallaxDialogBhaiya {
    private static final WeakHashMap<Activity, Dialog> DIALOGS = new WeakHashMap<>();
    private static volatile boolean installed;

    private ParallaxDialogBhaiya() {
    }

    static void installActivityBlocker(Application app) {
        if (installed) return;
        synchronized (ParallaxDialogBhaiya.class) {
            if (installed) return;
            installed = true;
        }
        app.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(Activity a, android.os.Bundle b) { show(a, Global.sProtectionBlockReason); }
            @Override public void onActivityStarted(Activity a) { show(a, Global.sProtectionBlockReason); }
            @Override public void onActivityResumed(Activity a) { show(a, Global.sProtectionBlockReason); }
            @Override public void onActivityPaused(Activity a) { }
            @Override public void onActivityStopped(Activity a) { }
            @Override public void onActivitySaveInstanceState(Activity a, android.os.Bundle b) { }
            @Override public void onActivityDestroyed(Activity a) { }
        });
    }

    static void show(final Activity activity, final int reason) {
        if (activity == null || activity.isFinishing() || reason == ParallaxBhaiya.CLEAR) return;
        activity.runOnUiThread(new Runnable() {
            @Override public void run() {
                synchronized (DIALOGS) {
                    Dialog old = DIALOGS.get(activity);
                    if (old != null && old.isShowing()) return;

                    final Dialog dialog = new Dialog(activity);
                    dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
                    dialog.setCancelable(false);
                    dialog.setCanceledOnTouchOutside(false);

                    FrameLayout frame = new FrameLayout(activity);
                    frame.setPadding(dp(activity, 20), 0, dp(activity, 20), 0);

                    LinearLayout card = new LinearLayout(activity);
                    card.setOrientation(LinearLayout.VERTICAL);
                    card.setGravity(Gravity.CENTER_HORIZONTAL);
                    card.setPadding(dp(activity, 24), dp(activity, 24), dp(activity, 24), dp(activity, 24));
                    GradientDrawable bg = new GradientDrawable();
                    bg.setColor(Color.rgb(20, 21, 28));
                    bg.setCornerRadius(dp(activity, 24));
                    bg.setStroke(dp(activity, 1), Color.rgb(238, 75, 95));
                    card.setBackground(bg);

                    TextView icon = new TextView(activity);
                    icon.setText(ParallaxHuYaarBhai.z(1808495703, 212));
                    icon.setTextColor(Color.WHITE);
                    icon.setTextSize(26);
                    icon.setTypeface(Typeface.DEFAULT_BOLD);
                    icon.setGravity(Gravity.CENTER);
                    GradientDrawable iconBg = new GradientDrawable();
                    iconBg.setShape(GradientDrawable.OVAL);
                    iconBg.setColor(Color.rgb(238, 75, 95));
                    icon.setBackground(iconBg);
                    card.addView(icon, new LinearLayout.LayoutParams(dp(activity, 54), dp(activity, 54)));

                    TextView title = text(activity,
                            ParallaxHuYaarBhai.z(1325293009, 147, 159, 238, 167, 42, 128, 88, 244, 86, 127, 253, 93, 44, 240, 135, 197, 0, 235, 184),
                            21, Color.WHITE);
                    title.setTypeface(Typeface.create(
                            ParallaxHuYaarBhai.z(797108530, 95, 231, 81, 145, 146, 97, 78, 198, 4, 169, 235, 255, 135, 9, 130, 93, 37),
                            Typeface.BOLD));
                    add(card, title, 18);

                    TextView message = text(activity, message(reason), 16, Color.rgb(245, 245, 248));
                    add(card, message, 12);

                    TextView detail = text(activity, detail(reason), 13, Color.rgb(176, 178, 190));
                    detail.setLineSpacing(0, 1.2f);
                    add(card, detail, 10);

                    Button close = new Button(activity);
                    close.setText(ParallaxHuYaarBhai.z(1077029238, 230, 146, 112, 218, 191, 2, 139, 138, 57));
                    close.setAllCaps(false);
                    close.setTextColor(Color.WHITE);
                    close.setTextSize(15);
                    close.setFilterTouchesWhenObscured(true);
                    GradientDrawable buttonBg = new GradientDrawable();
                    buttonBg.setColor(Color.rgb(216, 55, 78));
                    buttonBg.setCornerRadius(dp(activity, 16));
                    close.setBackground(buttonBg);
                    close.setOnClickListener(new View.OnClickListener() {
                        @Override public void onClick(View v) { terminate(activity); }
                    });
                    add(card, close, 22);

                    frame.addView(card, new FrameLayout.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT,
                            Gravity.CENTER));
                    dialog.setContentView(frame);
                    DIALOGS.put(activity, dialog);
                    dialog.show();

                    Window w = dialog.getWindow();
                    if (w != null) {
                        w.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
                        WindowManager.LayoutParams p = w.getAttributes();
                        p.width = WindowManager.LayoutParams.MATCH_PARENT;
                        p.height = WindowManager.LayoutParams.WRAP_CONTENT;
                        p.dimAmount = 0.78f;
                        w.setAttributes(p);
                        w.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND | WindowManager.LayoutParams.FLAG_SECURE);
                    }
                }
            }
        });
    }

    private static TextView text(Activity a, String value, int size, int color) {
        TextView v = new TextView(a);
        v.setText(value);
        v.setTextColor(color);
        v.setTextSize(size);
        v.setGravity(Gravity.CENTER);
        return v;
    }

    private static void add(LinearLayout parent, View child, int top) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp((Activity) parent.getContext(), top);
        parent.addView(child, p);
    }

    private static String message(int reason) {
        if (reason == ParallaxBhaiya.ROOT) return ParallaxHuYaarBhai.ROOT_MESSAGE;
        if (reason == ParallaxBhaiya.DEVELOPER_UNAUTHORIZED) {
            return ParallaxHuYaarBhai.z(254057330, 130, 180, 82, 196, 49, 22, 237, 102, 102, 58, 229, 68, 126, 32, 68, 255, 3, 136, 26, 65, 25, 39, 193, 74, 123, 64, 238, 6, 75, 168, 211, 210);
        }
        if (reason == ParallaxBhaiya.VIRTUAL) {
            return ParallaxHuYaarBhai.z(727938575, 179, 225, 246, 177, 23, 245, 177, 52, 167, 167, 69, 243, 172, 251, 92, 150, 225, 217, 173, 167, 121, 162, 72, 132, 214, 118, 18, 211, 126, 138, 224, 7, 240);
        }
        return ParallaxHuYaarBhai.z(885801723, 19, 145, 82, 236, 236, 145, 35, 40, 83, 78, 14, 55, 20, 225, 221, 107, 206, 4, 70, 67, 44, 68, 85, 153, 145, 254, 226, 149, 240, 34, 57, 47, 222, 190, 93);
    }

    private static String detail(int reason) {
        if (reason == ParallaxBhaiya.ROOT) {
            return ParallaxHuYaarBhai.z(683943634, 37, 47, 21, 139, 63, 235, 160, 29, 5, 60, 54, 190, 60, 218, 111, 178, 251, 213, 38, 83, 142, 242, 207, 210, 158, 77, 50, 58, 136, 90, 156, 97, 128, 30, 46, 12, 109, 59, 148, 26, 63, 13, 18, 106, 103, 197, 43, 15, 28, 75, 116, 172, 93, 70, 248, 121, 127, 9, 126, 180, 58, 245, 167, 233, 1, 8, 103, 106, 64, 197, 250, 201, 108, 75, 227, 16, 209, 216, 189, 187, 101, 172, 55, 47, 20, 64, 157, 121, 80, 243, 132, 43, 132);
        }
        if (reason == ParallaxBhaiya.DEVELOPER_UNAUTHORIZED) {
            return ParallaxHuYaarBhai.z(126941328, 119, 235, 163, 144, 79, 193, 122, 118, 206, 40, 37, 127, 70, 119, 230, 110, 117, 94, 69, 196, 2, 209, 226, 107, 81, 59, 29, 202, 249, 245, 147, 15, 250, 26, 107, 140, 125, 125, 109, 26, 19, 211, 224, 120, 120, 53, 107, 182, 82, 59, 198, 22, 63, 182, 161, 48, 255, 236, 186, 84, 53, 115, 91, 153, 64, 124, 33, 150, 248, 186, 91, 255, 171, 190, 33, 120, 48, 189, 70, 85, 0, 42, 240, 21, 30, 55, 48, 74, 180, 31, 36, 190, 173, 7, 74, 30, 64, 181, 130, 96, 217, 12, 188, 240, 228, 118, 99, 17);
        }
        if (reason == ParallaxBhaiya.VIRTUAL) {
            return ParallaxHuYaarBhai.z(627928656, 185, 17, 37, 243, 252, 122, 218, 166, 73, 71, 7, 253, 122, 36, 129, 80, 177, 162, 122, 198, 212, 236, 238, 216, 15, 52, 79, 164, 109, 101, 180, 97, 178, 88, 55, 33, 228, 127, 108, 77, 116, 197, 9, 10, 1, 87, 102, 204, 126, 6, 149, 200, 28, 105, 209, 165, 26, 112, 203, 16, 5, 218, 0, 105, 102, 151, 152, 54, 55, 248, 168, 225, 91);
        }
        return ParallaxHuYaarBhai.z(271470081, 209, 21, 205, 209, 143, 112, 49, 44, 84, 46, 175, 163, 142, 191, 98, 203, 120, 96, 96, 221, 190, 119, 64, 242, 71, 180, 28, 216, 186, 75, 87, 221, 48, 63, 134, 123, 144, 169, 108, 136, 163, 213, 49, 196, 158, 100, 47, 219, 162, 131, 47, 49, 3, 180, 63, 177, 44, 212, 218, 195, 66, 95, 153, 248, 5, 146, 10, 253, 64, 102, 205, 144, 69, 225, 88, 217, 156, 190, 23, 84, 207, 16, 28, 14, 137, 83, 102, 48, 245, 246, 131, 221, 241, 170, 41, 127, 115);
    }

    private static int dp(Activity a, int v) {
        return Math.round(v * a.getResources().getDisplayMetrics().density);
    }

    private static void terminate(Activity a) {
        try { a.finishAndRemoveTask(); } catch (Throwable ignored) { a.finish(); }
        Process.killProcess(Process.myPid());
        System.exit(0);
    }
}
