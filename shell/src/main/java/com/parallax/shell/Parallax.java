package com.parallax.shell;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Local-only protection screen. It intentionally performs no network requests and does
 * not depend on mutable remote media while the protected process is quarantined.
 */
public final class Parallax extends Activity {

    private static final AtomicBoolean LAUNCH_REQUESTED = new AtomicBoolean(false);
    private boolean screenReady;

    static void request(Activity activity) {
        if (activity == null || activity.isFinishing()) {
            return;
        }
        if (activity instanceof Parallax) {
            ((Parallax) activity).ensureProtectionScreen();
            return;
        }
        if (!LAUNCH_REQUESTED.compareAndSet(false, true)) {
            return;
        }

        try {
            ComponentName component = activity.getComponentName();
            if (component == null) {
                LAUNCH_REQUESTED.set(false);
                return;
            }
            Intent intent = new Intent();
            intent.setComponent(component);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_MULTIPLE_TASK);
            activity.startActivity(intent);
        } catch (Throwable ignored) {
            LAUNCH_REQUESTED.set(false);
        }
    }

    private int dp(float value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private TextView label(String text, float sp, int color, int style) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setTypeface(Typeface.create("sans-serif", style));
        view.setGravity(Gravity.CENTER);
        return view;
    }

    private GradientDrawable rounded(int color, float radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radiusDp));
        drawable.setStroke(dp(1), Color.argb(120, 255, 90, 90));
        return drawable;
    }

    private void applyImmersiveMode() {
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN
                | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        if (Build.VERSION.SDK_INT >= 28) {
            WindowManager.LayoutParams attrs = window.getAttributes();
            attrs.layoutInDisplayCutoutMode =
                    WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
            window.setAttributes(attrs);
        }
        window.getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                        | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_FULLSCREEN
                        | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                        | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
    }

    private View buildLocalProtectionContent() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.rgb(5, 7, 12));

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setGravity(Gravity.CENTER);
        card.setPadding(dp(24), dp(26), dp(24), dp(26));
        card.setBackground(rounded(Color.rgb(17, 22, 34), 22));

        TextView badge = label("TEAM DARK • CLIENT PROTECTION",
                11.5f, Color.rgb(255, 190, 82), Typeface.BOLD);
        card.addView(badge, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = label("PARALLAX PROTECTION",
                25f, Color.WHITE, Typeface.BOLD);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        titleParams.topMargin = dp(12);
        card.addView(title, titleParams);

        TextView reason = label(ParallaxKiSettingKarwaDo.protectionMessage(),
                14f, Color.rgb(255, 142, 142), Typeface.BOLD);
        LinearLayout.LayoutParams reasonParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        reasonParams.topMargin = dp(16);
        card.addView(reason, reasonParams);

        TextView footer = label(
                "Protection is enforced locally. Close this environment and relaunch the app.",
                12f, Color.rgb(205, 212, 225), Typeface.NORMAL);
        LinearLayout.LayoutParams footerParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        footerParams.topMargin = dp(16);
        card.addView(footer, footerParams);

        FrameLayout.LayoutParams cardParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER);
        cardParams.leftMargin = dp(22);
        cardParams.rightMargin = dp(22);
        root.addView(card, cardParams);
        return root;
    }

    private void ensureProtectionScreen() {
        if (isFinishing()) {
            return;
        }
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
        applyImmersiveMode();
        if (screenReady) {
            return;
        }
        screenReady = true;
        setContentView(buildLocalProtectionContent());
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        setTheme(android.R.style.Theme_DeviceDefault_NoActionBar);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
        super.onCreate(savedInstanceState);
        LAUNCH_REQUESTED.set(true);
        getWindow().setStatusBarColor(Color.BLACK);
        getWindow().setNavigationBarColor(Color.BLACK);
        ParallaxKoLadkiChahiye.rememberActivity(this);
        ensureProtectionScreen();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ParallaxKoLadkiChahiye.rememberActivity(this);
        ensureProtectionScreen();
        applyImmersiveMode();
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) {
            applyImmersiveMode();
        }
    }

    @Override
    public void onBackPressed() {
        // Quarantine screen is intentionally non-cancelable.
    }
}
