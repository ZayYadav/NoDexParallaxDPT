package com.parallax.shell;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.media.MediaPlayer;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.VideoView;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;

public final class Parallax extends Activity
        implements Runnable, MediaPlayer.OnPreparedListener, MediaPlayer.OnErrorListener {

    private static final long MAX_VIDEO_BYTES = 128L * 1024L * 1024L;
    private static final AtomicBoolean LAUNCH_REQUESTED = new AtomicBoolean(false);
    private static volatile int FLOW = 0x61C88647;

    private VideoView videoView;
    private LinearLayout loadingLayer;
    private ProgressBar progressBar;
    private TextView videoStatus;
    private File downloadedVideo;
    private Handler mainHandler;
    private volatile boolean downloadFailed;
    private boolean screenReady;

    private static String x(int key, int... data) {
        char[] out = new char[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (char) (data[i] ^ key);
        }
        return new String(out);
    }

    private static int hop(int real, int decoy) {
        int n = FLOW ^ (int) SystemClock.elapsedRealtimeNanos();
        FLOW = Integer.rotateLeft(n + 0x7F4A7C15, 9) ^ 0x9E3779B9;
        return (n & 1) == 0 ? real : decoy;
    }

    private static String videoUrl() {
        return x(55,95,67,67,71,68,13,24,24,80,94,67,95,66,85,25,84,88,90,24,68,92,15,0,15,0,14,6,3,26,90,86,92,82,69,24,109,88,69,88,26,88,89,91,94,89,82,26,90,88,83,24,69,86,64,24,69,82,81,68,24,95,82,86,83,68,24,90,86,94,89,24,97,126,115,104,5,7,5,1,7,15,5,5,104,5,4,2,6,6,6,104,5,7,1,25,90,71,3);
    }

    static void request(Activity activity) {
        int state = 0x21;
        for (;;) {
            switch (state) {
                case 0x21:
                    if (activity == null || activity.isFinishing()) return;
                    state = activity instanceof Parallax ? hop(0x31, 0x71) : hop(0x41, 0x72);
                    break;
                case 0x31:
                    ((Parallax) activity).ensureProtectionScreen();
                    return;
                case 0x41:
                    if (!LAUNCH_REQUESTED.compareAndSet(false, true)) return;
                    state = 0x51;
                    break;
                case 0x51:
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
                    return;
                case 0x71: state = 0x31; break;
                case 0x72: state = 0x41; break;
                default: state = 0x21; break;
            }
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
        return drawable;
    }

    private void applyImmersiveMode() {
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN
                | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
                | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS);
        if (Build.VERSION.SDK_INT >= 28) {
            WindowManager.LayoutParams attrs = window.getAttributes();
            attrs.layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
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

    private ViewGroup buildFullscreenContent() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.BLACK);

        videoView = new VideoView(this);
        FrameLayout.LayoutParams videoParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
                Gravity.CENTER);
        root.addView(videoView, videoParams);

        View scrim = new View(this);
        scrim.setBackgroundColor(Color.argb(86, 0, 0, 0));
        root.addView(scrim, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout topOverlay = new LinearLayout(this);
        topOverlay.setOrientation(LinearLayout.VERTICAL);
        topOverlay.setGravity(Gravity.CENTER_HORIZONTAL);
        topOverlay.setPadding(dp(20), dp(14), dp(20), dp(12));
        topOverlay.setBackground(rounded(Color.argb(150, 8, 10, 15), 18));

        TextView badge = label(x(49,9873,17,17,97,112,99,112,125,125,112,105,17,98,116,114,100,99,120,101,104,17,102,112,99,127,120,127,118),
                11.5f, Color.rgb(255, 195, 92), Typeface.BOLD);
        badge.setPadding(dp(12), dp(5), dp(12), dp(5));
        badge.setBackground(rounded(Color.argb(190, 62, 47, 22), 24));
        topOverlay.addView(badge, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = label(x(56,104,89,74,89,84,84,89,64,24,104,74,87,76,93,91,76,81,87,86),
                24f, Color.WHITE, Typeface.BOLD);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        titleParams.topMargin = dp(7);
        topOverlay.addView(title, titleParams);

        TextView subtitle = label(x(63,106,81,76,94,89,90,31,77,74,81,75,86,82,90,31,90,81,73,86,77,80,81,82,90,81,75,31,91,90,75,90,92,75,90,91,17,31,126,92,92,90,76,76,31,87,94,76,31,93,90,90,81,31,93,83,80,92,84,90,91,17),
                13.5f, Color.rgb(225, 228, 236), Typeface.NORMAL);
        LinearLayout.LayoutParams subtitleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subtitleParams.topMargin = dp(3);
        topOverlay.addView(subtitle, subtitleParams);

        TextView reason = label(ParallaxKiSettingKarwaDo.protectionMessage(),
                13f, Color.rgb(255, 160, 160), Typeface.BOLD);
        reason.setPadding(dp(12), dp(8), dp(12), dp(8));
        reason.setBackground(rounded(Color.argb(190, 72, 24, 31), 14));
        LinearLayout.LayoutParams reasonParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        reasonParams.topMargin = dp(8);
        topOverlay.addView(reason, reasonParams);

        FrameLayout.LayoutParams topParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP | Gravity.CENTER_HORIZONTAL);
        topParams.leftMargin = dp(18);
        topParams.rightMargin = dp(18);
        topParams.topMargin = dp(10);
        root.addView(topOverlay, topParams);

        TextView footer = label(x(77,31,40,32,34,59,40,109,63,34,34,57,109,98,109,36,35,62,57,63,56,32,40,35,57,44,57,36,34,35,109,57,34,34,33,62,109,44,35,41,109,63,40,34,61,40,35,109,57,37,40,109,44,61,61,99),
                12.5f, Color.WHITE, Typeface.NORMAL);
        footer.setPadding(dp(15), dp(9), dp(15), dp(9));
        footer.setBackground(rounded(Color.argb(165, 8, 10, 15), 18));
        FrameLayout.LayoutParams footerParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        footerParams.bottomMargin = dp(14);
        footerParams.leftMargin = dp(18);
        footerParams.rightMargin = dp(18);
        root.addView(footer, footerParams);

        loadingLayer = new LinearLayout(this);
        loadingLayer.setOrientation(LinearLayout.HORIZONTAL);
        loadingLayer.setGravity(Gravity.CENTER_VERTICAL);
        loadingLayer.setPadding(dp(14), dp(10), dp(14), dp(10));
        loadingLayer.setBackground(rounded(Color.argb(205, 8, 10, 15), 22));

        progressBar = new ProgressBar(this);
        loadingLayer.addView(progressBar, new LinearLayout.LayoutParams(dp(30), dp(30)));

        videoStatus = label(x(70,22,52,35,54,39,52,47,40,33,102,53,35,37,51,52,47,50,63,102,40,41,50,47,37,35,8288),
                12.5f, Color.rgb(225, 228, 236), Typeface.NORMAL);
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        statusParams.leftMargin = dp(10);
        loadingLayer.addView(videoStatus, statusParams);

        FrameLayout.LayoutParams loadingParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER);
        root.addView(loadingLayer, loadingParams);

        return root;
    }

    private void ensureProtectionScreen() {
        if (isFinishing()) return;
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
        applyImmersiveMode();
        if (screenReady) return;
        screenReady = true;
        setContentView(buildFullscreenContent());
        mainHandler = new Handler(Looper.getMainLooper());
        Thread downloader = new Thread(this, x(83,3,50,33,50,63,63,50,43,3,33,60,39,54,48,39,58,60,61,124,98,125,99));
        downloader.setDaemon(true);
        downloader.start();
    }

    private File downloadVideo() throws Exception {
        File dir = new File(getFilesDir(), x(62,78,95,76,95,82,82,95,70,97,78,76,81,74,91,93,74,87,81,80));
        if (!dir.exists() && !dir.mkdirs()) throw new IllegalStateException("cache");
        File target = new File(dir, x(69,50,36,55,43,44,43,34,107,40,53,113));
        if (target.isFile() && target.length() > 4096L) return target;
        File temp = new File(dir, x(76,59,45,62,34,37,34,43,98,33,60,120,98,60,45,62,56));
        if (temp.exists()) temp.delete();

        HttpURLConnection connection = null;
        long total = 0L;
        try {
            connection = (HttpURLConnection) new URL(videoUrl()).openConnection();
            connection.setConnectTimeout(12000);
            connection.setReadTimeout(20000);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("User-Agent", x(90,57,59,52,52,53,46,122,57,40,63,59,46,63,122,44,51,62,63,53,122,57,59,57,50,63,122,62,51,40,63,57,46,53,40,35));
            connection.connect();
            int code = connection.getResponseCode();
            if (code < 200 || code >= 300) throw new IllegalStateException("http");
            long declared = connection.getContentLength();
            if (declared > MAX_VIDEO_BYTES) throw new IllegalStateException("size");

            try (BufferedInputStream input = new BufferedInputStream(connection.getInputStream());
                 BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream(temp))) {
                byte[] buffer = new byte[32768];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    total += read;
                    if (total > MAX_VIDEO_BYTES) throw new IllegalStateException("limit");
                    output.write(buffer, 0, read);
                }
                output.flush();
            }
        } finally {
            if (connection != null) connection.disconnect();
        }

        if (total <= 4096L) {
            temp.delete();
            throw new IllegalStateException("empty");
        }
        if (target.exists()) target.delete();
        if (!temp.renameTo(target)) throw new IllegalStateException("rename");
        return target;
    }

    @Override
    public void run() {
        int state = Looper.myLooper() == Looper.getMainLooper() ? hop(0x201, 0x281) : hop(0x202, 0x282);
        for (;;) {
            switch (state) {
                case 0x201:
                    if (videoView == null || videoStatus == null) return;
                    if (downloadFailed || downloadedVideo == null) {
                        if (progressBar != null) progressBar.setVisibility(View.GONE);
                        videoStatus.setText(x(84,2,61,48,49,59,116,33,58,53,34,53,61,56,53,54,56,49,122,116,7,49,55,33,38,61,32,45,116,35,53,38,58,61,58,51,116,38,49,57,53,61,58,39,116,53,55,32,61,34,49,122));
                        return;
                    }
                    videoStatus.setText(x(91,8,62,56,46,41,50,47,34,123,53,52,47,50,56,62,123,41,62,58,63,34));
                    if (progressBar != null) progressBar.setVisibility(View.GONE);
                    videoView.setOnPreparedListener(this);
                    videoView.setOnErrorListener(this);
                    videoView.setVideoPath(downloadedVideo.getAbsolutePath());
                    videoView.start();
                    return;
                case 0x202:
                    try {
                        downloadedVideo = downloadVideo();
                    } catch (Throwable ignored) {
                        downloadFailed = true;
                    }
                    if (mainHandler != null) mainHandler.post(this);
                    return;
                case 0x281: state = 0x201; break;
                case 0x282: state = 0x202; break;
                default: return;
            }
        }
    }

    @Override
    public void onPrepared(MediaPlayer mediaPlayer) {
        mediaPlayer.setLooping(true);
        mediaPlayer.setVolume(1.0f, 1.0f);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            try {
                mediaPlayer.setVideoScalingMode(MediaPlayer.VIDEO_SCALING_MODE_SCALE_TO_FIT_WITH_CROPPING);
            } catch (Throwable ignored) { }
        }
        if (loadingLayer != null) loadingLayer.setVisibility(View.GONE);
        if (videoView != null && !videoView.isPlaying()) videoView.start();
        applyImmersiveMode();
    }

    @Override
    public boolean onError(MediaPlayer mediaPlayer, int what, int extra) {
        if (loadingLayer != null) loadingLayer.setVisibility(View.VISIBLE);
        if (progressBar != null) progressBar.setVisibility(View.GONE);
        if (videoStatus != null) {
            videoStatus.setText(x(84,2,61,48,49,59,116,33,58,53,34,53,61,56,53,54,56,49,122,116,7,49,55,33,38,61,32,45,116,35,53,38,58,61,58,51,116,38,49,57,53,61,58,39,116,53,55,32,61,34,49,122));
        }
        return true;
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
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
        ParallaxKoLadkiChahiye.rememberActivity(this);
        ensureProtectionScreen();
        applyImmersiveMode();
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) applyImmersiveMode();
    }

    @Override
    public void onBackPressed() { }
}
