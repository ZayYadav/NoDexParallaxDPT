package com.parallax.shell;

import android.app.Activity;
import android.app.Dialog;
import android.content.ComponentName;
import android.content.Intent;
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
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Space;
import android.widget.TextView;
import android.widget.VideoView;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;

public final class ParallaxKiGF extends Activity
        implements Runnable, MediaPlayer.OnPreparedListener, MediaPlayer.OnErrorListener {

    private static final long MAX_VIDEO_BYTES = 128L * 1024L * 1024L;
    private static final AtomicBoolean LAUNCH_REQUESTED = new AtomicBoolean(false);
    private static volatile int FLOW = 0x61C88647;

    private Dialog protectionDialog;
    private VideoView videoView;
    private LinearLayout loadingLayer;
    private ProgressBar progressBar;
    private TextView videoStatus;
    private File downloadedVideo;
    private Handler mainHandler;
    private volatile boolean downloadFailed;

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
                    state = activity instanceof ParallaxKiGF ? hop(0x31, 0x71) : hop(0x41, 0x72);
                    break;
                case 0x31:
                    ((ParallaxKiGF) activity).ensureProtectionDialog();
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
        view.setGravity(Gravity.CENTER_HORIZONTAL);
        return view;
    }

    private GradientDrawable rounded(int color, float radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(radiusDp));
        return drawable;
    }

    private ViewGroup buildDialogContent() {
        final int pad = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(pad, pad, pad, pad);
        root.setBackground(rounded(Color.rgb(16, 19, 28), 24));

        int state = 0x101;
        for (;;) {
            switch (state) {
                case 0x101: {
                    TextView badge = label(x(49,9873,17,17,97,112,99,112,125,125,112,105,17,98,116,114,100,99,120,101,104,17,102,112,99,127,120,127,118), 12f,
                            Color.rgb(255, 189, 89), Typeface.BOLD);
                    badge.setPadding(dp(12), dp(7), dp(12), dp(7));
                    badge.setBackground(rounded(Color.rgb(48, 39, 24), 30));
                    root.addView(badge, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                    root.addView(new Space(this), new LinearLayout.LayoutParams(1, dp(12)));
                    state = hop(0x102, 0x181);
                    break;
                }
                case 0x102: {
                    TextView title = label(x(56,104,89,74,89,84,84,89,64,24,104,74,87,76,93,91,76,81,87,86), 25f, Color.WHITE, Typeface.BOLD);
                    root.addView(title, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                    TextView subtitle = label(x(63,106,81,76,94,89,90,31,77,74,81,75,86,82,90,31,90,81,73,86,77,80,81,82,90,81,75,31,91,90,75,90,92,75,90,91,17,31,111,77,80,75,90,92,75,90,91,31,92,80,91,90,31,87,94,76,31,81,80,75,31,93,90,90,81,31,83,80,94,91,90,91,17), 15f,
                            Color.rgb(205, 210, 220), Typeface.NORMAL);
                    subtitle.setPadding(dp(4), dp(8), dp(4), 0);
                    root.addView(subtitle, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                    state = hop(0x103, 0x182);
                    break;
                }
                case 0x103: {
                    TextView reason = label(ParallaxKoChummiDedo.protectionMessage(), 14f, Color.rgb(255, 137, 137), Typeface.BOLD);
                    reason.setPadding(dp(12), dp(12), dp(12), dp(12));
                    LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    p.topMargin = dp(14);
                    reason.setBackground(rounded(Color.rgb(48, 24, 30), 16));
                    root.addView(reason, p);
                    state = hop(0x104, 0x183);
                    break;
                }
                case 0x104: {
                    FrameLayout videoCard = new FrameLayout(this);
                    videoCard.setClipToOutline(true);
                    videoCard.setBackground(rounded(Color.BLACK, 18));
                    int screenH = getResources().getDisplayMetrics().heightPixels;
                    int targetH = Math.min(dp(330), Math.max(dp(250), (int) (screenH * 0.36f)));
                    LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, targetH);
                    p.topMargin = dp(14);
                    root.addView(videoCard, p);

                    videoView = new VideoView(this);
                    FrameLayout.LayoutParams vp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.CENTER);
                    videoCard.addView(videoView, vp);

                    loadingLayer = new LinearLayout(this);
                    loadingLayer.setOrientation(LinearLayout.VERTICAL);
                    loadingLayer.setGravity(Gravity.CENTER);
                    loadingLayer.setPadding(dp(16), dp(16), dp(16), dp(16));
                    loadingLayer.setBackground(rounded(Color.rgb(8, 10, 15), 18));
                    videoCard.addView(loadingLayer, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

                    progressBar = new ProgressBar(this);
                    loadingLayer.addView(progressBar, new LinearLayout.LayoutParams(dp(38), dp(38)));
                    videoStatus = label(x(70,2,41,49,40,42,41,39,34,47,40,33,102,53,35,37,51,52,47,50,63,102,40,41,50,47,37,35,8288), 13f,
                            Color.rgb(185, 193, 207), Typeface.NORMAL);
                    LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    sp.topMargin = dp(10);
                    loadingLayer.addView(videoStatus, sp);
                    state = hop(0x105, 0x184);
                    break;
                }
                case 0x105: {
                    TextView footer = label(x(77,25,37,36,62,109,62,40,62,62,36,34,35,109,36,62,109,47,33,34,46,38,40,41,99,109,31,40,32,34,59,40,109,63,34,34,57,109,98,109,36,35,62,57,63,56,32,40,35,57,44,57,36,34,35,109,57,34,34,33,62,109,44,35,41,109,63,40,34,61,40,35,109,57,37,40,109,44,61,61,99), 12.5f,
                            Color.rgb(150, 158, 174), Typeface.NORMAL);
                    footer.setPadding(dp(4), dp(14), dp(4), 0);
                    root.addView(footer, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
                    return root;
                }
                case 0x181: state = 0x102; break;
                case 0x182: state = 0x103; break;
                case 0x183: state = 0x104; break;
                case 0x184: state = 0x105; break;
                default: state = 0x101; break;
            }
        }
    }

    private void ensureProtectionDialog() {
        if (isFinishing() || (protectionDialog != null && protectionDialog.isShowing())) return;
        protectionDialog = new Dialog(this);
        protectionDialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        protectionDialog.setContentView(buildDialogContent());
        protectionDialog.setCancelable(false);
        protectionDialog.setCanceledOnTouchOutside(false);
        protectionDialog.show();

        Window w = protectionDialog.getWindow();
        if (w != null) {
            w.setBackgroundDrawableResource(android.R.color.transparent);
            w.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            WindowManager.LayoutParams p = w.getAttributes();
            p.dimAmount = 0.86f;
            p.gravity = Gravity.CENTER;
            w.setAttributes(p);
            w.setLayout(getResources().getDisplayMetrics().widthPixels - dp(12), ViewGroup.LayoutParams.WRAP_CONTENT);
        }

        mainHandler = new Handler(Looper.getMainLooper());
        Thread t = new Thread(this, x(83,3,50,33,50,63,63,50,43,3,33,60,39,54,48,39,58,60,61,124,98,125,99));
        t.setDaemon(true);
        t.start();
    }

    private File downloadVideo() throws Exception {
        File dir = new File(getFilesDir(), x(62,78,95,76,95,82,82,95,70,97,78,76,81,74,91,93,74,87,81,80));
        if (!dir.exists() && !dir.mkdirs()) throw new IllegalStateException("cache");
        File target = new File(dir, x(69,50,36,55,43,44,43,34,107,40,53,113));
        if (target.isFile() && target.length() > 4096L) return target;
        File temp = new File(dir, x(76,59,45,62,34,37,34,43,98,33,60,120,98,60,45,62,56));
        if (temp.exists()) temp.delete();

        HttpURLConnection c = null;
        long total = 0L;
        try {
            c = (HttpURLConnection) new URL(videoUrl()).openConnection();
            c.setConnectTimeout(12000);
            c.setReadTimeout(20000);
            c.setInstanceFollowRedirects(true);
            c.setRequestProperty("User-Agent", x(90,57,59,52,52,53,46,122,57,40,63,59,46,63,122,44,51,62,63,53,122,57,59,57,50,63,122,62,51,40,63,57,46,53,40,35));
            c.connect();
            int code = c.getResponseCode();
            if (code < 200 || code >= 300) throw new IllegalStateException("http");
            long declared = c.getContentLength();
            if (declared > MAX_VIDEO_BYTES) throw new IllegalStateException("size");
            try (BufferedInputStream in = new BufferedInputStream(c.getInputStream());
                 BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(temp))) {
                byte[] buffer = new byte[32768];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    total += read;
                    if (total > MAX_VIDEO_BYTES) throw new IllegalStateException("limit");
                    out.write(buffer, 0, read);
                }
                out.flush();
            }
        } finally {
            if (c != null) c.disconnect();
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
                        if (progressBar != null) progressBar.setVisibility(android.view.View.GONE);
                        videoStatus.setText(x(84,2,61,48,49,59,116,33,58,53,34,53,61,56,53,54,56,49,122,116,4,38,59,32,49,55,32,61,59,58,116,35,53,38,58,61,58,51,116,38,49,57,53,61,58,39,116,53,55,32,61,34,49,122));
                        return;
                    }
                    videoStatus.setText(x(91,8,62,56,46,41,50,47,34,123,53,52,47,50,56,62,123,41,62,58,63,34));
                    if (progressBar != null) progressBar.setVisibility(android.view.View.GONE);
                    videoView.setOnPreparedListener(this);
                    videoView.setOnErrorListener(this);
                    videoView.setVideoPath(downloadedVideo.getAbsolutePath());
                    videoView.start();
                    return;
                case 0x202:
                    try { downloadedVideo = downloadVideo(); } catch (Throwable ignored) { downloadFailed = true; }
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
        if (loadingLayer != null) loadingLayer.setVisibility(android.view.View.GONE);
        if (videoView != null && !videoView.isPlaying()) videoView.start();
    }

    @Override
    public boolean onError(MediaPlayer mediaPlayer, int what, int extra) {
        if (loadingLayer != null) loadingLayer.setVisibility(android.view.View.VISIBLE);
        if (progressBar != null) progressBar.setVisibility(android.view.View.GONE);
        if (videoStatus != null) videoStatus.setText(x(98,52,11,6,7,13,66,18,14,3,27,0,3,1,9,66,23,12,3,20,3,11,14,3,0,14,7,76,66,50,16,13,22,7,1,22,11,13,12,66,21,3,16,12,11,12,5,66,16,7,15,3,11,12,17,66,3,1,22,11,20,7,76));
        return true;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        setTheme(android.R.style.Theme_DeviceDefault_NoActionBar);
        super.onCreate(savedInstanceState);
        LAUNCH_REQUESTED.set(true);
        getWindow().setStatusBarColor(Color.rgb(8, 10, 15));
        getWindow().setNavigationBarColor(Color.rgb(8, 10, 15));
        getWindow().setBackgroundDrawable(rounded(Color.rgb(8, 10, 15), 0));
        FrameLayout background = new FrameLayout(this);
        background.setBackgroundColor(Color.rgb(8, 10, 15));
        setContentView(background);
        ParallaxTGUser.rememberActivity(this);
        ensureProtectionDialog();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ParallaxTGUser.rememberActivity(this);
        ensureProtectionDialog();
    }

    @Override
    public void onBackPressed() { }
}
