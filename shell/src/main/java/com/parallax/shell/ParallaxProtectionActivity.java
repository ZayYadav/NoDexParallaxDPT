package com.parallax.shell;

import android.app.Activity;
import android.app.Dialog;
import android.content.ComponentName;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.media.MediaPlayer;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
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

public final class ParallaxProtectionActivity extends Activity
        implements Runnable, MediaPlayer.OnPreparedListener, MediaPlayer.OnErrorListener {

    private static final String VIDEO_URL =
            "https://github.com/sk8787914-maker/Zoro-online-mod/raw/refs/heads/main/VID_20260822_235111_206.mp4";
    private static final long MAX_VIDEO_BYTES = 128L * 1024L * 1024L;
    private static final AtomicBoolean LAUNCH_REQUESTED = new AtomicBoolean(false);

    private Dialog protectionDialog;
    private VideoView videoView;
    private ProgressBar progressBar;
    private TextView videoStatus;
    private File downloadedVideo;
    private Handler mainHandler;
    private volatile boolean downloadFailed;

    static void request(Activity activity) {
        if (activity == null || activity.isFinishing()) {
            return;
        }
        if (activity instanceof ParallaxProtectionActivity) {
            ((ParallaxProtectionActivity) activity).ensureProtectionDialog();
            return;
        }
        if (!LAUNCH_REQUESTED.compareAndSet(false, true)) {
            return;
        }
        try {
            // Re-launch an already-declared host component. Once protection is latched,
            // the component factory substitutes this warning Activity before the locked
            // protected class is resolved.
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
        int pad = dp(20);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(pad, pad, pad, pad);
        root.setBackground(rounded(Color.rgb(16, 19, 28), 24));

        TextView badge = label("⚠  PARALLAX SECURITY WARNING", 12f,
                Color.rgb(255, 189, 89), Typeface.BOLD);
        badge.setPadding(dp(12), dp(7), dp(12), dp(7));
        badge.setBackground(rounded(Color.rgb(48, 39, 24), 30));
        root.addView(badge, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        Space topGap = new Space(this);
        root.addView(topGap, new LinearLayout.LayoutParams(1, dp(14)));

        TextView title = label("Parallax Protection", 25f, Color.WHITE, Typeface.BOLD);
        root.addView(title, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView subtitle = label(
                "Unsafe runtime environment detected. Protected code has not been loaded.",
                15f, Color.rgb(205, 210, 220), Typeface.NORMAL);
        subtitle.setPadding(dp(4), dp(8), dp(4), 0);
        root.addView(subtitle, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView reason = label(ParallaxKoChummiDedo.protectionMessage(), 14f,
                Color.rgb(255, 137, 137), Typeface.BOLD);
        reason.setPadding(dp(12), dp(12), dp(12), dp(12));
        LinearLayout.LayoutParams reasonParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        reasonParams.topMargin = dp(14);
        reason.setBackground(rounded(Color.rgb(48, 24, 30), 16));
        root.addView(reason, reasonParams);

        FrameLayout videoCard = new FrameLayout(this);
        videoCard.setBackground(rounded(Color.BLACK, 18));
        LinearLayout.LayoutParams videoCardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(220));
        videoCardParams.topMargin = dp(16);
        root.addView(videoCard, videoCardParams);

        videoView = new VideoView(this);
        videoCard.addView(videoView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout loadingLayer = new LinearLayout(this);
        loadingLayer.setOrientation(LinearLayout.VERTICAL);
        loadingLayer.setGravity(Gravity.CENTER);
        loadingLayer.setPadding(dp(16), dp(16), dp(16), dp(16));
        loadingLayer.setBackground(rounded(Color.rgb(8, 10, 15), 18));
        videoCard.addView(loadingLayer, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        progressBar = new ProgressBar(this);
        loadingLayer.addView(progressBar, new LinearLayout.LayoutParams(dp(38), dp(38)));

        videoStatus = label("Downloading security notice…", 13f,
                Color.rgb(185, 193, 207), Typeface.NORMAL);
        LinearLayout.LayoutParams statusParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        statusParams.topMargin = dp(10);
        loadingLayer.addView(videoStatus, statusParams);

        TextView footer = label(
                "This session is blocked. Remove root / instrumentation tools and reopen the app.",
                12.5f, Color.rgb(150, 158, 174), Typeface.NORMAL);
        footer.setPadding(dp(4), dp(16), dp(4), 0);
        root.addView(footer, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        return root;
    }

    private void ensureProtectionDialog() {
        if (isFinishing() || (protectionDialog != null && protectionDialog.isShowing())) {
            return;
        }

        protectionDialog = new Dialog(this);
        protectionDialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        protectionDialog.setContentView(buildDialogContent());
        protectionDialog.setCancelable(false);
        protectionDialog.setCanceledOnTouchOutside(false);
        protectionDialog.show();

        Window dialogWindow = protectionDialog.getWindow();
        if (dialogWindow != null) {
            dialogWindow.setBackgroundDrawableResource(android.R.color.transparent);
            dialogWindow.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND
                    | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            WindowManager.LayoutParams params = dialogWindow.getAttributes();
            params.dimAmount = 0.82f;
            params.gravity = Gravity.CENTER;
            dialogWindow.setAttributes(params);
            int width = Math.min(getResources().getDisplayMetrics().widthPixels - dp(24), dp(520));
            dialogWindow.setLayout(width, ViewGroup.LayoutParams.WRAP_CONTENT);
        }

        mainHandler = new Handler(Looper.getMainLooper());
        Thread downloader = new Thread(this, "ParallaxProtectionVideo");
        downloader.setDaemon(true);
        downloader.start();
    }

    private File downloadVideo() throws Exception {
        File dir = new File(getFilesDir(), "parallax_protection");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IllegalStateException("cannot create video cache directory");
        }
        File target = new File(dir, "warning.mp4");
        if (target.isFile() && target.length() > 4096L) {
            return target;
        }

        File temp = new File(dir, "warning.mp4.part");
        if (temp.exists()) {
            temp.delete();
        }

        HttpURLConnection connection = null;
        long total = 0L;
        try {
            URL url = new URL(VIDEO_URL);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(12000);
            connection.setReadTimeout(20000);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("User-Agent", "ParallaxProtection/1.0");
            connection.connect();

            int code = connection.getResponseCode();
            if (code < 200 || code >= 300) {
                throw new IllegalStateException("video HTTP " + code);
            }
            long declared = connection.getContentLength();
            if (declared > MAX_VIDEO_BYTES) {
                throw new IllegalStateException("video is too large");
            }

            try (BufferedInputStream input = new BufferedInputStream(connection.getInputStream());
                 BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream(temp))) {
                byte[] buffer = new byte[32768];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    total += read;
                    if (total > MAX_VIDEO_BYTES) {
                        throw new IllegalStateException("video exceeded size limit");
                    }
                    output.write(buffer, 0, read);
                }
                output.flush();
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        if (total <= 4096L) {
            temp.delete();
            throw new IllegalStateException("downloaded video is empty");
        }
        if (target.exists()) {
            target.delete();
        }
        if (!temp.renameTo(target)) {
            throw new IllegalStateException("cannot finalize downloaded video");
        }
        return target;
    }

    @Override
    public void run() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            if (videoView == null || videoStatus == null) {
                return;
            }
            if (downloadFailed || downloadedVideo == null) {
                if (progressBar != null) {
                    progressBar.setVisibility(android.view.View.GONE);
                }
                videoStatus.setText("Video unavailable. Protection warning remains active.");
                return;
            }
            videoStatus.setText("Security notice ready");
            if (progressBar != null) {
                progressBar.setVisibility(android.view.View.GONE);
            }
            videoView.setOnPreparedListener(this);
            videoView.setOnErrorListener(this);
            videoView.setVideoPath(downloadedVideo.getAbsolutePath());
            videoView.start();
            return;
        }

        try {
            downloadedVideo = downloadVideo();
        } catch (Throwable error) {
            downloadFailed = true;
        }
        if (mainHandler != null) {
            mainHandler.post(this);
        }
    }

    @Override
    public void onPrepared(MediaPlayer mediaPlayer) {
        mediaPlayer.setLooping(true);
        mediaPlayer.setVolume(1.0f, 1.0f);
        if (videoView != null && !videoView.isPlaying()) {
            videoView.start();
        }
    }

    @Override
    public boolean onError(MediaPlayer mediaPlayer, int what, int extra) {
        if (progressBar != null) {
            progressBar.setVisibility(android.view.View.GONE);
        }
        if (videoStatus != null) {
            videoStatus.setText("Video playback unavailable. Protection warning remains active.");
        }
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
        ParallaxProtectionFactory.rememberActivity(this);
        ensureProtectionDialog();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ParallaxProtectionFactory.rememberActivity(this);
        ensureProtectionDialog();
    }

    @Override
    public void onBackPressed() {
        // Intentionally blocked: protection warning is non-cancelable.
    }
}
