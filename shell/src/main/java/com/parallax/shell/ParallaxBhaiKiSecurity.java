package com.parallax.shell;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;

/** Generic debugger/tamper block screen with fail-closed app-process quarantine. */
public class ParallaxBhaiKiSecurity extends Activity {
    // Give the user enough time to read and acknowledge the incompatibility dialog.
    // If they leave it open, the protected app still fail-closes automatically.
    private static final long QUARANTINE_DELAY_MS = 15_000L;

    private final Handler quarantineHandler = new Handler(Looper.getMainLooper());
    private final Runnable quarantine = new Runnable() {
        @Override
        public void run() {
            try {
                finishAndRemoveTask();
            } catch (Throwable ignored) {
                try {
                    finish();
                } catch (Throwable ignoredAgain) {
                }
            }

            // Defensive response only: terminate this protected app process. Never write
            // junk data, fill storage/RAM, heat the device, damage hardware, or touch
            // other apps/processes.
            Process.killProcess(Process.myPid());
            System.exit(173);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.DEBUG_OR_TAMPER);
        armQuarantine();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.DEBUG_OR_TAMPER);
        armQuarantine();
    }

    private void armQuarantine() {
        quarantineHandler.removeCallbacks(quarantine);
        quarantineHandler.postDelayed(quarantine, QUARANTINE_DELAY_MS);
    }

    @Override
    protected void onDestroy() {
        quarantineHandler.removeCallbacks(quarantine);
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        // Protection dialog is intentionally non-cancelable; quarantine remains armed.
    }
}
