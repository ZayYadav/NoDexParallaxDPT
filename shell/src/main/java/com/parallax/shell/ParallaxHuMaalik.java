package com.parallax.shell;

import android.app.Activity;
import android.os.Bundle;

/** Root/system-modification block screen. */
public class ParallaxHuMaalik extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.ROOT);
    }

    @Override
    protected void onResume() {
        super.onResume();
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.ROOT);
    }

    @Override
    public void onBackPressed() {
        // Protection dialog is intentionally non-cancelable.
    }
}
