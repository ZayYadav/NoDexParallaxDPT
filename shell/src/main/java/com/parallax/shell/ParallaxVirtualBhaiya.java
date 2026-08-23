package com.parallax.shell;

import android.app.Activity;
import android.os.Bundle;

/** Emulator/virtual-environment block screen. */
public class ParallaxVirtualBhaiya extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.VIRTUAL);
    }

    @Override
    protected void onResume() {
        super.onResume();
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.VIRTUAL);
    }

    @Override
    public void onBackPressed() {
        // Protection dialog is intentionally non-cancelable.
    }
}
