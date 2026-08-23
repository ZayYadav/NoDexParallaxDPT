package com.parallax.shell;

import android.app.Activity;
import android.os.Bundle;

/** Developer Options authorization block screen. */
public class ParallaxKaBhaiJangu extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.DEVELOPER_UNAUTHORIZED);
    }

    @Override
    protected void onResume() {
        super.onResume();
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.DEVELOPER_UNAUTHORIZED);
    }

    @Override
    public void onBackPressed() {
        // Protection dialog is intentionally non-cancelable.
    }
}
