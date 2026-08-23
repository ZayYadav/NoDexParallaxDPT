package com.parallax.shell;

import android.app.Activity;
import android.os.Bundle;

/** Generic debugger/tamper block screen. */
public class ParallaxBhaiKiSecurity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.DEBUG_OR_TAMPER);
    }

    @Override
    protected void onResume() {
        super.onResume();
        ParallaxBhaiya.showProtectionDialog(this, ParallaxBhaiya.DEBUG_OR_TAMPER);
    }

    @Override
    public void onBackPressed() {
        // Protection dialog is intentionally non-cancelable.
    }
}
