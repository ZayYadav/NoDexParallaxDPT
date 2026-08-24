package com.parallax.shell;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public final class ParallaxBlockedReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // Blocked runtime: intentionally do not dispatch into protected application code.
    }
}
