package com.parallax.parallax;

import android.app.Application;
import android.content.Context;
import android.util.Log;

public class ThisApplication extends Application {
    private static final String TAG = ThisApplication.class.getSimpleName();
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG,"parallax onCreate");
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        Log.d(TAG,"parallax attachBaseContext");
    }
}
