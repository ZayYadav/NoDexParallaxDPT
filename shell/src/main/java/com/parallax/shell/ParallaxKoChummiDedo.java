package com.parallax.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import com.parallax.shell.util.FileUtils;

/** Proxy Application used by the Parallax shell. */
public class ParallaxKoChummiDedo extends Application {
    private static final String TAG = ParallaxKoChummiDedo.class.getSimpleName();
    private String realApplicationName = "";
    private Application realApplication = null;

    private boolean isBlocked() {
        return Global.sProtectionBlockReason != ParallaxBhaiya.CLEAR;
    }

    private void replaceApplication() {
        if (isBlocked()) {
            return;
        }
        if (Global.sNeedCalledApplication && !TextUtils.isEmpty(realApplicationName)) {
            realApplication = (Application) ParallaxJaRaha.ra(realApplicationName);
            Log.d(TAG, "applicationExchange: " + realApplicationName + ", realApplication: " + realApplication.getClass().getName());
            ParallaxJaRaha.craoc(realApplicationName);
            Global.sNeedCalledApplication = false;
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        int reason = ParallaxBhaiya.evaluate(this);
        if (reason != ParallaxBhaiya.CLEAR) {
            if (Build.VERSION.SDK_INT < 28) {
                ParallaxBhaiya.installActivityBlocker(this);
            }
            return;
        }
        Log.d(TAG, "parallax onCreate");
        replaceApplication();
    }

    @Override
    public Context createPackageContext(String packageName, int flags) throws PackageManager.NameNotFoundException {
        if (isBlocked()) {
            return super.createPackageContext(packageName, flags);
        }
        Log.d(TAG, "createPackageContext: " + realApplicationName);
        if (!TextUtils.isEmpty(realApplicationName)) {
            replaceApplication();
            return realApplication;
        }
        return super.createPackageContext(packageName, flags);
    }

    @Override
    public String getPackageName() {
        if (isBlocked()) {
            return super.getPackageName();
        }
        if (!TextUtils.isEmpty(realApplicationName)) {
            return "";
        }
        return super.getPackageName();
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        int reason = ParallaxBhaiya.evaluate(base);
        Log.d(TAG, "parallax attachBaseContext classloader = " + base.getClassLoader());
        if (reason != ParallaxBhaiya.CLEAR) {
            if (Build.VERSION.SDK_INT < 28) {
                ParallaxBhaiya.installActivityBlocker(this);
            }
            return;
        }

        if (!Global.sIsReplacedClassLoader) {
            ApplicationInfo applicationInfo = base.getApplicationInfo();
            if (applicationInfo == null) {
                throw new NullPointerException("application info is null");
            }
            FileUtils.unzipLibs(applicationInfo.sourceDir, applicationInfo.dataDir);
            ParallaxJaRaha.loadShellLibs(applicationInfo.dataDir);

            int nativeReason = ParallaxBhaiya.evaluateNativeAfterLoad();
            if (nativeReason != ParallaxBhaiya.CLEAR) {
                if (Build.VERSION.SDK_INT < 28) {
                    ParallaxBhaiya.installActivityBlocker(this);
                }
                return;
            }

            Log.d(TAG, "ParallaxKoChummiDedo init");
            ParallaxJaRaha.ia();
            ClassLoader targetClassLoader = base.getClassLoader();
            ParallaxJaRaha.cbde(targetClassLoader);
            Global.sIsReplacedClassLoader = true;
        }

        if (!isBlocked()) {
            realApplicationName = ParallaxJaRaha.rapn();
        }
    }
}
