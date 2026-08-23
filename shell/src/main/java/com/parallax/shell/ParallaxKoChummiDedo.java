package com.parallax.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import com.parallax.shell.util.FileUtils;

/** Minimal proxy Application used only to bootstrap the existing native runtime. */
public final class ParallaxKoChummiDedo extends Application {
    private String realApplicationName = "";
    private Application realApplication;

    private void prepare(Context base) {
        if (!Global.sIsReplacedClassLoader) {
            ApplicationInfo info = base.getApplicationInfo();
            if (info == null) {
                throw new IllegalStateException("application info is null");
            }
            FileUtils.unzipLibs(info.sourceDir, info.dataDir);
            ParallaxJaRaha.loadShellLibs(info.dataDir);
            ParallaxJaRaha.ia();
            ParallaxJaRaha.cbde(base.getClassLoader());
            Global.sIsReplacedClassLoader = true;
        }
        realApplicationName = ParallaxJaRaha.rapn();
    }

    private void replaceApplication() {
        if (!Global.sNeedCalledApplication || realApplicationName == null || realApplicationName.isEmpty()) {
            return;
        }
        Object app = ParallaxJaRaha.ra(realApplicationName);
        if (app instanceof Application) {
            realApplication = (Application) app;
            ParallaxJaRaha.craoc(realApplicationName);
            Global.sNeedCalledApplication = false;
        }
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        prepare(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        replaceApplication();
    }

    @Override
    public Context createPackageContext(String packageName, int flags) throws PackageManager.NameNotFoundException {
        if (realApplicationName != null && !realApplicationName.isEmpty()) {
            replaceApplication();
            if (realApplication != null) {
                return realApplication;
            }
        }
        return super.createPackageContext(packageName, flags);
    }

    @Override
    public String getPackageName() {
        if (realApplicationName != null && !realApplicationName.isEmpty()) {
            return "";
        }
        return super.getPackageName();
    }
}
