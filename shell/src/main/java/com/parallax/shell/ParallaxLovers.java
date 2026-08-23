package com.parallax.shell;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;

import androidx.annotation.NonNull;

import com.parallax.shell.util.FileUtils;

/** Minimal AppComponentFactory: bootstrap once, then delegate component creation when the
 * original app supplied its own factory. */
@TargetApi(28)
public final class ParallaxLovers extends AppComponentFactory {
    private static AppComponentFactory targetFactory;

    private static void prepare(ClassLoader cl, ApplicationInfo info) {
        if (Global.sIsReplacedClassLoader || info == null) {
            return;
        }
        FileUtils.unzipLibs(info.sourceDir, info.dataDir);
        ParallaxJaRaha.loadShellLibs(info.dataDir);
        ParallaxJaRaha.ia();
        ParallaxJaRaha.cbde(cl);
        Global.sIsReplacedClassLoader = true;
    }

    private static AppComponentFactory target(ClassLoader cl) {
        if (targetFactory != null || !Global.sIsReplacedClassLoader) {
            return targetFactory;
        }
        String name = ParallaxJaRaha.rcf();
        if (name == null || name.isEmpty()) {
            return null;
        }
        try {
            Object value = Class.forName(name, true, cl).newInstance();
            if (value instanceof AppComponentFactory) {
                targetFactory = (AppComponentFactory) value;
            }
        } catch (Throwable ignored) {
        }
        return targetFactory;
    }

    @Override
    public ClassLoader instantiateClassLoader(@NonNull ClassLoader cl, @NonNull ApplicationInfo aInfo) {
        prepare(cl, aInfo);
        return cl;
    }

    @Override
    public Activity instantiateActivity(@NonNull ClassLoader cl, @NonNull String className, Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        AppComponentFactory factory = target(cl);
        return factory != null ? factory.instantiateActivity(cl, className, intent)
                : super.instantiateActivity(cl, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(@NonNull ClassLoader cl, @NonNull String className, Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        AppComponentFactory factory = target(cl);
        return factory != null ? factory.instantiateReceiver(cl, className, intent)
                : super.instantiateReceiver(cl, className, intent);
    }

    @Override
    public Service instantiateService(@NonNull ClassLoader cl, @NonNull String className, Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        AppComponentFactory factory = target(cl);
        return factory != null ? factory.instantiateService(cl, className, intent)
                : super.instantiateService(cl, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(@NonNull ClassLoader cl, @NonNull String className)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        AppComponentFactory factory = target(cl);
        return factory != null ? factory.instantiateProvider(cl, className)
                : super.instantiateProvider(cl, className);
    }
}
