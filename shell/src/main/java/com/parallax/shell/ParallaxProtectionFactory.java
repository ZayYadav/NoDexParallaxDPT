package com.parallax.shell;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;

import java.lang.ref.WeakReference;

public final class ParallaxProtectionFactory extends AppComponentFactory {
    private static volatile WeakReference<Activity> lastActivity = new WeakReference<>(null);
    private volatile AppComponentFactory originalFactory;
    private volatile String originalFactoryName;

    static void rememberActivity(Activity activity) {
        if (activity != null) {
            lastActivity = new WeakReference<>(activity);
        }
    }

    static Activity peekActivity() {
        WeakReference<Activity> ref = lastActivity;
        return ref == null ? null : ref.get();
    }

    private AppComponentFactory resolveOriginalFactory(ClassLoader classLoader) {
        String name = ParallaxKoChummiDedo.getRealComponentFactoryName();
        if (name == null || name.isEmpty()
                || "android.app.AppComponentFactory".equals(name)
                || ParallaxProtectionFactory.class.getName().equals(name)) {
            return null;
        }

        AppComponentFactory cached = originalFactory;
        if (cached != null && name.equals(originalFactoryName)) {
            return cached;
        }

        try {
            Class<?> type = Class.forName(name, true, classLoader);
            Object candidate = type.getDeclaredConstructor().newInstance();
            if (candidate instanceof AppComponentFactory) {
                originalFactory = (AppComponentFactory) candidate;
                originalFactoryName = name;
                return originalFactory;
            }
        } catch (Throwable ignored) {
            // Fall back to the platform factory. Protection must not crash the host app
            // because an optional original factory cannot be reconstructed.
        }
        return null;
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ParallaxKoChummiDedo.isProtectionBlocked()) {
            Activity activity = new ParallaxProtectionActivity();
            rememberActivity(activity);
            return activity;
        }
        AppComponentFactory delegate = resolveOriginalFactory(cl);
        Activity activity = delegate != null
                ? delegate.instantiateActivity(cl, className, intent)
                : super.instantiateActivity(cl, className, intent);
        rememberActivity(activity);
        return activity;
    }

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        // The manifest intentionally points to the Parallax bootstrap Application.
        return super.instantiateApplication(cl, className);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ParallaxKoChummiDedo.isProtectionBlocked()) {
            return new ParallaxBlockedProvider();
        }
        AppComponentFactory delegate = resolveOriginalFactory(cl);
        return delegate != null
                ? delegate.instantiateProvider(cl, className)
                : super.instantiateProvider(cl, className);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ParallaxKoChummiDedo.isProtectionBlocked()) {
            return new ParallaxBlockedReceiver();
        }
        AppComponentFactory delegate = resolveOriginalFactory(cl);
        return delegate != null
                ? delegate.instantiateReceiver(cl, className, intent)
                : super.instantiateReceiver(cl, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ParallaxKoChummiDedo.isProtectionBlocked()) {
            return new ParallaxBlockedService();
        }
        AppComponentFactory delegate = resolveOriginalFactory(cl);
        return delegate != null
                ? delegate.instantiateService(cl, className, intent)
                : super.instantiateService(cl, className, intent);
    }
}
