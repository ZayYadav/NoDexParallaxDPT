package com.parallax.shell;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.SystemClock;

import java.lang.ref.WeakReference;

/**
 * Stable framework ABI used by the protected manifest.
 *
 * This class deliberately has its final release name at source level instead of depending
 * on R8 to rename a framework-instantiated component. The packer's package-rewrite pass
 * can still move it from com.parallax.shell to the configured shell package while keeping
 * the Parallax2 basename stable.
 */
public class Parallax2 extends AppComponentFactory {
    private static volatile WeakReference<Activity> lastActivity = new WeakReference<>(null);
    private static volatile int FLOW = 0x13579BDF;
    private volatile AppComponentFactory originalFactory;
    private volatile String originalFactoryName;

    static void rememberActivity(Activity activity) {
        if (activity != null) lastActivity = new WeakReference<>(activity);
    }

    static Activity peekActivity() {
        WeakReference<Activity> ref = lastActivity;
        return ref == null ? null : ref.get();
    }

    private static int hop(int real, int decoy) {
        int n = FLOW ^ (int) SystemClock.elapsedRealtimeNanos();
        FLOW = Integer.rotateLeft(n ^ 0x6D2B79F5, 11) + 0x7F4A7C15;
        return (n & 1) == 0 ? real : decoy;
    }

    private AppComponentFactory resolveOriginalFactory(ClassLoader classLoader) {
        int state = 0x11;
        String name = null;
        for (;;) {
            switch (state) {
                case 0x11:
                    name = ParallaxKiSettingKarwaDo.getRealComponentFactoryName();
                    state = hop(0x22, 0x71);
                    break;
                case 0x22:
                    if (name == null || name.isEmpty()
                            || "android.app.AppComponentFactory".equals(name)
                            || Parallax2.class.getName().equals(name)) return null;
                    state = hop(0x33, 0x72);
                    break;
                case 0x33: {
                    AppComponentFactory cached = originalFactory;
                    if (cached != null && name.equals(originalFactoryName)) return cached;
                    state = hop(0x44, 0x73);
                    break;
                }
                case 0x44:
                    try {
                        Class<?> type = Class.forName(name, true, classLoader);
                        Object candidate = type.getDeclaredConstructor().newInstance();
                        if (candidate instanceof AppComponentFactory) {
                            originalFactory = (AppComponentFactory) candidate;
                            originalFactoryName = name;
                            return originalFactory;
                        }
                    } catch (Throwable ignored) { }
                    return null;
                case 0x71: state = 0x22; break;
                case 0x72: state = 0x33; break;
                case 0x73: state = 0x44; break;
                default: return null;
            }
        }
    }

    private static String resolveApplicationName(ClassLoader classLoader) {
        String name = ParallaxKiSettingKarwaDo.getRealApplicationName();
        if (name == null || name.isEmpty()) return null;

        String packageName = ParallaxKiSettingKarwaDo.getApplicationPackageName();
        if (name.startsWith(".") && packageName != null && !packageName.isEmpty()) {
            return packageName + name;
        }

        try {
            Class.forName(name, false, classLoader);
            return name;
        } catch (ClassNotFoundException ignored) {
            if (name.indexOf('.') < 0 && packageName != null && !packageName.isEmpty()) {
                return packageName + "." + name;
            }
            return name;
        }
    }

    @Override
    public ClassLoader instantiateClassLoader(ClassLoader cl, ApplicationInfo aInfo) {
        ParallaxKiSettingKarwaDo.prepareClassLoader(cl, aInfo);
        return cl;
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        int state = ParallaxKiSettingKarwaDo.isProtectionBlocked() ? hop(0x91, 0xB1) : hop(0x92, 0xB2);
        for (;;) {
            switch (state) {
                case 0x91: {
                    Activity activity = new Parallax();
                    rememberActivity(activity);
                    return activity;
                }
                case 0x92: {
                    AppComponentFactory delegate = resolveOriginalFactory(cl);
                    Activity activity = delegate != null
                            ? delegate.instantiateActivity(cl, className, intent)
                            : super.instantiateActivity(cl, className, intent);
                    rememberActivity(activity);
                    return activity;
                }
                case 0xB1: state = 0x91; break;
                case 0xB2: state = 0x92; break;
                default: state = 0x92; break;
            }
        }
    }

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ParallaxKiSettingKarwaDo.isProtectionBlocked()) {
            return super.instantiateApplication(cl, className);
        }

        String applicationName = resolveApplicationName(cl);
        if (applicationName == null || applicationName.isEmpty()) {
            return super.instantiateApplication(cl, className);
        }

        AppComponentFactory delegate = resolveOriginalFactory(cl);
        if (delegate != null) {
            try {
                return delegate.instantiateApplication(cl, applicationName);
            } catch (Exception ignored) {
                // Preserve platform fallback when an app-specific component factory fails.
            }
        }
        return super.instantiateApplication(cl, applicationName);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ParallaxKiSettingKarwaDo.isProtectionBlocked()) return new ParallaxHu();
        AppComponentFactory delegate = resolveOriginalFactory(cl);
        return delegate != null ? delegate.instantiateProvider(cl, className)
                : super.instantiateProvider(cl, className);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ParallaxKiSettingKarwaDo.isProtectionBlocked()) return new ParallaxKiShadiKarwaDo();
        AppComponentFactory delegate = resolveOriginalFactory(cl);
        return delegate != null ? delegate.instantiateReceiver(cl, className, intent)
                : super.instantiateReceiver(cl, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ParallaxKiSettingKarwaDo.isProtectionBlocked()) return new JangamMeraBhaiHai();
        AppComponentFactory delegate = resolveOriginalFactory(cl);
        return delegate != null ? delegate.instantiateService(cl, className, intent)
                : super.instantiateService(cl, className, intent);
    }
}
