package com.parallax.shell;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.IBinder;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.NonNull;

import com.parallax.shell.util.EnvUtils;
import com.parallax.shell.util.FileUtils;

import java.lang.reflect.Method;

@TargetApi(28)
public class ParallaxLovers extends AppComponentFactory {
    private static final String TAG = "parallax " + ParallaxLovers.class.getSimpleName();
    private static AppComponentFactory sAppComponentFactory;

    private static int blockReason() {
        return ParallaxBhaiya.evaluateEarly();
    }

    private String getTargetClassName() {
        return ParallaxJaRaha.rcf();
    }

    private AppComponentFactory getTargetAppComponentFactory(ClassLoader appClassLoader) {
        if (sAppComponentFactory == null) {
            String targetClassName = getTargetClassName();
            Log.d(TAG, "targetClassName = " + targetClassName);
            if (!TextUtils.isEmpty(targetClassName)) {
                try {
                    sAppComponentFactory = (AppComponentFactory) Class.forName(targetClassName, true, appClassLoader).newInstance();
                    return sAppComponentFactory;
                } catch (Exception ignored) {
                }
            }
        }
        return sAppComponentFactory;
    }

    @Override
    public Activity instantiateActivity(@NonNull ClassLoader cl, @NonNull String className, Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        int reason = Global.sProtectionBlockReason;
        if (reason == ParallaxBhaiya.CLEAR) {
            reason = blockReason();
        }
        if (reason != ParallaxBhaiya.CLEAR) {
            return ParallaxBhaiya.newBlockedActivity(reason);
        }
        Log.d(TAG, "instantiateActivity() called with: cl = [" + cl + "], className = [" + className + "], intent = [" + intent + "]");
        AppComponentFactory targetAppComponentFactory = getTargetAppComponentFactory(cl);
        if (targetAppComponentFactory != null) {
            try {
                Method method = AppComponentFactory.class.getDeclaredMethod("instantiateActivity", ClassLoader.class, String.class, Intent.class);
                return (Activity) method.invoke(targetAppComponentFactory, cl, className, intent);
            } catch (Exception ignored) {
            }
        }
        return super.instantiateActivity(cl, className, intent);
    }

    @Override
    public Application instantiateApplication(@NonNull ClassLoader cl, @NonNull String className)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        int reason = blockReason();
        if (reason != ParallaxBhaiya.CLEAR) {
            return super.instantiateApplication(cl, className);
        }
        Log.d(TAG, "instantiateApplication() called with: cl = [" + cl + "], className = [" + className + "]");
        if (!Global.sIsReplacedClassLoader) {
            if (EnvUtils.getApplicationInfo() == null) {
                throw new NullPointerException("application info is null");
            }
            String dataDir = EnvUtils.getApplicationInfo().dataDir;
            String sourceDir = EnvUtils.getApplicationInfo().sourceDir;
            FileUtils.unzipLibs(sourceDir, dataDir);
            ParallaxJaRaha.loadShellLibs(dataDir);
            reason = ParallaxBhaiya.evaluateNativeAfterLoad();
            if (reason != ParallaxBhaiya.CLEAR) {
                return super.instantiateApplication(cl, className);
            }
        }
        ParallaxJaRaha.ia();

        String applicationName = ParallaxJaRaha.rapn();
        AppComponentFactory targetAppComponentFactory;
        if (!Global.sIsReplacedClassLoader) {
            ParallaxJaRaha.cbde(cl);
            Global.sIsReplacedClassLoader = true;
            targetAppComponentFactory = getTargetAppComponentFactory(cl);
        } else {
            targetAppComponentFactory = getTargetAppComponentFactory(cl);
        }

        Global.sNeedCalledApplication = false;

        if (targetAppComponentFactory != null) {
            try {
                Method method = targetAppComponentFactory.getClass().getDeclaredMethod("instantiateApplication", ClassLoader.class, String.class);
                if (!TextUtils.isEmpty(applicationName)) {
                    return (Application) method.invoke(targetAppComponentFactory, cl, applicationName);
                }
                return (Application) method.invoke(targetAppComponentFactory, cl, className);
            } catch (Exception e) {
                Log.e(TAG, "instantiateApplication", e);
            }
        }

        if (!TextUtils.isEmpty(applicationName)) {
            try {
                Class.forName(applicationName, false, cl);
            } catch (ClassNotFoundException e) {
                if (EnvUtils.getApplicationInfo() != null) {
                    applicationName = EnvUtils.getApplicationInfo().packageName + "." + applicationName;
                }
            }
            return super.instantiateApplication(cl, applicationName);
        }
        return super.instantiateApplication(cl, className);
    }

    @Override
    public ClassLoader instantiateClassLoader(@NonNull ClassLoader cl, @NonNull ApplicationInfo aInfo) {
        int reason = blockReason();
        if (reason != ParallaxBhaiya.CLEAR) {
            return cl;
        }
        Log.d(TAG, "instantiateClassLoader() called with: cl = [" + cl + "], aInfo = [" + aInfo + "]");
        FileUtils.unzipLibs(aInfo.sourceDir, aInfo.dataDir);
        ParallaxJaRaha.loadShellLibs(aInfo.dataDir);
        reason = ParallaxBhaiya.evaluateNativeAfterLoad();
        if (reason != ParallaxBhaiya.CLEAR) {
            return cl;
        }
        ParallaxJaRaha.ia();

        AppComponentFactory targetAppComponentFactory = getTargetAppComponentFactory(cl);
        ParallaxJaRaha.cbde(cl);
        Global.sIsReplacedClassLoader = true;

        if (targetAppComponentFactory != null) {
            try {
                Method method = AppComponentFactory.class.getDeclaredMethod("instantiateClassLoader", ClassLoader.class, ApplicationInfo.class);
                return (ClassLoader) method.invoke(targetAppComponentFactory, cl, aInfo);
            } catch (Exception ignored) {
            }
        }
        return super.instantiateClassLoader(cl, aInfo);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(@NonNull ClassLoader cl, @NonNull String className, Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        if (blockReason() != ParallaxBhaiya.CLEAR) {
            return new ParallaxBhaiReceiver();
        }
        AppComponentFactory targetAppComponentFactory = getTargetAppComponentFactory(cl);
        if (targetAppComponentFactory != null) {
            try {
                Method method = AppComponentFactory.class.getDeclaredMethod("instantiateReceiver", ClassLoader.class, String.class, Intent.class);
                return (BroadcastReceiver) method.invoke(targetAppComponentFactory, cl, className, intent);
            } catch (Exception ignored) {
            }
        }
        return super.instantiateReceiver(cl, className, intent);
    }

    @Override
    public Service instantiateService(@NonNull ClassLoader cl, @NonNull String className, Intent intent)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        if (blockReason() != ParallaxBhaiya.CLEAR) {
            return new ParallaxBhaiService();
        }
        AppComponentFactory targetAppComponentFactory = getTargetAppComponentFactory(cl);
        if (targetAppComponentFactory != null) {
            try {
                Method method = AppComponentFactory.class.getDeclaredMethod("instantiateService", ClassLoader.class, String.class, Intent.class);
                return (Service) method.invoke(targetAppComponentFactory, cl, className, intent);
            } catch (Exception ignored) {
            }
        }
        return super.instantiateService(cl, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(@NonNull ClassLoader cl, @NonNull String className)
            throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        if (blockReason() != ParallaxBhaiya.CLEAR) {
            return new ParallaxBhaiProvider();
        }
        AppComponentFactory targetAppComponentFactory = getTargetAppComponentFactory(cl);
        if (targetAppComponentFactory != null) {
            try {
                Method method = AppComponentFactory.class.getDeclaredMethod("instantiateProvider", ClassLoader.class, String.class);
                return (ContentProvider) method.invoke(targetAppComponentFactory, cl, className);
            } catch (Exception ignored) {
            }
        }
        return super.instantiateProvider(cl, className);
    }

    public static final class ParallaxBhaiReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
        }
    }

    public static final class ParallaxBhaiService extends Service {
        @Override
        public IBinder onBind(Intent intent) {
            return null;
        }

        @Override
        public int onStartCommand(Intent intent, int flags, int startId) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
    }

    public static final class ParallaxBhaiProvider extends ContentProvider {
        @Override
        public boolean onCreate() {
            return true;
        }

        @Override
        public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
            return null;
        }

        @Override
        public String getType(Uri uri) {
            return null;
        }

        @Override
        public Uri insert(Uri uri, ContentValues values) {
            return null;
        }

        @Override
        public int delete(Uri uri, String selection, String[] selectionArgs) {
            return 0;
        }

        @Override
        public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
            return 0;
        }
    }
}
