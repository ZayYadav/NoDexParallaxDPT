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

public class Parallax2 extends AppComponentFactory {
    private static volatile WeakReference<Activity> lastActivity = new WeakReference<>(null);
    private static volatile int FLOW = 0x13579BDF;
    private volatile AppComponentFactory originalFactory;
    private volatile String originalFactoryName;
    static void rememberActivity(Activity activity){if(activity!=null)lastActivity=new WeakReference<>(activity);} static Activity peekActivity(){WeakReference<Activity> r=lastActivity;return r==null?null:r.get();}
    private static int hop(int real,int decoy){int n=FLOW^(int)SystemClock.elapsedRealtimeNanos();FLOW=Integer.rotateLeft(n^0x6D2B79F5,11)+0x7F4A7C15;return(n&1)==0?real:decoy;}
    private AppComponentFactory resolveOriginalFactory(ClassLoader cl){int s=0x11;String n=null;for(;;)switch(s){case 0x11:n=ParallaxKiSettingKarwaDo.getRealComponentFactoryName();s=hop(0x22,0x71);break;case 0x22:if(n==null||n.isEmpty()||"android.app.AppComponentFactory".equals(n)||Parallax2.class.getName().equals(n))return null;s=hop(0x33,0x72);break;case 0x33:{AppComponentFactory c=originalFactory;if(c!=null&&n.equals(originalFactoryName))return c;s=hop(0x44,0x73);break;}case 0x44:try{Class<?>t=Class.forName(n,true,cl);Object c=t.getDeclaredConstructor().newInstance();if(c instanceof AppComponentFactory){originalFactory=(AppComponentFactory)c;originalFactoryName=n;return originalFactory;}}catch(Throwable ignored){}return null;case 0x71:s=0x22;break;case 0x72:s=0x33;break;case 0x73:s=0x44;break;default:return null;}}
    private static String resolveApplicationName(ClassLoader cl){String n=ParallaxKiSettingKarwaDo.getRealApplicationName();if(n==null||n.isEmpty())return null;String p=ParallaxKiSettingKarwaDo.getApplicationPackageName();if(n.startsWith(".")&&p!=null&&!p.isEmpty())return p+n;try{Class.forName(n,false,cl);return n;}catch(ClassNotFoundException ignored){if(n.indexOf('.')<0&&p!=null&&!p.isEmpty())return p+"."+n;return n;}}
    @Override public ClassLoader instantiateClassLoader(ClassLoader cl,ApplicationInfo info){ParallaxKiSettingKarwaDo.prepareClassLoader(cl,info);return cl;}
    @Override public Activity instantiateActivity(ClassLoader cl,String name,Intent intent)throws InstantiationException,IllegalAccessException,ClassNotFoundException{int s=ParallaxKiSettingKarwaDo.isProtectionBlocked()?hop(0x91,0xB1):hop(0x92,0xB2);for(;;)switch(s){case 0x91:{Activity a=new Parallax();rememberActivity(a);return a;}case 0x92:{AppComponentFactory d=resolveOriginalFactory(cl);Activity a=d!=null?d.instantiateActivity(cl,name,intent):super.instantiateActivity(cl,name,intent);rememberActivity(a);return a;}case 0xB1:s=0x91;break;case 0xB2:s=0x92;break;default:s=0x92;}}
    @Override public Application instantiateApplication(ClassLoader cl,String name)throws InstantiationException,IllegalAccessException,ClassNotFoundException{if(ParallaxKiSettingKarwaDo.isProtectionBlocked())return super.instantiateApplication(cl,name);String app=resolveApplicationName(cl);if(app==null||app.isEmpty())return super.instantiateApplication(cl,name);AppComponentFactory d=resolveOriginalFactory(cl);if(d!=null)try{return d.instantiateApplication(cl,app);}catch(Exception ignored){}return super.instantiateApplication(cl,app);}
    @Override public ContentProvider instantiateProvider(ClassLoader cl,String name)throws InstantiationException,IllegalAccessException,ClassNotFoundException{if(ParallaxKiSettingKarwaDo.isProtectionBlocked())return new ParallaxHu();AppComponentFactory d=resolveOriginalFactory(cl);return d!=null?d.instantiateProvider(cl,name):super.instantiateProvider(cl,name);}
    @Override public BroadcastReceiver instantiateReceiver(ClassLoader cl,String name,Intent i)throws InstantiationException,IllegalAccessException,ClassNotFoundException{if(ParallaxKiSettingKarwaDo.isProtectionBlocked())return new ParallaxKiShadiKarwaDo();AppComponentFactory d=resolveOriginalFactory(cl);return d!=null?d.instantiateReceiver(cl,name,i):super.instantiateReceiver(cl,name,i);}
    @Override public Service instantiateService(ClassLoader cl,String name,Intent i)throws InstantiationException,IllegalAccessException,ClassNotFoundException{if(ParallaxKiSettingKarwaDo.isProtectionBlocked())return new JangamMeraBhaiHai();AppComponentFactory d=resolveOriginalFactory(cl);return d!=null?d.instantiateService(cl,name,i):super.instantiateService(cl,name,i);}
}
