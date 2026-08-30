package com.parallax.parallax.res;

import com.parallax.parallax.util.IoUtils;
import com.wind.meditor.core.FileProcesser;
import com.wind.meditor.property.AttributeItem;
import com.wind.meditor.property.ModificationProperty;
import com.wind.meditor.utils.NodeValue;

import pxb.android.axml.AxmlParser;

/**
 * @author parallax
 */
public class ApkManifestEditor {
    /**
     * Write the exact release bootstrap Application name supplied by Apk.
     *
     * The shell release build uses a deterministic R8 mapping:
     *   com.parallax.shell.ParallaxKiSettingKarwaDo -> Parallax.Enc.Parallax1
     *
     * Do not rewrite the class basename here. Doing so makes the protected manifest
     * reference a class that is not present in the release shell dex and Android fails
     * before Application.attachBaseContext() with ClassNotFoundException.
     */
    public static void writeApplicationName(String inManifestFile, String outManifestFile, String newApplicationName){
        ModificationProperty property = new ModificationProperty();
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.NAME,newApplicationName));
        property.addUsesPermission("android.permission.INTERNET");
        FileProcesser.processManifestFile(inManifestFile, outManifestFile, property);
    }

    /**
     * Write the exact release AppComponentFactory name supplied by Apk.
     * Parallax2 is the framework-visible release ABI and must stay in sync with
     * stub-obfuscation.map / Const.KEY_COMPONENT_FACTORY_BASE_CLASS_NAME.
     */
    public static void writeAppComponentFactory(String inManifestFile, String outManifestFile, String newComponentFactory){
        ModificationProperty property = new ModificationProperty();
        property.addApplicationAttribute(new AttributeItem("appComponentFactory",newComponentFactory));
        FileProcesser.processManifestFile(inManifestFile, outManifestFile, property);
    }

    public static void writeDebuggable(String inManifestFile, String outManifestFile, String debuggable){
        ModificationProperty property = new ModificationProperty();
        property.addApplicationAttribute(new AttributeItem("debuggable",debuggable));
        FileProcesser.processManifestFile(inManifestFile, outManifestFile, property);
    }

    public static String getAttributeValue(String file, String tag, String ns, String attrName){
        byte[] axmlData = IoUtils.readFile(file);
        AxmlParser axmlParser = new AxmlParser(axmlData);
        try {
            while (axmlParser.next() != AxmlParser.END_FILE) {
                if (axmlParser.getAttrCount() != 0 && !axmlParser.getName().equals(tag)) {
                    continue;
                }
                for (int i = 0; i < axmlParser.getAttrCount(); i++) {
                    if (ns == null || axmlParser.getNamespacePrefix().equals(ns)) {
                        if(axmlParser.getAttrName(i).equals(attrName)) {
                            return (String) axmlParser.getAttrValue(i);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String getApplicationName(String file) {
        String attributeValue = getAttributeValue(file, "application", "android", "name");
        attributeValue = attributeValue == null ? getAttributeValue(file, "application", "dist", "name") : attributeValue;
        attributeValue = attributeValue == null ? getAttributeValue(file, "application", null,"name") : attributeValue;
        return attributeValue;
    }

    public static String getAppComponentFactory(String file) {
        String attributeValue = getAttributeValue(file, "application", "android", "appComponentFactory");
        attributeValue = attributeValue == null ? getAttributeValue(file, "application", "android", "appComponentFactory") : attributeValue;
        attributeValue = attributeValue == null ? getAttributeValue(file, "application", null,"appComponentFactory") : attributeValue;
        return attributeValue;
    }

    public static String getPackageName(String file) {
        return getAttributeValue(file,"manifest","android","package");
    }
}
