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
    public static void writeApplicationName(String inManifestFile, String outManifestFile, String newApplicationName){
        if (newApplicationName != null) {
            int lastDot = newApplicationName.lastIndexOf('.');
            if (lastDot > 0) {
                newApplicationName = newApplicationName.substring(0, lastDot + 1)
                        + "ParallaxKiSettingKarwaDo";
            }
        }
        ModificationProperty property = new ModificationProperty();
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.NAME,newApplicationName));
        property.addUsesPermission("android.permission.INTERNET");
        FileProcesser.processManifestFile(inManifestFile, outManifestFile, property);
    }

    public static void writeAppComponentFactory(String inManifestFile, String outManifestFile, String newComponentFactory){
        String applicationName = getApplicationName(inManifestFile);
        if (applicationName != null && applicationName.endsWith(".ParallaxKiSettingKarwaDo")) {
            int lastDot = applicationName.lastIndexOf('.');
            if (lastDot > 0) {
                newComponentFactory = applicationName.substring(0, lastDot + 1)
                        + "ParallaxKoLadkiChahiye";
            }
        }
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
