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

    private static String requireClassName(String value, String label) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(label + " must not be empty");
        }
        return value.trim();
    }

    public static void writeApplicationName(String inManifestFile, String outManifestFile, String newApplicationName){
        String applicationName = requireClassName(newApplicationName, "Application class name");
        ModificationProperty property = new ModificationProperty();
        // The caller already resolves the release ABI name (for example
        // Parallax.Enc.Parallax1). Never rewrite it back to a source/legacy class.
        property.addApplicationAttribute(new AttributeItem(NodeValue.Application.NAME, applicationName));
        property.addUsesPermission("android.permission.INTERNET");
        FileProcesser.processManifestFile(inManifestFile, outManifestFile, property);
    }

    public static void writeAppComponentFactory(String inManifestFile, String outManifestFile, String newComponentFactory){
        String componentFactory = requireClassName(newComponentFactory, "AppComponentFactory class name");
        ModificationProperty property = new ModificationProperty();
        // Keep the factory name exactly aligned with the class emitted into the release
        // shell DEX (for example Parallax.Enc.Parallax2).
        property.addApplicationAttribute(new AttributeItem("appComponentFactory", componentFactory));
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
        attributeValue = attributeValue == null ? getAttributeValue(file, "application", null,"appComponentFactory") : attributeValue;
        return attributeValue;
    }

    public static String getPackageName(String file) {
        return getAttributeValue(file,"manifest","android","package");
    }
}
