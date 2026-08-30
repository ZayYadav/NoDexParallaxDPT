package com.parallax.parallax.dex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;

import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;

public class HighValueVmAutoScanTest {

    @Test
    public void autoScanSelectsOnlyVerifierSafeStaticIntAbi() throws Exception {
        File dir = Files.createTempDirectory("parallax-auto-vm").toFile();
        File dex = new File(dir, "classes.dex");
        try {
            ImmutableMethod supported = intConstantMethod(
                    "Lsample/AutoVm;", "supported", AccessFlags.PUBLIC.getValue()
                            | AccessFlags.STATIC.getValue());
            ImmutableMethod unsupportedInstance = intConstantMethod(
                    "Lsample/AutoVm;", "instanceMethod", AccessFlags.PUBLIC.getValue());
            ImmutableMethod unsupportedBoolean = booleanConstantMethod(
                    "Lsample/AutoVm;", "booleanMethod", AccessFlags.PUBLIC.getValue()
                            | AccessFlags.STATIC.getValue());

            ImmutableClassDef clazz = new ImmutableClassDef(
                    "Lsample/AutoVm;",
                    AccessFlags.PUBLIC.getValue(),
                    "Ljava/lang/Object;",
                    Collections.emptyList(),
                    null,
                    null,
                    null,
                    List.of(supported, unsupportedInstance, unsupportedBoolean));
            DexFileFactory.writeDexFile(dex.getAbsolutePath(),
                    new ImmutableDexFile(Opcodes.getDefault(), List.of(clazz)));

            HighValueVmTransformer.AutoScanResult result =
                    HighValueVmTransformer.scanAutoCandidates(dex, 4096, 175000);

            assertEquals(3, result.getScanned());
            assertEquals(1, result.getCompatible());
            assertEquals(2, result.getUnsupported());
            assertEquals(1, result.getSelected());
            assertEquals(0, result.getDeferredByLimit());
            assertEquals(2, result.getSelectedOps());
            assertTrue(result.getRules().get(0).matches(
                    "Lsample/AutoVm;->supported()I"));
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    public void autoScanDefersCompatibleMethodWhenSafetyCapIsReached() throws Exception {
        File dir = Files.createTempDirectory("parallax-auto-vm-limit").toFile();
        File dex = new File(dir, "classes.dex");
        try {
            ImmutableMethod supported = intConstantMethod(
                    "Lsample/Limit;", "supported", AccessFlags.PUBLIC.getValue()
                            | AccessFlags.STATIC.getValue());
            ImmutableClassDef clazz = new ImmutableClassDef(
                    "Lsample/Limit;",
                    AccessFlags.PUBLIC.getValue(),
                    "Ljava/lang/Object;",
                    Collections.emptyList(),
                    null,
                    null,
                    null,
                    List.of(supported));
            DexFileFactory.writeDexFile(dex.getAbsolutePath(),
                    new ImmutableDexFile(Opcodes.getDefault(), List.of(clazz)));

            HighValueVmTransformer.AutoScanResult result =
                    HighValueVmTransformer.scanAutoCandidates(dex, 0, 175000);

            assertEquals(1, result.getScanned());
            assertEquals(1, result.getCompatible());
            assertEquals(0, result.getSelected());
            assertEquals(1, result.getDeferredByLimit());
        } finally {
            deleteRecursively(dir);
        }
    }

    private static ImmutableMethod intConstantMethod(String owner, String name, int flags) {
        return constantMethod(owner, name, "I", flags, 7);
    }

    private static ImmutableMethod booleanConstantMethod(String owner, String name, int flags) {
        return constantMethod(owner, name, "Z", flags, 1);
    }

    private static ImmutableMethod constantMethod(
            String owner, String name, String returnType, int flags, int value) {
        return new ImmutableMethod(
                owner,
                name,
                Collections.emptyList(),
                returnType,
                flags,
                null,
                null,
                new ImmutableMethodImplementation(
                        1,
                        List.of(
                                new ImmutableInstruction31i(Opcode.CONST, 0, value),
                                new ImmutableInstruction11x(Opcode.RETURN, 0)),
                        null,
                        null));
    }

    private static void deleteRecursively(File file) {
        if (file == null || !file.exists()) return;
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) deleteRecursively(child);
            }
        }
        file.delete();
    }
}
