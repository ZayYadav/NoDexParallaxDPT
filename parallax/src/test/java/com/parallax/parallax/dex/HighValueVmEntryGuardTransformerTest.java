package com.parallax.parallax.dex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;

import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class HighValueVmEntryGuardTransformerTest {

    @Test
    public void prependsVmGateWithoutReplacingLifecycleBody() throws Exception {
        File dir = Files.createTempDirectory("parallax-pvm4-sidecar").toFile();
        File input = new File(dir, "classes.dex");
        File output = new File(dir, "classes.guarded.dex");
        try {
            // Parameter-free synthetic methods keep this regression test independent of
            // dexlib's MethodParameter constructor API. P.apk integration covers the real
            // Bundle-taking Activity callbacks on every protection build.
            ImmutableMethod boxOnCreate = voidMethod(
                    "Lcom/bgmi/BoxApplication;", "onCreate", 2);
            ImmutableMethod loginHelper = voidMethod(
                    "Lcom/bgmi/LogAct;", "q", 2);

            List<ClassDef> classes = new ArrayList<>();
            classes.add(clazz("Lcom/bgmi/BoxApplication;", List.of(boxOnCreate)));
            classes.add(clazz("Lcom/bgmi/LogAct;", List.of(loginHelper)));
            DexFileFactory.writeDexFile(input.getAbsolutePath(),
                    new ImmutableDexFile(Opcodes.getDefault(), classes));

            HighValueVmEntryGuardTransformer.Result result =
                    HighValueVmEntryGuardTransformer.transform(
                            input, output, 1, "LParallax/Enc/CrackWarTeamMC;", "com.bgmi", 4);

            assertEquals(2, result.getGuarded());
            assertEquals(2, result.getPrograms().size());
            assertEquals(3, result.getNextMethodId());

            DexBackedDexFile guarded = DexFileFactory.loadDexFile(output, Opcodes.getDefault());
            int checked = 0;
            for (ClassDef cls : guarded.getClasses()) {
                for (Method method : cls.getMethods()) {
                    if (!isExpected(method)) continue;
                    assertNotNull(method.getImplementation());
                    List<? extends Instruction> instructions =
                            toList(method.getImplementation().getInstructions());
                    assertEquals(Opcode.CONST, instructions.get(0).getOpcode());
                    assertEquals(Opcode.INVOKE_STATIC, instructions.get(1).getOpcode());
                    // The original body still follows the PVM4 gate; it was not replaced.
                    assertEquals(Opcode.RETURN_VOID,
                            instructions.get(instructions.size() - 1).getOpcode());
                    checked++;
                }
            }
            assertEquals(2, checked);
        } finally {
            deleteRecursively(dir);
        }
    }

    private static boolean isExpected(Method method) {
        String owner = method.getDefiningClass();
        return (owner.endsWith("/BoxApplication;") && "onCreate".equals(method.getName()))
                || (owner.endsWith("/LogAct;") && "q".equals(method.getName()));
    }

    private static ImmutableClassDef clazz(String type, List<ImmutableMethod> methods) {
        return new ImmutableClassDef(
                type,
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                Collections.emptyList(),
                null,
                null,
                null,
                methods);
    }

    private static ImmutableMethod voidMethod(
            String owner, String name, int registerCount) {
        return new ImmutableMethod(
                owner,
                name,
                Collections.emptyList(),
                "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.FINAL.getValue(),
                null,
                null,
                new ImmutableMethodImplementation(
                        registerCount,
                        List.of(new ImmutableInstruction10x(Opcode.RETURN_VOID)),
                        null,
                        null));
    }

    private static <T> List<T> toList(Iterable<? extends T> iterable) {
        List<T> out = new ArrayList<>();
        for (T item : iterable) out.add(item);
        return out;
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
