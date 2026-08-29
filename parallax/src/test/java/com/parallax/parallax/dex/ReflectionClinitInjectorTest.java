package com.parallax.parallax.dex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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

public class ReflectionClinitInjectorTest {

    @Test
    public void preservesExistingInitializerAndAddsEncodedSyntheticGate() throws Exception {
        ImmutableMethod existingClinit = new ImmutableMethod(
                "Lsample/Existing;",
                "<clinit>",
                Collections.emptyList(),
                "V",
                AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null,
                null,
                new ImmutableMethodImplementation(
                        0,
                        List.of(
                                new ImmutableInstruction10x(Opcode.NOP),
                                new ImmutableInstruction10x(Opcode.RETURN_VOID)
                        ),
                        null,
                        null
                )
        );

        ImmutableClassDef existingClass = new ImmutableClassDef(
                "Lsample/Existing;",
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                Collections.emptyList(),
                null,
                null,
                null,
                List.of(existingClinit)
        );

        ImmutableClassDef syntheticHost = new ImmutableClassDef(
                "Lsample/SyntheticHost;",
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                Collections.emptyList(),
                null,
                null,
                null,
                Collections.emptyList()
        );

        File dir = Files.createTempDirectory("parallax-clinit-test").toFile();
        File input = new File(dir, "input.dex");
        File output = new File(dir, "output.dex");
        DexFileFactory.writeDexFile(input.getAbsolutePath(),
                new ImmutableDexFile(Opcodes.getDefault(), List.of(existingClass, syntheticHost)));

        ReflectionClinitInjector.inject(
                input.getAbsolutePath(),
                output.getAbsolutePath(),
                "Lcom/parallax/shell/ParallaxKiSettingKarwaDo;"
        );

        DexBackedDexFile result = DexFileFactory.loadDexFile(output, Opcodes.getDefault());
        ClassDef existing = findClass(result, "Lsample/Existing;");
        ClassDef synthetic = findClass(result, "Lsample/SyntheticHost;");
        assertNotNull(existing);
        assertNotNull(synthetic);

        Method preserved = findClinit(existing);
        assertNotNull(preserved);
        List<Opcode> preservedOpcodes = opcodes(preserved);
        assertEquals(List.of(Opcode.NOP, Opcode.RETURN_VOID), preservedOpcodes);
        assertTrue("existing initializer must not receive invoke-static",
                !preservedOpcodes.contains(Opcode.INVOKE_STATIC));

        Method added = findClinit(synthetic);
        assertNotNull(added);
        assertEquals(List.of(
                Opcode.CONST,
                Opcode.CONST,
                Opcode.CONST,
                Opcode.CONST,
                Opcode.INVOKE_STATIC,
                Opcode.RETURN_VOID
        ), opcodes(added));
        assertEquals(4, added.getImplementation().getRegisterCount());
    }

    private static ClassDef findClass(DexBackedDexFile dex, String type) {
        for (ClassDef classDef : dex.getClasses()) {
            if (type.equals(classDef.getType())) {
                return classDef;
            }
        }
        return null;
    }

    private static Method findClinit(ClassDef classDef) {
        for (Method method : classDef.getMethods()) {
            if ("<clinit>".equals(method.getName())) {
                return method;
            }
        }
        return null;
    }

    private static List<Opcode> opcodes(Method method) {
        List<Opcode> result = new ArrayList<>();
        for (Instruction instruction : method.getImplementation().getInstructions()) {
            result.add(instruction.getOpcode());
        }
        return result;
    }
}
