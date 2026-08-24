package com.parallax.parallax.dex;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.parallax.parallax.util.LogUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Binds the protected application's original DEX to the Parallax shell.
 *
 * The old implementation emitted a reflection/decryption helper into every eligible
 * class. That worked, but it inflated protected APKs. The current implementation uses
 * a tiny direct native gate instead: existing static initializers receive one invoke,
 * and a small number of ordinary application classes receive a synthetic <clinit>.
 *
 * Consequences:
 *  - extracted original DEX files keep distributed dependencies on the shell;
 *  - signature/runtime checks execute naturally as classes initialize;
 *  - the size cost is only a few code units per gate instead of a reflection helper;
 *  - no extra bootstrap class is introduced, preserving the one-class shell DEX.
 */
public final class ReflectionClinitInjector {

    private static final int MAX_METHODS_PER_DEX = 65535;
    private static final int MAX_SYNTHETIC_GATES_PER_DEX = 16;

    private static final Set<String> SKIPPED_CLASS_TYPES = Set.of(
            "Landroidx/multidex/MultiDex;",
            "Lcom/android/support/multidex/MultiDex;"
    );

    private static final String[] SYNTHETIC_SKIP_PREFIXES = {
            "Landroid/",
            "Landroidx/",
            "Lkotlin/",
            "Lkotlinx/",
            "Ljava/",
            "Ljavax/",
            "Lcom/google/",
            "Lcom/facebook/",
            "Lokhttp3/",
            "Lokio/"
    };

    private ReflectionClinitInjector() {
    }

    public static void inject(String inputDex, String outputDex, String jniClassSig) throws IOException {
        File inputFile = new File(inputDex);
        DexBackedDexFile dexFile = DexFileFactory.loadDexFile(inputFile, Opcodes.getDefault());

        List<ClassDef> classes = new ArrayList<>();
        int totalMethods = 0;
        for (ClassDef classDef : dexFile.getClasses()) {
            classes.add(classDef);
            for (Method ignored : classDef.getMethods()) {
                totalMethods++;
            }
        }

        ImmutableMethodReference gateRef = new ImmutableMethodReference(
                jniClassSig,
                "clinit",
                Collections.emptyList(),
                "V"
        );

        List<ClassDef> rewritten = new ArrayList<>(classes.size());
        int existingGates = 0;
        int syntheticGates = 0;

        for (ClassDef classDef : classes) {
            if (isSkippedClass(classDef.getType())) {
                rewritten.add(classDef);
                continue;
            }

            List<Method> methods = new ArrayList<>();
            boolean hasClinit = false;
            boolean injectedExisting = false;

            for (Method method : classDef.getMethods()) {
                if ("<clinit>".equals(method.getName())) {
                    hasClinit = true;
                    if (isEligibleClinit(method)) {
                        methods.add(injectGateCall(method, gateRef));
                        existingGates++;
                        injectedExisting = true;
                        continue;
                    }
                }
                methods.add(method);
            }

            if (!hasClinit
                    && !injectedExisting
                    && syntheticGates < MAX_SYNTHETIC_GATES_PER_DEX
                    && totalMethods < MAX_METHODS_PER_DEX
                    && isSafeSyntheticHost(classDef)) {
                methods.add(createSyntheticGateClinit(classDef.getType(), gateRef));
                syntheticGates++;
                totalMethods++;
            }

            rewritten.add(new ImmutableClassDefAdapter(classDef, methods).build());
        }

        DexFile outDex = new ImmutableDexFile(dexFile.getOpcodes(), rewritten);
        DexFileFactory.writeDexFile(outputDex, outDex);
        LogUtils.info("Parallax DEX integrity gates: existing=%d synthetic=%d total=%d",
                existingGates, syntheticGates, existingGates + syntheticGates);
    }

    private static boolean isSkippedClass(String classType) {
        return classType == null || SKIPPED_CLASS_TYPES.contains(classType);
    }

    private static boolean isSafeSyntheticHost(ClassDef classDef) {
        int flags = classDef.getAccessFlags();
        if ((flags & AccessFlags.INTERFACE.getValue()) != 0
                || (flags & AccessFlags.ANNOTATION.getValue()) != 0) {
            return false;
        }

        String type = classDef.getType();
        for (String prefix : SYNTHETIC_SKIP_PREFIXES) {
            if (type.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isEligibleClinit(Method method) {
        MethodImplementation implementation = method.getImplementation();
        if (implementation == null || !implementation.getTryBlocks().isEmpty()) {
            return false;
        }

        List<Instruction> instructions = toInstructionList(implementation.getInstructions());
        if (instructions.isEmpty()
                || instructions.get(instructions.size() - 1).getOpcode() != Opcode.RETURN_VOID) {
            return false;
        }

        for (Instruction instruction : instructions) {
            if (instruction.getOpcode() == Opcode.FILL_ARRAY_DATA) {
                return false;
            }
        }
        return true;
    }

    private static List<Instruction> toInstructionList(Iterable<? extends Instruction> instructions) {
        List<Instruction> list = new ArrayList<>();
        for (Instruction instruction : instructions) {
            list.add(instruction);
        }
        return list;
    }

    private static Method injectGateCall(Method method, ImmutableMethodReference gateRef) {
        MethodImplementation implementation = method.getImplementation();
        List<Instruction> original = toInstructionList(implementation.getInstructions());
        List<Instruction> code = new ArrayList<>(original.size() + 1);

        for (int i = 0; i < original.size() - 1; i++) {
            code.add(original.get(i));
        }
        code.add(new ImmutableInstruction35c(
                Opcode.INVOKE_STATIC,
                0, 0, 0, 0, 0, 0,
                gateRef
        ));
        code.add(original.get(original.size() - 1));

        return new ImmutableMethod(
                method.getDefiningClass(),
                method.getName(),
                method.getParameters(),
                method.getReturnType(),
                method.getAccessFlags(),
                method.getAnnotations(),
                method.getHiddenApiRestrictions(),
                new ImmutableMethodImplementation(
                        implementation.getRegisterCount(),
                        code,
                        implementation.getTryBlocks(),
                        implementation.getDebugItems()
                )
        );
    }

    private static Method createSyntheticGateClinit(String classType,
                                                     ImmutableMethodReference gateRef) {
        List<Instruction> code = List.of(
                new ImmutableInstruction35c(
                        Opcode.INVOKE_STATIC,
                        0, 0, 0, 0, 0, 0,
                        gateRef
                ),
                new ImmutableInstruction10x(Opcode.RETURN_VOID)
        );

        return new ImmutableMethod(
                classType,
                "<clinit>",
                Collections.emptyList(),
                "V",
                AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null,
                null,
                new ImmutableMethodImplementation(0, code, null, null)
        );
    }

    private static final class ImmutableClassDefAdapter {
        private final ClassDef source;
        private final List<Method> methods;

        ImmutableClassDefAdapter(ClassDef source, List<Method> methods) {
            this.source = source;
            this.methods = methods;
        }

        ClassDef build() {
            return new com.android.tools.smali.dexlib2.immutable.ImmutableClassDef(
                    source.getType(),
                    source.getAccessFlags(),
                    source.getSuperclass(),
                    source.getInterfaces(),
                    source.getSourceFile(),
                    source.getAnnotations(),
                    source.getFields(),
                    methods
            );
        }
    }
}
