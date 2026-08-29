package com.parallax.parallax.dex;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.parallax.parallax.config.Const;
import com.parallax.parallax.config.ProtectRules;
import com.parallax.parallax.util.LogUtils;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Adds small non-destructive integrity gates to the ORIGINAL app DEX before DPT method
 * extraction. The synthetic gate bodies are then hollowed by the normal extraction pass,
 * so their randomized challenge words live in the encrypted/authenticated Parallax.love
 * vault instead of remaining as a useful plaintext verifier in the final static DEX.
 *
 * Runtime compatibility is the first invariant here: existing <clinit> methods are never
 * rewritten. Rebuilding an existing initializer from raw immutable instructions can leave
 * branch/payload offsets tied to the old layout; inserting even one instruction can then
 * change control flow and make a class fail only when it is first initialized much later.
 *
 * We therefore add gates only as brand-new synthetic <clinit> methods on conservative
 * host classes that did not already have one. Existing methods stay bytecode-structurally
 * untouched. The shell gate validates the randomized challenge and then enters the native
 * deterministic signature/integrity check.
 */
public final class ReflectionClinitInjector {

    private static final int MAX_METHODS_PER_DEX = 65535;
    private static final int MAX_SYNTHETIC_GATES_PER_DEX = 8;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final Set<String> SKIPPED_CLASS_TYPES = Set.of(
            "Landroidx/multidex/MultiDex;",
            "Lcom/android/support/multidex/MultiDex;"
    );

    private static final String[] SYNTHETIC_SKIP_PREFIXES = {
            "Landroid/",
            "Landroidx/",
            "Ldalvik/",
            "Lkotlin/",
            "Lkotlinx/",
            "Ljava/",
            "Ljavax/",
            "Lcom/google/",
            "Lcom/facebook/",
            "Lokhttp3/",
            "Lokio/",
            // Engine / runtime bridge packages are intentionally left completely intact.
            "Lcom/epicgames/",
            "Lcom/unity3d/",
            "Lorg/cocos2d/",
            "Lorg/cocos2dx/",
            "Lcom/tencent/",
            "Lcom/netease/",
            "Lcom/badlogic/",
            "Lmono/android/",
            "Lxamarin/"
    };

    private static final Set<String> FRAMEWORK_COMPONENT_SUPERS = Set.of(
            "Landroid/app/Activity;",
            "Landroid/app/NativeActivity;",
            "Landroid/app/Application;",
            "Landroid/app/Service;",
            "Landroid/content/BroadcastReceiver;",
            "Landroid/content/ContentProvider;"
    );

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
                gateClassSig(jniClassSig),
                "g",
                List.of("I", "I", "I", "I"),
                "V"
        );

        List<ClassDef> rewritten = new ArrayList<>(classes.size());
        int preservedExistingClinits = 0;
        int syntheticGates = 0;

        for (ClassDef classDef : classes) {
            List<Method> methods = new ArrayList<>();
            boolean hasClinit = false;

            for (Method method : classDef.getMethods()) {
                if ("<clinit>".equals(method.getName())) {
                    hasClinit = true;
                    preservedExistingClinits++;
                }
                // Deliberately preserve every existing method exactly as supplied by dexlib2.
                methods.add(method);
            }

            if (!hasClinit
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
        LogUtils.info("Parallax encoded pre-pack DEX gates: existing_clinit_preserved=%d synthetic=%d",
                preservedExistingClinits, syntheticGates);
    }

    private static String gateClassSig(String jniClassSig) {
        final String fallback = "Lcom/parallax/shell/" + Const.KEY_GATE_BASE_CLASS_NAME + ";";
        if (jniClassSig == null) {
            return fallback;
        }
        int slash = jniClassSig.lastIndexOf('/');
        if (slash <= 0) {
            return fallback;
        }
        return jniClassSig.substring(0, slash + 1) + Const.KEY_GATE_BASE_CLASS_NAME + ";";
    }

    private static int gateValue(int a, int b, int c) {
        int value = Integer.rotateLeft(a ^ 0x5A17D3C9, b & 31);
        value ^= Integer.rotateRight(b + 0x6D2B79F5, 11);
        value += c ^ 0x9E3779B9;
        return value;
    }

    private static boolean isSafeSyntheticHost(ClassDef classDef) {
        String type = classDef.getType();
        if (type == null || SKIPPED_CLASS_TYPES.contains(type)) {
            return false;
        }

        int flags = classDef.getAccessFlags();
        if ((flags & AccessFlags.INTERFACE.getValue()) != 0
                || (flags & AccessFlags.ANNOTATION.getValue()) != 0) {
            return false;
        }

        String superType = classDef.getSuperclass();
        if (superType != null && FRAMEWORK_COMPONENT_SUPERS.contains(superType)) {
            return false;
        }

        for (String prefix : SYNTHETIC_SKIP_PREFIXES) {
            if (type.startsWith(prefix)) {
                return false;
            }
        }

        // Keep the same compatibility boundary used by method extraction. Classes that
        // are excluded from DPT hollowing must not receive a new initializer either.
        if (ProtectRules.getInstance().matchRules(type)) {
            return false;
        }

        // JNI/engine bridge classes often depend on exact class-initialization behavior.
        for (Method method : classDef.getMethods()) {
            if ((method.getAccessFlags() & AccessFlags.NATIVE.getValue()) != 0) {
                return false;
            }
        }

        return true;
    }

    private static Method createSyntheticGateClinit(String classType,
                                                     ImmutableMethodReference gateRef) {
        int a = SECURE_RANDOM.nextInt();
        int b = SECURE_RANDOM.nextInt();
        int c = SECURE_RANDOM.nextInt();
        int expected = gateValue(a, b, c);

        List<com.android.tools.smali.dexlib2.iface.instruction.Instruction> code = List.of(
                new ImmutableInstruction31i(Opcode.CONST, 0, a),
                new ImmutableInstruction31i(Opcode.CONST, 1, b),
                new ImmutableInstruction31i(Opcode.CONST, 2, c),
                new ImmutableInstruction31i(Opcode.CONST, 3, expected),
                new ImmutableInstruction35c(
                        Opcode.INVOKE_STATIC,
                        4, 0, 1, 2, 3, 0,
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
                new ImmutableMethodImplementation(4, code, null, null)
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
