package com.parallax.parallax.dex;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.parallax.parallax.util.LogUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Adds a small PVM4 sidecar gate to selected application startup/UI hot spots without replacing
 * their Android method bodies. This is deliberately different from full high-value
 * virtualization: lifecycle ABI, receiver state, object parameters, try/catch layout and the
 * original method implementation stay on normal DPT. The inserted gate only makes the method
 * enter an authenticated four-layer VM program before continuing with its original code.
 *
 * Why this exists: Application/Activity callbacks are unsafe candidates for the scalar method
 * VM, but leaving every callback completely outside the VM gives no VM coverage in applications
 * whose business code is concentrated in those callbacks. A sidecar gate gives a bounded VM
 * dependency while preserving Android verifier/runtime semantics.
 */
final class HighValueVmEntryGuardTransformer {
    private static final int PREFIX_CODE_UNITS = 6; // const/31i (3) + invoke-static/35c (3)

    private HighValueVmEntryGuardTransformer() {}

    static final class Result {
        private final List<HighValueVmTransformer.Program> programs;
        private final int nextMethodId;
        private final int guarded;

        Result(List<HighValueVmTransformer.Program> programs, int nextMethodId, int guarded) {
            this.programs = programs;
            this.nextMethodId = nextMethodId;
            this.guarded = guarded;
        }

        List<HighValueVmTransformer.Program> getPrograms() { return programs; }
        int getNextMethodId() { return nextMethodId; }
        int getGuarded() { return guarded; }
    }

    static Result transform(File inputDex,
                            File outputDex,
                            int firstMethodId,
                            String bridgeClassSig,
                            String appPackage,
                            int maxGuards) throws IOException {
        if (maxGuards <= 0) {
            return new Result(new ArrayList<>(), firstMethodId, 0);
        }
        DexBackedDexFile dex = DexFileFactory.loadDexFile(inputDex, Opcodes.getDefault());
        List<ClassDef> rewrittenClasses = new ArrayList<>();
        List<HighValueVmTransformer.Program> programs = new ArrayList<>();
        int nextId = firstMethodId;
        int guarded = 0;

        String appPrefix = "L" + appPackage.replace('.', '/') + "/";
        for (ClassDef classDef : dex.getClasses()) {
            List<Method> methods = new ArrayList<>();
            for (Method method : classDef.getMethods()) {
                if (guarded >= maxGuards
                        || !classDef.getType().startsWith(appPrefix)
                        || !isPreferredHotspot(method)
                        || !isSafeToPrepend(method)) {
                    methods.add(method);
                    continue;
                }

                methods.add(prependVmGate(method, nextId, bridgeClassSig));
                programs.add(makeGuardProgram(nextId));
                LogUtils.info("High-value PVM4 sidecar: guarded %s -> VM id=%d",
                        signatureOf(method), nextId);
                nextId++;
                guarded++;
            }
            rewrittenClasses.add(new ImmutableClassDef(
                    classDef.getType(), classDef.getAccessFlags(), classDef.getSuperclass(),
                    classDef.getInterfaces(), classDef.getSourceFile(), classDef.getAnnotations(),
                    classDef.getFields(), methods));
        }

        if (guarded > 0) {
            DexFileFactory.writeDexFile(outputDex.getAbsolutePath(),
                    new ImmutableDexFile(dex.getOpcodes(), rewrittenClasses));
        }
        return new Result(programs, nextId, guarded);
    }

    /**
     * Keep this intentionally narrow. We want a few guards in the application/login/main flow,
     * not arbitrary framework callbacks. Full method virtualization is handled separately.
     */
    private static boolean isPreferredHotspot(Method method) {
        String owner = method.getDefiningClass();
        String simple = owner.substring(owner.lastIndexOf('/') + 1, owner.length() - 1);
        String name = method.getName();
        String ret = method.getReturnType();
        List<? extends CharSequence> params = method.getParameterTypes();

        if ("BoxApplication".equals(simple)) {
            return "onCreate".equals(name) && params.isEmpty() && "V".equals(ret);
        }

        boolean login = "LogAct".equals(simple)
                || simple.toLowerCase().contains("login");
        if (login) {
            if ("onCreate".equals(name) && isBundleOnly(params) && "V".equals(ret)) return true;
            return "q".equals(name) && params.isEmpty() && "V".equals(ret);
        }

        boolean main = "MAct".equals(simple)
                || simple.toLowerCase().contains("mainactivity");
        if (main) {
            return "onCreate".equals(name) && isBundleOnly(params) && "V".equals(ret);
        }
        return false;
    }

    private static boolean isBundleOnly(List<? extends CharSequence> params) {
        return params.size() == 1 && "Landroid/os/Bundle;".contentEquals(params.get(0));
    }

    private static boolean isSafeToPrepend(Method method) {
        int flags = method.getAccessFlags();
        if ((flags & (AccessFlags.NATIVE.getValue() | AccessFlags.ABSTRACT.getValue())) != 0) {
            return false;
        }
        if ("<init>".equals(method.getName()) || "<clinit>".equals(method.getName())) {
            return false;
        }
        MethodImplementation impl = method.getImplementation();
        if (impl == null || !impl.getTryBlocks().isEmpty()) {
            // We do not rewrite exception-handler addresses here. Keeping such methods on normal
            // DPT is safer than silently damaging their handler table.
            return false;
        }

        int incomingWords = ((flags & AccessFlags.STATIC.getValue()) == 0) ? 1 : 0;
        for (CharSequence type : method.getParameterTypes()) {
            incomingWords += ("J".contentEquals(type) || "D".contentEquals(type)) ? 2 : 1;
        }
        int locals = impl.getRegisterCount() - incomingWords;
        // v0 is guaranteed to be a local register, so the gate never overwrites this/parameters.
        return locals >= 1 && impl.getRegisterCount() <= 255;
    }

    private static Method prependVmGate(Method method, int methodId, String bridgeClassSig) {
        MethodImplementation impl = method.getImplementation();
        List<Instruction> code = new ArrayList<>();
        code.add(new ImmutableInstruction31i(Opcode.CONST, 0, methodId));
        ImmutableMethodReference bridge = new ImmutableMethodReference(
                bridgeClassSig, "hvv0", List.of("I"), "V");
        code.add(new ImmutableInstruction35c(
                Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, bridge));
        for (Instruction instruction : impl.getInstructions()) code.add(instruction);

        // PREFIX_CODE_UNITS is even, preserving payload alignment for switch/array payloads.
        if ((PREFIX_CODE_UNITS & 1) != 0) {
            throw new IllegalStateException("PVM4 sidecar prefix must preserve DEX payload alignment");
        }

        return new ImmutableMethod(
                method.getDefiningClass(), method.getName(), method.getParameters(),
                method.getReturnType(), method.getAccessFlags(), method.getAnnotations(),
                method.getHiddenApiRestrictions(),
                new ImmutableMethodImplementation(impl.getRegisterCount(), code, null, null));
    }

    private static HighValueVmTransformer.Program makeGuardProgram(int methodId) {
        // The semantic work is intentionally side-effect free; the security value comes from the
        // authenticated PVM4 envelope, randomized L2/L3/L4 lowering and native per-cell guards.
        int seed = Integer.rotateLeft(methodId * 0x45d9f3b, 7) ^ 0x6d2b79f5;
        List<HighValueVmTransformer.VmOp> ops = new ArrayList<>();
        ops.add(new HighValueVmTransformer.VmOp(
                HighValueVmTransformer.OP_CONST, 0, 0, 0, seed, 0));
        ops.add(new HighValueVmTransformer.VmOp(
                HighValueVmTransformer.OP_XOR_LIT, 0, 0, 0, 0x51f2a3c7, 0));
        ops.add(new HighValueVmTransformer.VmOp(
                HighValueVmTransformer.OP_ADD_LIT, 0, 0, 0, 0x13579bdf, 0));
        ops.add(new HighValueVmTransformer.VmOp(
                HighValueVmTransformer.OP_RETURN_VOID, 0, 0, 0, 0, 0));
        return new HighValueVmTransformer.Program(methodId, 1, 0, false, ops);
    }

    private static String signatureOf(Method method) {
        StringBuilder out = new StringBuilder(method.getDefiningClass())
                .append("->").append(method.getName()).append('(');
        for (CharSequence type : method.getParameterTypes()) out.append(type);
        return out.append(')').append(method.getReturnType()).toString();
    }
}
