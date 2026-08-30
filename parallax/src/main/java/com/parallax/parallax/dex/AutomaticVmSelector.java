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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Conservative zero-config selector for the two native VM tiers.
 *
 * The selector never guesses beyond the instruction/type subset that the existing
 * HighValueVmTransformer can compile. Unsupported, framework, tiny and excessively large
 * methods stay on the normal DPT path. This keeps automatic mode fail-soft while still
 * moving useful pure-integer methods away from their original Dalvik bodies.
 */
final class AutomaticVmSelector {
    static final int MAX_TOTAL_METHODS = 96;
    static final int MAX_VM4_METHODS = 32;
    static final int MIN_INSTRUCTIONS = 6;
    static final int MAX_INSTRUCTIONS = 128;

    enum Tier { VM, VM4 }

    static final class Selection {
        private final List<HighValueVmTransformer.Rule> vmRules;
        private final List<HighValueVmTransformer.Rule> vm4Rules;
        private final int eligibleCount;

        Selection(List<HighValueVmTransformer.Rule> vmRules,
                  List<HighValueVmTransformer.Rule> vm4Rules,
                  int eligibleCount) {
            this.vmRules = vmRules;
            this.vm4Rules = vm4Rules;
            this.eligibleCount = eligibleCount;
        }

        List<HighValueVmTransformer.Rule> getVmRules() { return vmRules; }
        List<HighValueVmTransformer.Rule> getVm4Rules() { return vm4Rules; }
        int getEligibleCount() { return eligibleCount; }
        int getSelectedCount() { return vmRules.size() + vm4Rules.size(); }
    }

    private static final class Candidate {
        final String signature;
        final int score;
        final int instructionCount;
        final int branchCount;
        final int arithmeticCount;
        final boolean sensitiveName;

        Candidate(String signature, int score, int instructionCount, int branchCount,
                  int arithmeticCount, boolean sensitiveName) {
            this.signature = signature;
            this.score = score;
            this.instructionCount = instructionCount;
            this.branchCount = branchCount;
            this.arithmeticCount = arithmeticCount;
            this.sensitiveName = sensitiveName;
        }
    }

    private AutomaticVmSelector() {}

    static Selection select(List<File> dexFiles) throws IOException {
        List<Candidate> candidates = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (File dex : dexFiles) {
            DexBackedDexFile file = DexFileFactory.loadDexFile(dex, Opcodes.getDefault());
            for (ClassDef classDef : file.getClasses()) {
                if (isFrameworkClass(classDef.getType())) continue;
                for (Method method : classDef.getMethods()) {
                    Candidate candidate = inspect(method);
                    if (candidate != null && seen.add(candidate.signature)) {
                        candidates.add(candidate);
                    }
                }
            }
        }

        candidates.sort(Comparator
                .comparingInt((Candidate c) -> c.score).reversed()
                .thenComparing(c -> c.signature));

        List<HighValueVmTransformer.Rule> vm = new ArrayList<>();
        List<HighValueVmTransformer.Rule> vm4 = new ArrayList<>();
        int selected = Math.min(candidates.size(), MAX_TOTAL_METHODS);
        for (int i = 0; i < selected; i++) {
            Candidate candidate = candidates.get(i);
            Tier tier = classify(candidate.instructionCount, candidate.branchCount,
                    candidate.arithmeticCount, candidate.sensitiveName);
            if (tier == Tier.VM4 && vm4.size() < MAX_VM4_METHODS) {
                vm4.add(new HighValueVmTransformer.Rule(candidate.signature));
            } else {
                vm.add(new HighValueVmTransformer.Rule(candidate.signature));
            }
        }
        return new Selection(Collections.unmodifiableList(vm),
                Collections.unmodifiableList(vm4), candidates.size());
    }

    static Tier classify(int instructionCount, int branchCount,
                         int arithmeticCount, boolean sensitiveName) {
        if (sensitiveName || branchCount >= 3 || arithmeticCount >= 10
                || (branchCount >= 1 && instructionCount >= 18)
                || instructionCount >= 32) {
            return Tier.VM4;
        }
        return Tier.VM;
    }

    private static Candidate inspect(Method method) {
        int flags = method.getAccessFlags();
        if ((flags & AccessFlags.STATIC.getValue()) == 0) return null;
        if ((flags & (AccessFlags.NATIVE.getValue() | AccessFlags.ABSTRACT.getValue())) != 0) return null;
        if ("<init>".equals(method.getName()) || "<clinit>".equals(method.getName())) return null;
        if (method.getParameterTypes().size() > 4) return null;
        for (CharSequence type : method.getParameterTypes()) {
            if (!"I".contentEquals(type)) return null;
        }
        if (!"I".equals(method.getReturnType()) && !"V".equals(method.getReturnType())) return null;

        MethodImplementation impl = method.getImplementation();
        if (impl == null || !impl.getTryBlocks().isEmpty()) return null;
        int registers = impl.getRegisterCount();
        if (registers <= 0 || registers > 255 || registers < method.getParameterTypes().size()) return null;

        int instructionCount = 0;
        int branchCount = 0;
        int arithmeticCount = 0;
        for (Instruction instruction : impl.getInstructions()) {
            Opcode opcode = instruction.getOpcode();
            if (!isSupported(opcode)) return null;
            instructionCount++;
            if (isBranch(opcode)) branchCount++;
            if (isArithmetic(opcode)) arithmeticCount++;
            if (instructionCount > MAX_INSTRUCTIONS) return null;
        }
        if (instructionCount < MIN_INSTRUCTIONS) return null;

        String signature = signatureOf(method);
        boolean sensitive = hasSensitiveName(method);
        int score = instructionCount + branchCount * 8 + arithmeticCount * 2 + (sensitive ? 24 : 0);
        return new Candidate(signature, score, instructionCount, branchCount, arithmeticCount, sensitive);
    }

    private static boolean hasSensitiveName(Method method) {
        String text = (method.getDefiningClass() + "/" + method.getName()).toLowerCase(Locale.US);
        String[] hints = {
                "auth", "verify", "valid", "license", "licence", "token", "secret",
                "sign", "signature", "hash", "crypt", "cipher", "key", "security",
                "check", "guard", "access", "permission", "integrity"
        };
        for (String hint : hints) if (text.contains(hint)) return true;
        return false;
    }

    private static boolean isFrameworkClass(String type) {
        String[] prefixes = {
                "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lsun/",
                "Lkotlin/", "Lkotlinx/", "Lcom/google/", "Lokhttp3/", "Lokio/",
                "Lorg/apache/", "Lorg/json/", "Lorg/intellij/"
        };
        for (String prefix : prefixes) if (type.startsWith(prefix)) return true;
        return false;
    }

    private static String signatureOf(Method method) {
        StringBuilder out = new StringBuilder(method.getDefiningClass())
                .append("->").append(method.getName()).append('(');
        for (CharSequence type : method.getParameterTypes()) out.append(type);
        return out.append(')').append(method.getReturnType()).toString();
    }

    private static boolean isBranch(Opcode op) {
        switch (op) {
            case GOTO: case GOTO_16: case GOTO_32:
            case IF_EQZ: case IF_NEZ: case IF_LTZ: case IF_GEZ: case IF_GTZ: case IF_LEZ:
            case IF_EQ: case IF_NE: case IF_LT: case IF_GE: case IF_GT: case IF_LE:
                return true;
            default:
                return false;
        }
    }

    private static boolean isArithmetic(Opcode op) {
        switch (op) {
            case NEG_INT: case NOT_INT:
            case ADD_INT: case SUB_INT: case MUL_INT: case DIV_INT: case REM_INT:
            case AND_INT: case OR_INT: case XOR_INT: case SHL_INT: case SHR_INT: case USHR_INT:
            case ADD_INT_2ADDR: case SUB_INT_2ADDR: case MUL_INT_2ADDR: case DIV_INT_2ADDR:
            case REM_INT_2ADDR: case AND_INT_2ADDR: case OR_INT_2ADDR: case XOR_INT_2ADDR:
            case SHL_INT_2ADDR: case SHR_INT_2ADDR: case USHR_INT_2ADDR:
            case ADD_INT_LIT8: case ADD_INT_LIT16: case RSUB_INT: case RSUB_INT_LIT8:
            case MUL_INT_LIT8: case MUL_INT_LIT16: case DIV_INT_LIT8: case DIV_INT_LIT16:
            case REM_INT_LIT8: case REM_INT_LIT16: case AND_INT_LIT8: case AND_INT_LIT16:
            case OR_INT_LIT8: case OR_INT_LIT16: case XOR_INT_LIT8: case XOR_INT_LIT16:
            case SHL_INT_LIT8: case SHR_INT_LIT8: case USHR_INT_LIT8:
                return true;
            default:
                return false;
        }
    }

    private static boolean isSupported(Opcode op) {
        switch (op) {
            case NOP:
            case CONST_4: case CONST_16: case CONST: case CONST_HIGH16:
            case MOVE: case MOVE_FROM16: case MOVE_16:
            case NEG_INT: case NOT_INT: case INT_TO_BYTE: case INT_TO_CHAR: case INT_TO_SHORT:
            case ADD_INT: case SUB_INT: case MUL_INT: case DIV_INT: case REM_INT:
            case AND_INT: case OR_INT: case XOR_INT: case SHL_INT: case SHR_INT: case USHR_INT:
            case ADD_INT_2ADDR: case SUB_INT_2ADDR: case MUL_INT_2ADDR: case DIV_INT_2ADDR:
            case REM_INT_2ADDR: case AND_INT_2ADDR: case OR_INT_2ADDR: case XOR_INT_2ADDR:
            case SHL_INT_2ADDR: case SHR_INT_2ADDR: case USHR_INT_2ADDR:
            case ADD_INT_LIT8: case ADD_INT_LIT16: case RSUB_INT: case RSUB_INT_LIT8:
            case MUL_INT_LIT8: case MUL_INT_LIT16: case DIV_INT_LIT8: case DIV_INT_LIT16:
            case REM_INT_LIT8: case REM_INT_LIT16: case AND_INT_LIT8: case AND_INT_LIT16:
            case OR_INT_LIT8: case OR_INT_LIT16: case XOR_INT_LIT8: case XOR_INT_LIT16:
            case SHL_INT_LIT8: case SHR_INT_LIT8: case USHR_INT_LIT8:
            case GOTO: case GOTO_16: case GOTO_32:
            case IF_EQZ: case IF_NEZ: case IF_LTZ: case IF_GEZ: case IF_GTZ: case IF_LEZ:
            case IF_EQ: case IF_NE: case IF_LT: case IF_GE: case IF_GT: case IF_LE:
            case RETURN: case RETURN_VOID:
                return true;
            default:
                return false;
        }
    }
}
