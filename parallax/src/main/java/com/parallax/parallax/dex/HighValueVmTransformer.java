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
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.parallax.parallax.Parallax;
import com.parallax.parallax.util.CryptoUtils;
import com.parallax.parallax.util.LogUtils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * High-value method compiler.
 *
 * A selected method is compiled into a private integer VM program and its ORIGINAL Dalvik
 * body is replaced, before normal DPT extraction, with a tiny fixed JNI trampoline.
 * The original selected body therefore never enters the hollow DEX or Parallax.love.
 *
 * Manual rules remain fail-closed. Auto mode probes every method with the same compiler and
 * only selects methods that are completely supported, leaving everything else on normal DPT.
 */
public final class HighValueVmTransformer {
    private static final byte[] ENVELOPE_MAGIC = {'P', 'V', 'M', '1'};
    private static final byte[] RAW_MAGIC = {'P', 'V', 'R', '1'};
    private static final String KEY_LABEL = "Parallax/highvalue/vm/encryption/v1/";
    private static final String AAD_PREFIX = "Parallax/highvalue/vm/payload/v1/";
    private static final int NONCE_SIZE = 12;
    private static final int MAX_SEMANTIC_OPS_PER_PROGRAM = 65536;
    private static final SecureRandom RANDOM = new SecureRandom();

    // Keep in sync with shell/src/main/cpp/parallax_vm4.cpp.
    public static final int OP_NOP = 0;
    public static final int OP_CONST = 1;
    public static final int OP_MOVE = 2;
    public static final int OP_NEG = 3;
    public static final int OP_NOT = 4;
    public static final int OP_BYTE = 5;
    public static final int OP_CHAR = 6;
    public static final int OP_SHORT = 7;
    public static final int OP_ADD = 10;
    public static final int OP_SUB = 11;
    public static final int OP_MUL = 12;
    public static final int OP_DIV = 13;
    public static final int OP_REM = 14;
    public static final int OP_AND = 15;
    public static final int OP_OR = 16;
    public static final int OP_XOR = 17;
    public static final int OP_SHL = 18;
    public static final int OP_SHR = 19;
    public static final int OP_USHR = 20;
    public static final int OP_ADD_LIT = 21;
    public static final int OP_RSUB_LIT = 22;
    public static final int OP_MUL_LIT = 23;
    public static final int OP_DIV_LIT = 24;
    public static final int OP_REM_LIT = 25;
    public static final int OP_AND_LIT = 26;
    public static final int OP_OR_LIT = 27;
    public static final int OP_XOR_LIT = 28;
    public static final int OP_SHL_LIT = 29;
    public static final int OP_SHR_LIT = 30;
    public static final int OP_USHR_LIT = 31;
    public static final int OP_GOTO = 40;
    public static final int OP_IF_EQZ = 41;
    public static final int OP_IF_NEZ = 42;
    public static final int OP_IF_LTZ = 43;
    public static final int OP_IF_GEZ = 44;
    public static final int OP_IF_GTZ = 45;
    public static final int OP_IF_LEZ = 46;
    public static final int OP_IF_EQ = 47;
    public static final int OP_IF_NE = 48;
    public static final int OP_IF_LT = 49;
    public static final int OP_IF_GE = 50;
    public static final int OP_IF_GT = 51;
    public static final int OP_IF_LE = 52;
    public static final int OP_RETURN = 60;
    public static final int OP_RETURN_VOID = 61;

    private HighValueVmTransformer() {}

    public static final class Rule {
        private final String source;
        private final Pattern pattern;
        private final boolean wildcard;
        private int matches;

        Rule(String source) {
            this.source = source;
            this.wildcard = source.indexOf('*') >= 0 || source.indexOf('?') >= 0;
            if (!wildcard) {
                this.pattern = null;
                return;
            }
            StringBuilder regex = new StringBuilder("^");
            for (int i = 0; i < source.length(); i++) {
                char ch = source.charAt(i);
                if (ch == '*') regex.append(".*");
                else if (ch == '?') regex.append('.');
                else regex.append(Pattern.quote(String.valueOf(ch)));
            }
            this.pattern = Pattern.compile(regex.append('$').toString());
        }

        boolean matches(String signature) {
            boolean matched = wildcard ? pattern.matcher(signature).matches() : source.equals(signature);
            if (!matched) return false;
            matches++;
            return true;
        }

        boolean isExact() { return !wildcard; }
        public String getSource() { return source; }
        public int getMatches() { return matches; }
    }

    public static final class VmOp {
        final int opcode, a, b, c, imm, target;
        VmOp(int opcode, int a, int b, int c, int imm, int target) {
            this.opcode = opcode; this.a = a; this.b = b; this.c = c;
            this.imm = imm; this.target = target;
        }
    }

    public static final class Program {
        final int id, registerCount, parameterCount;
        final boolean returnsValue;
        final List<VmOp> ops;
        Program(int id, int registerCount, int parameterCount, boolean returnsValue, List<VmOp> ops) {
            this.id = id; this.registerCount = registerCount; this.parameterCount = parameterCount;
            this.returnsValue = returnsValue; this.ops = ops;
        }
    }

    public static final class Result {
        private final List<Program> programs;
        private final int nextMethodId;
        Result(List<Program> programs, int nextMethodId) {
            this.programs = programs; this.nextMethodId = nextMethodId;
        }
        public List<Program> getPrograms() { return programs; }
        public int getNextMethodId() { return nextMethodId; }
    }

    /** Aggregate-only discovery data; method signatures are intentionally not written to the APK. */
    public static final class AutoScanResult {
        private final List<Rule> rules;
        private final int scanned;
        private final int compatible;
        private final int unsupported;
        private final int deferredByLimit;
        private final int selectedOps;

        AutoScanResult(List<Rule> rules, int scanned, int compatible, int unsupported,
                       int deferredByLimit, int selectedOps) {
            this.rules = rules;
            this.scanned = scanned;
            this.compatible = compatible;
            this.unsupported = unsupported;
            this.deferredByLimit = deferredByLimit;
            this.selectedOps = selectedOps;
        }

        public List<Rule> getRules() { return rules; }
        public int getScanned() { return scanned; }
        public int getCompatible() { return compatible; }
        public int getUnsupported() { return unsupported; }
        public int getDeferredByLimit() { return deferredByLimit; }
        public int getSelected() { return rules.size(); }
        public int getSelectedOps() { return selectedOps; }
    }

    public static List<Rule> loadRules(String rulesPath) throws IOException {
        if (rulesPath == null || rulesPath.trim().isEmpty()) return new ArrayList<>();
        File file = new File(rulesPath);
        if (!file.isFile()) throw new IOException("High-value method rules file not found: " + rulesPath);
        List<Rule> rules = new ArrayList<>();
        for (String raw : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
            String line = raw.trim();
            if (!line.isEmpty() && !line.startsWith("#")) rules.add(new Rule(line));
        }
        if (rules.isEmpty()) throw new IOException("High-value method rules file is empty: " + rulesPath);
        return rules;
    }

    public static void verifyAllRulesMatched(List<Rule> rules) throws IOException {
        List<String> missing = new ArrayList<>();
        for (Rule rule : rules) if (rule.getMatches() == 0) missing.add(rule.getSource());
        if (!missing.isEmpty()) throw new IOException(
                "High-value method rule(s) matched nothing: " + String.join(", ", missing));
    }

    /**
     * Probe every method with the exact same compiler used for real conversion. Unsupported
     * methods are skipped rather than causing an auto-mode pack failure. Selection is bounded
     * by both program count and semantic-op budget so PVM4 stays inside native runtime limits.
     */
    public static AutoScanResult scanAutoCandidates(File inputDex, int maxSelections,
                                                     int maxSemanticOps) throws IOException {
        if (maxSelections < 0 || maxSemanticOps < 0) {
            throw new IOException("High-value auto limits cannot be negative");
        }
        DexBackedDexFile dex = DexFileFactory.loadDexFile(inputDex, Opcodes.getDefault());
        List<Rule> selectedRules = new ArrayList<>();
        int scanned = 0;
        int compatible = 0;
        int unsupportedCount = 0;
        int deferred = 0;
        int selectedOps = 0;

        for (ClassDef classDef : dex.getClasses()) {
            for (Method method : classDef.getMethods()) {
                scanned++;
                String signature = signatureOf(method);
                try {
                    Program program = compile(1, signature, method);
                    compatible++;
                    int opCount = program.ops.size();
                    if (selectedRules.size() >= maxSelections
                            || selectedOps + opCount > maxSemanticOps) {
                        deferred++;
                        continue;
                    }
                    selectedRules.add(new Rule(signature));
                    selectedOps += opCount;
                } catch (IOException | RuntimeException ignored) {
                    unsupportedCount++;
                }
            }
        }
        return new AutoScanResult(selectedRules, scanned, compatible, unsupportedCount,
                deferred, selectedOps);
    }

    public static Result transform(File inputDex, File outputDex, List<Rule> rules,
                                   int firstMethodId, String bridgeClassSig) throws IOException {
        DexBackedDexFile dex = DexFileFactory.loadDexFile(inputDex, Opcodes.getDefault());
        List<ClassDef> rewrittenClasses = new ArrayList<>();
        List<Program> programs = new ArrayList<>();
        int nextId = firstMethodId;

        Map<String, List<Rule>> exactRules = new HashMap<>();
        List<Rule> wildcardRules = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.isExact()) {
                exactRules.computeIfAbsent(rule.getSource(), ignored -> new ArrayList<>()).add(rule);
            } else {
                wildcardRules.add(rule);
            }
        }

        for (ClassDef classDef : dex.getClasses()) {
            List<Method> methods = new ArrayList<>();
            for (Method method : classDef.getMethods()) {
                String signature = signatureOf(method);
                boolean selected = false;
                List<Rule> exact = exactRules.get(signature);
                if (exact != null) {
                    for (Rule rule : exact) selected |= rule.matches(signature);
                }
                for (Rule rule : wildcardRules) selected |= rule.matches(signature);
                if (!selected) {
                    methods.add(method);
                    continue;
                }
                Program program = compile(nextId, signature, method);
                methods.add(rewriteAsTrampoline(method, nextId, bridgeClassSig));
                programs.add(program);
                LogUtils.info("High-value VM: moved %s -> native VM id=%d", signature, nextId);
                nextId++;
            }
            rewrittenClasses.add(new ImmutableClassDef(
                    classDef.getType(), classDef.getAccessFlags(), classDef.getSuperclass(),
                    classDef.getInterfaces(), classDef.getSourceFile(), classDef.getAnnotations(),
                    classDef.getFields(), methods));
        }

        DexFileFactory.writeDexFile(outputDex.getAbsolutePath(),
                new ImmutableDexFile(dex.getOpcodes(), rewrittenClasses));
        return new Result(programs, nextId);
    }

    public static void writeEncryptedPayload(File output, List<Program> programs, byte[] encKey)
            throws IOException {
        String buildKey = Parallax.getBuildKey();
        if (buildKey == null || buildKey.isEmpty()) {
            throw new IOException("Parallax build key is missing; cannot seal high-value VM payload");
        }
        byte[] raw = serialize(programs);
        byte[] payloadKey = CryptoUtils.hmacSha256(encKey, KEY_LABEL + buildKey);
        byte[] nonce = new byte[NONCE_SIZE];
        RANDOM.nextBytes(nonce);
        byte[] aad = (AAD_PREFIX + raw.length).getBytes(StandardCharsets.US_ASCII);
        byte[] ciphertext = CryptoUtils.aesGcmEncrypt(payloadKey, nonce, aad, raw);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(ENVELOPE_MAGIC);
            out.writeInt(raw.length);
            out.write(nonce);
            out.write(ciphertext);
        }
        Files.write(output.toPath(), buffer.toByteArray());
        LogUtils.info("High-value native VM payload AES-256-GCM sealed: methods=%d raw=%d encrypted=%d",
                programs.size(), raw.length, buffer.size());
        Arrays.fill(raw, (byte) 0);
        Arrays.fill(payloadKey, (byte) 0);
        Arrays.fill(aad, (byte) 0);
    }

    private static byte[] serialize(List<Program> programs) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(RAW_MAGIC);
            out.writeInt(programs.size());
            for (Program p : programs) {
                out.writeInt(p.id);
                out.writeShort(p.registerCount);
                out.writeByte(p.parameterCount);
                out.writeByte(p.returnsValue ? 1 : 0);
                out.writeInt(p.ops.size());
                for (VmOp op : p.ops) {
                    out.writeByte(op.opcode); out.writeByte(op.a); out.writeByte(op.b); out.writeByte(op.c);
                    out.writeInt(op.imm); out.writeInt(op.target);
                }
            }
        }
        return buffer.toByteArray();
    }

    private static String signatureOf(Method method) {
        StringBuilder out = new StringBuilder(method.getDefiningClass())
                .append("->").append(method.getName()).append('(');
        for (CharSequence type : method.getParameterTypes()) out.append(type);
        return out.append(')').append(method.getReturnType()).toString();
    }

    private static Program compile(int methodId, String signature, Method method) throws IOException {
        int flags = method.getAccessFlags();
        if ((flags & AccessFlags.STATIC.getValue()) == 0) throw unsupported(signature, "method must be static");
        if ((flags & (AccessFlags.NATIVE.getValue() | AccessFlags.ABSTRACT.getValue())) != 0
                || "<init>".equals(method.getName()) || "<clinit>".equals(method.getName())) {
            throw unsupported(signature, "native/abstract/constructor methods are not eligible");
        }
        if (method.getParameterTypes().size() > 4) throw unsupported(signature, "maximum four int parameters");
        for (CharSequence type : method.getParameterTypes()) {
            if (!"I".contentEquals(type)) throw unsupported(signature, "v1 accepts only int parameters");
        }
        boolean returnsValue = "I".equals(method.getReturnType());
        if (!returnsValue && !"V".equals(method.getReturnType())) {
            throw unsupported(signature, "v1 return type must be int or void");
        }

        MethodImplementation impl = method.getImplementation();
        if (impl == null) throw unsupported(signature, "method has no implementation");
        if (!impl.getTryBlocks().isEmpty()) throw unsupported(signature, "try/catch is not supported");
        int registerCount = impl.getRegisterCount();
        if (registerCount <= 0 || registerCount > 255 || registerCount < method.getParameterTypes().size()) {
            throw unsupported(signature, "register layout outside VM limits");
        }

        List<Instruction> insns = new ArrayList<>();
        Map<Integer, Integer> addressToIndex = new LinkedHashMap<>();
        int address = 0;
        for (Instruction i : impl.getInstructions()) {
            addressToIndex.put(address, insns.size());
            insns.add(i);
            address += i.getCodeUnits();
        }
        if (insns.isEmpty()) throw unsupported(signature, "method has no executable instructions");
        if (insns.size() > MAX_SEMANTIC_OPS_PER_PROGRAM) {
            throw unsupported(signature, "method exceeds VM operation limit");
        }
        List<VmOp> ops = new ArrayList<>(insns.size());
        address = 0;
        for (Instruction i : insns) {
            ops.add(translate(signature, i, address, addressToIndex));
            address += i.getCodeUnits();
        }
        return new Program(methodId, registerCount, method.getParameterTypes().size(), returnsValue, ops);
    }

    private static IOException unsupported(String signature, String why) {
        return new IOException("High-value VM cannot convert " + signature + ": " + why);
    }

    private static int branchTarget(String signature, Instruction i, int address,
                                    Map<Integer, Integer> targets) throws IOException {
        int targetAddress = address + ((OffsetInstruction) i).getCodeOffset();
        Integer target = targets.get(targetAddress);
        if (target == null) throw unsupported(signature, "branch target is not an instruction boundary");
        return target;
    }

    private static VmOp translate(String signature, Instruction i, int address,
                                  Map<Integer, Integer> targets) throws IOException {
        Opcode op = i.getOpcode();
        switch (op) {
            case NOP: return v(OP_NOP, 0, 0, 0, 0, 0);
            case CONST_4: case CONST_16: case CONST: case CONST_HIGH16:
                return v(OP_CONST, a(i), 0, 0, lit(i), 0);
            case MOVE: case MOVE_FROM16: case MOVE_16:
                return v(OP_MOVE, a(i), b(i), 0, 0, 0);
            case NEG_INT: return v(OP_NEG, a(i), b(i), 0, 0, 0);
            case NOT_INT: return v(OP_NOT, a(i), b(i), 0, 0, 0);
            case INT_TO_BYTE: return v(OP_BYTE, a(i), b(i), 0, 0, 0);
            case INT_TO_CHAR: return v(OP_CHAR, a(i), b(i), 0, 0, 0);
            case INT_TO_SHORT: return v(OP_SHORT, a(i), b(i), 0, 0, 0);
            case ADD_INT: return three(OP_ADD, i); case SUB_INT: return three(OP_SUB, i);
            case MUL_INT: return three(OP_MUL, i); case DIV_INT: return three(OP_DIV, i);
            case REM_INT: return three(OP_REM, i); case AND_INT: return three(OP_AND, i);
            case OR_INT: return three(OP_OR, i); case XOR_INT: return three(OP_XOR, i);
            case SHL_INT: return three(OP_SHL, i); case SHR_INT: return three(OP_SHR, i);
            case USHR_INT: return three(OP_USHR, i);
            case ADD_INT_2ADDR: return two(OP_ADD, i); case SUB_INT_2ADDR: return two(OP_SUB, i);
            case MUL_INT_2ADDR: return two(OP_MUL, i); case DIV_INT_2ADDR: return two(OP_DIV, i);
            case REM_INT_2ADDR: return two(OP_REM, i); case AND_INT_2ADDR: return two(OP_AND, i);
            case OR_INT_2ADDR: return two(OP_OR, i); case XOR_INT_2ADDR: return two(OP_XOR, i);
            case SHL_INT_2ADDR: return two(OP_SHL, i); case SHR_INT_2ADDR: return two(OP_SHR, i);
            case USHR_INT_2ADDR: return two(OP_USHR, i);
            case ADD_INT_LIT8: case ADD_INT_LIT16: return literalOp(OP_ADD_LIT, i);
            case RSUB_INT: case RSUB_INT_LIT8: return literalOp(OP_RSUB_LIT, i);
            case MUL_INT_LIT8: case MUL_INT_LIT16: return literalOp(OP_MUL_LIT, i);
            case DIV_INT_LIT8: case DIV_INT_LIT16: return literalOp(OP_DIV_LIT, i);
            case REM_INT_LIT8: case REM_INT_LIT16: return literalOp(OP_REM_LIT, i);
            case AND_INT_LIT8: case AND_INT_LIT16: return literalOp(OP_AND_LIT, i);
            case OR_INT_LIT8: case OR_INT_LIT16: return literalOp(OP_OR_LIT, i);
            case XOR_INT_LIT8: case XOR_INT_LIT16: return literalOp(OP_XOR_LIT, i);
            case SHL_INT_LIT8: return literalOp(OP_SHL_LIT, i);
            case SHR_INT_LIT8: return literalOp(OP_SHR_LIT, i);
            case USHR_INT_LIT8: return literalOp(OP_USHR_LIT, i);
            case GOTO: case GOTO_16: case GOTO_32:
                return v(OP_GOTO, 0, 0, 0, 0, branchTarget(signature, i, address, targets));
            case IF_EQZ: return oneBranch(OP_IF_EQZ, i, signature, address, targets);
            case IF_NEZ: return oneBranch(OP_IF_NEZ, i, signature, address, targets);
            case IF_LTZ: return oneBranch(OP_IF_LTZ, i, signature, address, targets);
            case IF_GEZ: return oneBranch(OP_IF_GEZ, i, signature, address, targets);
            case IF_GTZ: return oneBranch(OP_IF_GTZ, i, signature, address, targets);
            case IF_LEZ: return oneBranch(OP_IF_LEZ, i, signature, address, targets);
            case IF_EQ: return twoBranch(OP_IF_EQ, i, signature, address, targets);
            case IF_NE: return twoBranch(OP_IF_NE, i, signature, address, targets);
            case IF_LT: return twoBranch(OP_IF_LT, i, signature, address, targets);
            case IF_GE: return twoBranch(OP_IF_GE, i, signature, address, targets);
            case IF_GT: return twoBranch(OP_IF_GT, i, signature, address, targets);
            case IF_LE: return twoBranch(OP_IF_LE, i, signature, address, targets);
            case RETURN: return v(OP_RETURN, a(i), 0, 0, 0, 0);
            case RETURN_VOID: return v(OP_RETURN_VOID, 0, 0, 0, 0, 0);
            default: throw unsupported(signature, "unsupported opcode " + op);
        }
    }

    private static int a(Instruction i) { return ((OneRegisterInstruction) i).getRegisterA(); }
    private static int b(Instruction i) { return ((TwoRegisterInstruction) i).getRegisterB(); }
    private static int lit(Instruction i) { return ((NarrowLiteralInstruction) i).getNarrowLiteral(); }
    private static VmOp v(int op, int a, int b, int c, int imm, int target) { return new VmOp(op,a,b,c,imm,target); }
    private static VmOp three(int op, Instruction i) {
        ThreeRegisterInstruction x = (ThreeRegisterInstruction) i;
        return v(op, x.getRegisterA(), x.getRegisterB(), x.getRegisterC(), 0, 0);
    }
    private static VmOp two(int op, Instruction i) {
        TwoRegisterInstruction x = (TwoRegisterInstruction) i;
        return v(op, x.getRegisterA(), x.getRegisterA(), x.getRegisterB(), 0, 0);
    }
    private static VmOp literalOp(int op, Instruction i) {
        TwoRegisterInstruction x = (TwoRegisterInstruction) i;
        return v(op, x.getRegisterA(), x.getRegisterB(), 0, lit(i), 0);
    }
    private static VmOp oneBranch(int op, Instruction i, String sig, int address,
                                  Map<Integer,Integer> targets) throws IOException {
        return v(op, a(i), 0, 0, 0, branchTarget(sig, i, address, targets));
    }
    private static VmOp twoBranch(int op, Instruction i, String sig, int address,
                                  Map<Integer,Integer> targets) throws IOException {
        TwoRegisterInstruction x = (TwoRegisterInstruction) i;
        return v(op, x.getRegisterA(), x.getRegisterB(), 0, 0,
                branchTarget(sig, i, address, targets));
    }

    private static Method rewriteAsTrampoline(Method method, int methodId, String bridgeClassSig) {
        int params = method.getParameterTypes().size();
        boolean returnsValue = "I".equals(method.getReturnType());
        List<String> bridgeParams = new ArrayList<>();
        bridgeParams.add("I");
        for (int i = 0; i < params; i++) bridgeParams.add("I");
        ImmutableMethodReference bridge = new ImmutableMethodReference(
                bridgeClassSig, (returnsValue ? "hvi" : "hvv") + params,
                bridgeParams, returnsValue ? "I" : "V");

        List<Instruction> code = new ArrayList<>();
        code.add(new ImmutableInstruction31i(Opcode.CONST, 0, methodId));
        code.add(new ImmutableInstruction35c(Opcode.INVOKE_STATIC, params + 1,
                0, params >= 1 ? 1 : 0, params >= 2 ? 2 : 0,
                params >= 3 ? 3 : 0, params >= 4 ? 4 : 0, bridge));
        if (returnsValue) {
            code.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT, 0));
            code.add(new ImmutableInstruction11x(Opcode.RETURN, 0));
        } else {
            code.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        }
        return new ImmutableMethod(method.getDefiningClass(), method.getName(), method.getParameters(),
                method.getReturnType(), method.getAccessFlags(), method.getAnnotations(),
                method.getHiddenApiRestrictions(),
                new ImmutableMethodImplementation(params + 1, code, null, null));
    }
}
