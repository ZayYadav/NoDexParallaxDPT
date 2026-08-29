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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Opt-in high-value method tier.
 *
 * Selected methods are compiled from a deliberately small, deterministic subset of Dalvik
 * integer bytecode into a private Parallax VM program. Their original Dalvik implementation
 * is replaced BEFORE the normal DPT extraction pass with a tiny invoke-static trampoline.
 * Therefore the original selected method body never enters the hollow DEX or Parallax.love.
 *
 * This is intentionally strict. A rule-matched method that uses an unsupported construct
 * fails the protection build instead of silently falling back to normal DEX restoration.
 */
public final class HighValueVmTransformer {
    private static final byte[] ENVELOPE_MAGIC = {'P', 'V', 'M', '1'};
    private static final byte[] RAW_MAGIC = {'P', 'V', 'R', '1'};
    private static final String KEY_LABEL = "Parallax/highvalue/vm/encryption/v1/";
    private static final String AAD_PREFIX = "Parallax/highvalue/vm/payload/v1/";
    private static final int NONCE_SIZE = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    // Keep in sync with shell/src/main/cpp/parallax_vm.h.
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
        private int matches;

        Rule(String source) {
            this.source = source;
            StringBuilder regex = new StringBuilder("^");
            for (int i = 0; i < source.length(); i++) {
                char ch = source.charAt(i);
                if (ch == '*') regex.append(".*");
                else if (ch == '?') regex.append('.');
                else regex.append(Pattern.quote(String.valueOf(ch)));
            }
            regex.append('$');
            this.pattern = Pattern.compile(regex.toString());
        }

        boolean matches(String signature) {
            if (pattern.matcher(signature).matches()) {
                matches++;
                return true;
            }
            return false;
        }

        public String getSource() { return source; }
        public int getMatches() { return matches; }
    }

    public static final class VmOp {
        final int opcode;
        final int a;
        final int b;
        final int c;
        final int imm;
        final int target;

        VmOp(int opcode, int a, int b, int c, int imm, int target) {
            this.opcode = opcode;
            this.a = a;
            this.b = b;
            this.c = c;
            this.imm = imm;
            this.target = target;
        }
    }

    public static final class Program {
        final int id;
        final String signature;
        final int registerCount;
        final int parameterCount;
        final boolean returnsValue;
        final List<VmOp> ops;

        Program(int id, String signature, int registerCount, int parameterCount,
                boolean returnsValue, List<VmOp> ops) {
            this.id = id;
            this.signature = signature;
            this.registerCount = registerCount;
            this.parameterCount = parameterCount;
            this.returnsValue = returnsValue;
            this.ops = ops;
        }
    }

    public static final class Result {
        private final List<Program> programs;
        private final int nextMethodId;

        Result(List<Program> programs, int nextMethodId) {
            this.programs = programs;
            this.nextMethodId = nextMethodId;
        }

        public List<Program> getPrograms() { return programs; }
        public int getNextMethodId() { return nextMethodId; }
    }

    public static List<Rule> loadRules(String rulesPath) throws IOException {
        if (rulesPath == null || rulesPath.trim().isEmpty()) return new ArrayList<>();
        File file = new File(rulesPath);
        if (!file.isFile()) throw new IOException("High-value method rules file not found: " + rulesPath);
        List<Rule> rules = new ArrayList<>();
        for (String raw : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            rules.add(new Rule(line));
        }
        if (rules.isEmpty()) throw new IOException("High-value method rules file is empty: " + rulesPath);
        return rules;
    }

    public static void verifyAllRulesMatched(List<Rule> rules) throws IOException {
        List<String> missing = new ArrayList<>();
        for (Rule rule : rules) if (rule.getMatches() == 0) missing.add(rule.getSource());
        if (!missing.isEmpty()) {
            throw new IOException("High-value method rule(s) matched nothing: " + String.join(", ", missing));
        }
    }

    public static Result transform(File inputDex, File outputDex, List<Rule> rules,
                                   int firstMethodId, String jniClassSig) throws IOException {
        if (rules == null || rules.isEmpty()) {
            Files.copy(inputDex.toPath(), outputDex.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            return new Result(new ArrayList<>(), firstMethodId);
        }

        DexBackedDexFile dex = DexFileFactory.loadDexFile(inputDex, Opcodes.getDefault());
        List<ClassDef> rewrittenClasses = new ArrayList<>();
        List<Program> programs = new ArrayList<>();
        int methodId = firstMethodId;

        for (ClassDef classDef : dex.getClasses()) {
            List<Method> methods = new ArrayList<>();
            for (Method method : classDef.getMethods()) {
                String signature = signatureOf(method);
                boolean selected = false;
                for (Rule rule : rules) selected |= rule.matches(signature);
                if (!selected) {
                    methods.add(method);
                    continue;
                }

                Program program = compile(methodId, signature, method);
                methods.add(rewriteAsTrampoline(method, methodId, jniClassSig));
                programs.add(program);
                LogUtils.info("High-value VM: moved %s -> native VM id=%d", signature, methodId);
                methodId++;
            }
            rewrittenClasses.add(new ImmutableClassDef(
                    classDef.getType(), classDef.getAccessFlags(), classDef.getSuperclass(),
                    classDef.getInterfaces(), classDef.getSourceFile(), classDef.getAnnotations(),
                    classDef.getFields(), methods));
        }

        DexFile out = new ImmutableDexFile(dex.getOpcodes(), rewrittenClasses);
        DexFileFactory.writeDexFile(outputDex.getAbsolutePath(), out);
        return new Result(programs, methodId);
    }

    public static void writeEncryptedPayload(File output, List<Program> programs, byte[] encKey)
            throws IOException {
        if (programs == null || programs.isEmpty()) return;
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

        ByteArrayOutputStream buffer = new ByteArrayOutputStream(
                ENVELOPE_MAGIC.length + 4 + nonce.length + ciphertext.length);
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
            for (Program program : programs) {
                out.writeInt(program.id);
                out.writeShort(program.registerCount);
                out.writeByte(program.parameterCount);
                out.writeByte(program.returnsValue ? 1 : 0);
                out.writeInt(program.ops.size());
                for (VmOp op : program.ops) {
                    out.writeByte(op.opcode);
                    out.writeByte(op.a);
                    out.writeByte(op.b);
                    out.writeByte(op.c);
                    out.writeInt(op.imm);
                    out.writeInt(op.target);
                }
            }
        }
        return buffer.toByteArray();
    }

    private static String signatureOf(Method method) {
        StringBuilder sb = new StringBuilder();
        sb.append(method.getDefiningClass()).append("->").append(method.getName()).append('(');
        for (CharSequence type : method.getParameterTypes()) sb.append(type);
        return sb.append(')').append(method.getReturnType()).toString();
    }

    private static boolean intLike(CharSequence type) {
        if (type == null || type.length() != 1) return false;
        char ch = type.charAt(0);
        return ch == 'I' || ch == 'Z' || ch == 'B' || ch == 'S' || ch == 'C';
    }

    private static Program compile(int methodId, String signature, Method method) throws IOException {
        int flags = method.getAccessFlags();
        if ((flags & AccessFlags.STATIC.getValue()) == 0) {
            throw unsupported(signature, "only static methods are supported");
        }
        if ((flags & (AccessFlags.NATIVE.getValue() | AccessFlags.ABSTRACT.getValue())) != 0
                || "<init>".equals(method.getName()) || "<clinit>".equals(method.getName())) {
            throw unsupported(signature, "native/abstract/constructor methods are not eligible");
        }

        List<? extends CharSequence> params = method.getParameterTypes();
        if (params.size() > 4) throw unsupported(signature, "maximum four primitive arguments");
        for (CharSequence type : params) {
            if (!intLike(type)) throw unsupported(signature, "only int/boolean/byte/short/char arguments");
        }
        boolean returnsValue = intLike(method.getReturnType());
        if (!returnsValue && !"V".equals(method.getReturnType())) {
            throw unsupported(signature, "return type must be int-like or void");
        }

        MethodImplementation implementation = method.getImplementation();
        if (implementation == null) throw unsupported(signature, "method has no implementation");
        if (!implementation.getTryBlocks().isEmpty()) {
            throw unsupported(signature, "try/catch is intentionally unsupported in native VM tier");
        }
        int registerCount = implementation.getRegisterCount();
        if (registerCount <= 0 || registerCount > 255 || registerCount < params.size()) {
            throw unsupported(signature, "register layout outside VM limits");
        }

        List<Instruction> instructions = new ArrayList<>();
        Map<Integer, Integer> addressToIndex = new LinkedHashMap<>();
        int address = 0;
        for (Instruction instruction : implementation.getInstructions()) {
            addressToIndex.put(address, instructions.size());
            instructions.add(instruction);
            address += instruction.getCodeUnits();
        }

        List<VmOp> ops = new ArrayList<>(instructions.size());
        address = 0;
        for (Instruction instruction : instructions) {
            ops.add(translate(signature, instruction, address, addressToIndex));
            address += instruction.getCodeUnits();
        }
        return new Program(methodId, signature, registerCount, params.size(), returnsValue, ops);
    }

    private static IOException unsupported(String signature, String why) {
        return new IOException("High-value VM cannot convert " + signature + ": " + why);
    }

    private static int regA(Instruction i) { return ((OneRegisterInstruction) i).getRegisterA(); }
    private static int regB(Instruction i) { return ((TwoRegisterInstruction) i).getRegisterB(); }
    private static int regC(Instruction i) { return ((ThreeRegisterInstruction) i).getRegisterC(); }
    private static int literal(Instruction i) { return ((NarrowLiteralInstruction) i).getNarrowLiteral(); }

    private static int target(String signature, Instruction instruction, int address,
                              Map<Integer, Integer> addressToIndex) throws IOException {
        int targetAddress = address + ((OffsetInstruction) instruction).getCodeOffset();
        Integer value = addressToIndex.get(targetAddress);
        if (value == null) throw unsupported(signature, "branch target is not an instruction boundary");
        return value;
    }

    private static VmOp translate(String signature, Instruction i, int address,
                                  Map<Integer, Integer> targets) throws IOException {
        Opcode op = i.getOpcode();
        switch (op) {
            case NOP: return new VmOp(OP_NOP, 0, 0, 0, 0, 0);
            case CONST_4:
            case CONST_16:
            case CONST:
            case CONST_HIGH16:
                return new VmOp(OP_CONST, regA(i), 0, 0, literal(i), 0);
            case MOVE:
            case MOVE_FROM16:
            case MOVE_16:
                return new VmOp(OP_MOVE, regA(i), regB(i), 0, 0, 0);
            case NEG_INT: return new VmOp(OP_NEG, regA(i), regB(i), 0, 0, 0);
            case NOT_INT: return new VmOp(OP_NOT, regA(i), regB(i), 0, 0, 0);
            case INT_TO_BYTE: return new VmOp(OP_BYTE, regA(i), regB(i), 0, 0, 0);
            case INT_TO_CHAR: return new VmOp(OP_CHAR, regA(i), regB(i), 0, 0, 0);
            case INT_TO_SHORT: return new VmOp(OP_SHORT, regA(i), regB(i), 0, 0, 0);

            case ADD_INT: return three(OP_ADD, i);
            case SUB_INT: return three(OP_SUB, i);
            case MUL_INT: return three(OP_MUL, i);
            case DIV_INT: return three(OP_DIV, i);
            case REM_INT: return three(OP_REM, i);
            case AND_INT: return three(OP_AND, i);
            case OR_INT: return three(OP_OR, i);
            case XOR_INT: return three(OP_XOR, i);
            case SHL_INT: return three(OP_SHL, i);
            case SHR_INT: return three(OP_SHR, i);
            case USHR_INT: return three(OP_USHR, i);

            case ADD_INT_2ADDR: return twoAddr(OP_ADD, i);
            case SUB_INT_2ADDR: return twoAddr(OP_SUB, i);
            case MUL_INT_2ADDR: return twoAddr(OP_MUL, i);
            case DIV_INT_2ADDR: return twoAddr(OP_DIV, i);
            case REM_INT_2ADDR: return twoAddr(OP_REM, i);
            case AND_INT_2ADDR: return twoAddr(OP_AND, i);
            case OR_INT_2ADDR: return twoAddr(OP_OR, i);
            case XOR_INT_2ADDR: return twoAddr(OP_XOR, i);
            case SHL_INT_2ADDR: return twoAddr(OP_SHL, i);
            case SHR_INT_2ADDR: return twoAddr(OP_SHR, i);
            case USHR_INT_2ADDR: return twoAddr(OP_USHR, i);

            case ADD_INT_LIT8:
            case ADD_INT_LIT16: return lit(OP_ADD_LIT, i);
            case RSUB_INT:
            case RSUB_INT_LIT8: return lit(OP_RSUB_LIT, i);
            case MUL_INT_LIT8:
            case MUL_INT_LIT16: return lit(OP_MUL_LIT, i);
            case DIV_INT_LIT8:
            case DIV_INT_LIT16: return lit(OP_DIV_LIT, i);
            case REM_INT_LIT8:
            case REM_INT_LIT16: return lit(OP_REM_LIT, i);
            case AND_INT_LIT8:
            case AND_INT_LIT16: return lit(OP_AND_LIT, i);
            case OR_INT_LIT8:
            case OR_INT_LIT16: return lit(OP_OR_LIT, i);
            case XOR_INT_LIT8:
            case XOR_INT_LIT16: return lit(OP_XOR_LIT, i);
            case SHL_INT_LIT8: return lit(OP_SHL_LIT, i);
            case SHR_INT_LIT8: return lit(OP_SHR_LIT, i);
            case USHR_INT_LIT8: return lit(OP_USHR_LIT, i);

            case GOTO:
            case GOTO_16:
            case GOTO_32:
                return new VmOp(OP_GOTO, 0, 0, 0, 0, target(signature, i, address, targets));
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
            case RETURN: return new VmOp(OP_RETURN, regA(i), 0, 0, 0, 0);
            case RETURN_VOID: return new VmOp(OP_RETURN_VOID, 0, 0, 0, 0, 0);
            default:
                throw unsupported(signature, "unsupported opcode " + op.name);
        }
    }

    private static VmOp three(int opcode, Instruction i) {
        ThreeRegisterInstruction x = (ThreeRegisterInstruction) i;
        return new VmOp(opcode, x.getRegisterA(), x.getRegisterB(), x.getRegisterC(), 0, 0);
    }

    private static VmOp twoAddr(int opcode, Instruction i) {
        TwoRegisterInstruction x = (TwoRegisterInstruction) i;
        return new VmOp(opcode, x.getRegisterA(), x.getRegisterA(), x.getRegisterB(), 0, 0);
    }

    private static VmOp lit(int opcode, Instruction i) {
        TwoRegisterInstruction x = (TwoRegisterInstruction) i;
        return new VmOp(opcode, x.getRegisterA(), x.getRegisterB(), 0, literal(i), 0);
    }

    private static VmOp oneBranch(int opcode, Instruction i, String signature, int address,
                                  Map<Integer, Integer> targets) throws IOException {
        return new VmOp(opcode, regA(i), 0, 0, 0, target(signature, i, address, targets));
    }

    private static VmOp twoBranch(int opcode, Instruction i, String signature, int address,
                                  Map<Integer, Integer> targets) throws IOException {
        TwoRegisterInstruction x = (TwoRegisterInstruction) i;
        return new VmOp(opcode, x.getRegisterA(), x.getRegisterB(), 0, 0,
                target(signature, i, address, targets));
    }

    private static Method rewriteAsTrampoline(Method method, int methodId, String jniClassSig)
            throws IOException {
        List<String> parameterTypes = new ArrayList<>();
        for (CharSequence type : method.getParameterTypes()) parameterTypes.add(type.toString());
        int paramCount = parameterTypes.size();
        boolean returnsValue = intLike(method.getReturnType());
        String bridgeName = (returnsValue ? "hvi" : "hvv") + paramCount;

        List<String> bridgeParams = new ArrayList<>();
        bridgeParams.add("I"); // method id
        bridgeParams.addAll(parameterTypes);
        ImmutableMethodReference bridgeRef = new ImmutableMethodReference(
                jniClassSig, bridgeName, bridgeParams, returnsValue ? "I" : "V");

        int registerCount = paramCount + 1;
        List<Instruction> code = new ArrayList<>();
        code.add(new ImmutableInstruction31i(Opcode.CONST, 0, methodId));
        int c = 0, d = 0, e = 0, f = 0, g = 0;
        int[] regs = {0, 1, 2, 3, 4};
        if (paramCount + 1 > 0) c = regs[0];
        if (paramCount + 1 > 1) d = regs[1];
        if (paramCount + 1 > 2) e = regs[2];
        if (paramCount + 1 > 3) f = regs[3];
        if (paramCount + 1 > 4) g = regs[4];
        code.add(new ImmutableInstruction35c(Opcode.INVOKE_STATIC, paramCount + 1,
                c, d, e, f, g, bridgeRef));
        if (returnsValue) {
            code.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT, 0));
            code.add(new ImmutableInstruction11x(Opcode.RETURN, 0));
        } else {
            code.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
        }

        ImmutableMethodImplementation implementation = new ImmutableMethodImplementation(
                registerCount, code, null, null);
        return new ImmutableMethod(method.getDefiningClass(), method.getName(), method.getParameters(),
                method.getReturnType(), method.getAccessFlags(), method.getAnnotations(),
                method.getHiddenApiRestrictions(), implementation);
    }
}
