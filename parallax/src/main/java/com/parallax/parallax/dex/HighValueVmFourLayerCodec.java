package com.parallax.parallax.dex;

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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Four-stage virtualization codec for high-value methods.
 *
 * L1: semantic VM IR emitted by HighValueVmTransformer.
 * L2: per-program register permutation plus decoy NOP micro-ops.
 * L3: every micro-op becomes a randomly-addressed state-machine cell and the physical
 *     cell array is shuffled so control flow is not recoverable from file order.
 * L4: opcodes/registers/words are encoded with per-program masks and every encoded cell
 *     carries a lightweight runtime guard. The native interpreter keeps this L4 form and
 *     decodes one cell at dispatch time instead of expanding it back to a canonical array.
 */
final class HighValueVmFourLayerCodec {
    private static final byte[] ENVELOPE_MAGIC = {'P', 'V', 'M', '4'};
    private static final byte[] RAW_MAGIC = {'P', 'V', 'R', '4'};
    private static final String KEY_LABEL = "Parallax/highvalue/vm/encryption/v4/";
    private static final String AAD_PREFIX = "Parallax/highvalue/vm/payload/v4/";
    private static final int NONCE_SIZE = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    private HighValueVmFourLayerCodec() {}

    static void writeEncryptedPayload(File output,
                                      List<HighValueVmTransformer.Program> programs,
                                      byte[] encKey) throws IOException {
        if (encKey == null || encKey.length != 16) {
            throw new IOException("Four-layer VM requires the 16-byte APK build key");
        }
        String buildKey = Parallax.getBuildKey();
        if (buildKey == null || buildKey.isEmpty()) {
            throw new IOException("Parallax build key is missing; cannot seal four-layer VM payload");
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
        LogUtils.info("High-value 4-layer VM sealed: methods=%d raw=%d encrypted=%d",
                programs.size(), raw.length, buffer.size());
        Arrays.fill(raw, (byte) 0);
        Arrays.fill(payloadKey, (byte) 0);
        Arrays.fill(aad, (byte) 0);
    }

    static byte[] serialize(List<HighValueVmTransformer.Program> programs) throws IOException {
        if (programs == null || programs.isEmpty()) {
            throw new IOException("Four-layer VM has no programs");
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(RAW_MAGIC);
            out.writeInt(programs.size());
            for (HighValueVmTransformer.Program program : programs) {
                Layer4Program p = lower(program);
                out.writeInt(p.id);
                out.writeShort(p.registerCount);
                out.writeByte(p.parameterCount);
                out.writeByte(p.returnsValue ? 1 : 0);
                for (int i = 0; i < 4; i++) out.writeByte(p.parameterSlots[i]);
                out.writeInt(p.entryState);
                out.writeInt(p.cells.size());
                out.writeInt(p.mask);
                out.writeByte(p.opXor);
                out.writeByte(p.opBias);
                out.writeByte(p.regXor);
                out.writeByte(4); // format layer count, validated by native parser
                for (Layer4Cell cell : p.cells) {
                    out.writeInt(cell.stateEncoded);
                    out.writeByte(cell.opEncoded);
                    out.writeByte(cell.aEncoded);
                    out.writeByte(cell.bEncoded);
                    out.writeByte(cell.cEncoded);
                    out.writeInt(cell.immEncoded);
                    out.writeInt(cell.nextEncoded);
                    out.writeInt(cell.branchEncoded);
                    out.writeInt(cell.guard);
                    out.writeInt(cell.noise);
                }
            }
        }
        return buffer.toByteArray();
    }

    private static Layer4Program lower(HighValueVmTransformer.Program source) throws IOException {
        Layer2Program l2 = layer2(source);
        Layer3Program l3 = layer3(l2);
        return layer4(l3);
    }

    /** L2: virtual register permutation + randomized decoy micro-ops. */
    private static Layer2Program layer2(HighValueVmTransformer.Program source) throws IOException {
        if (source.registerCount <= 0 || source.registerCount > 255) {
            throw new IOException("Four-layer VM register count outside limits for method " + source.id);
        }
        int[] permutation = new int[source.registerCount];
        for (int i = 0; i < permutation.length; i++) permutation[i] = i;
        for (int i = permutation.length - 1; i > 0; i--) {
            int j = RANDOM.nextInt(i + 1);
            int t = permutation[i]; permutation[i] = permutation[j]; permutation[j] = t;
        }

        int[] parameterSlots = new int[] {0xff, 0xff, 0xff, 0xff};
        int logicalBase = source.registerCount - source.parameterCount;
        for (int i = 0; i < source.parameterCount; i++) {
            parameterSlots[i] = permutation[logicalBase + i];
        }

        int count = source.ops.size();
        int[] prefixNops = new int[count];
        int[] sourceStart = new int[count];
        int total = 0;
        for (int i = 0; i < count; i++) {
            prefixNops[i] = RANDOM.nextInt(3); // 0..2 opaque no-op cells per semantic op
            sourceStart[i] = total;
            total += prefixNops[i] + 1;
        }

        List<Layer2Op> ops = new ArrayList<>(total);
        for (int i = 0; i < count; i++) {
            for (int n = 0; n < prefixNops[i]; n++) {
                ops.add(new Layer2Op(HighValueVmTransformer.OP_NOP, 0, 0, 0, RANDOM.nextInt(), 0));
            }
            HighValueVmTransformer.VmOp op = source.ops.get(i);
            int target = op.target;
            if (isBranch(op.opcode)) {
                if (target < 0 || target >= count) {
                    throw new IOException("Four-layer VM branch outside program for method " + source.id);
                }
                target = sourceStart[target];
            }
            ops.add(new Layer2Op(op.opcode,
                    remapRegister(op.a, permutation, source.registerCount),
                    remapRegister(op.b, permutation, source.registerCount),
                    remapRegister(op.c, permutation, source.registerCount),
                    op.imm, target));
        }
        return new Layer2Program(source.id, source.registerCount, source.parameterCount,
                source.returnsValue, parameterSlots, ops);
    }

    private static int remapRegister(int value, int[] permutation, int registerCount) {
        if (value < 0 || value >= registerCount) return value;
        return permutation[value];
    }

    /** L3: replace linear PCs with random state IDs and shuffle physical cells. */
    private static Layer3Program layer3(Layer2Program source) {
        int count = source.ops.size();
        int[] states = new int[count];
        Set<Integer> used = new HashSet<>(count * 2);
        for (int i = 0; i < count; i++) {
            int state;
            do state = RANDOM.nextInt(); while (state == 0 || !used.add(state));
            states[i] = state;
        }

        List<Layer3Cell> cells = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            Layer2Op op = source.ops.get(i);
            int next = i + 1 < count ? states[i + 1] : 0;
            int branch = 0;
            if (op.opcode == HighValueVmTransformer.OP_GOTO) {
                next = 0;
                branch = states[op.target];
            } else if (isConditional(op.opcode)) {
                branch = states[op.target];
            } else if (isReturn(op.opcode)) {
                next = 0;
            }
            cells.add(new Layer3Cell(states[i], op.opcode, op.a, op.b, op.c,
                    op.imm, next, branch));
        }
        Collections.shuffle(cells, RANDOM);
        return new Layer3Program(source.id, source.registerCount, source.parameterCount,
                source.returnsValue, source.parameterSlots, states[0], cells);
    }

    /** L4: encode dispatch cells and attach a per-cell runtime memory guard. */
    private static Layer4Program layer4(Layer3Program source) {
        int mask;
        do mask = RANDOM.nextInt(); while (mask == 0);
        int opXor = 1 + RANDOM.nextInt(255);
        int opBias = 1 + RANDOM.nextInt(251);
        int regXor = 1 + RANDOM.nextInt(255);
        int rotate = 5 + (mask & 15);
        int nextMask = Integer.rotateLeft(mask, 5);
        int branchMask = Integer.rotateLeft(mask, 13);

        List<Layer4Cell> cells = new ArrayList<>(source.cells.size());
        for (Layer3Cell cell : source.cells) {
            int stateEncoded = cell.state ^ mask;
            int opEncoded = (((cell.opcode + opBias) & 0xff) ^ opXor) & 0xff;
            int aEncoded = (cell.a ^ regXor) & 0xff;
            int bEncoded = (cell.b ^ regXor) & 0xff;
            int cEncoded = (cell.c ^ regXor) & 0xff;
            int immEncoded = Integer.rotateLeft(cell.imm ^ mask, rotate);
            int nextEncoded = cell.nextState ^ nextMask;
            int branchEncoded = cell.branchState ^ branchMask;
            int noise = RANDOM.nextInt();
            int guard = guard(source.id, mask, stateEncoded, opEncoded, aEncoded, bEncoded,
                    cEncoded, immEncoded, nextEncoded, branchEncoded, noise);
            cells.add(new Layer4Cell(stateEncoded, opEncoded, aEncoded, bEncoded, cEncoded,
                    immEncoded, nextEncoded, branchEncoded, guard, noise));
        }
        return new Layer4Program(source.id, source.registerCount, source.parameterCount,
                source.returnsValue, source.parameterSlots, source.entryState, mask,
                opXor, opBias, regXor, cells);
    }

    static int guard(int id, int mask, int stateEncoded, int opEncoded,
                     int aEncoded, int bEncoded, int cEncoded, int immEncoded,
                     int nextEncoded, int branchEncoded, int noise) {
        int packed = ((opEncoded & 0xff) << 24)
                | ((aEncoded & 0xff) << 16)
                | ((bEncoded & 0xff) << 8)
                | (cEncoded & 0xff);
        int value = 0x6D2B79F5 ^ id;
        value = Integer.rotateLeft(value ^ stateEncoded, 5) + 0x9E3779B9;
        value = Integer.rotateLeft(value ^ packed, 7) + immEncoded;
        value = Integer.rotateLeft(value ^ nextEncoded, 11) + branchEncoded;
        return Integer.rotateLeft(value ^ noise, 13) + mask;
    }

    private static boolean isBranch(int opcode) {
        return opcode == HighValueVmTransformer.OP_GOTO || isConditional(opcode);
    }

    private static boolean isConditional(int opcode) {
        return opcode >= HighValueVmTransformer.OP_IF_EQZ
                && opcode <= HighValueVmTransformer.OP_IF_LE;
    }

    private static boolean isReturn(int opcode) {
        return opcode == HighValueVmTransformer.OP_RETURN
                || opcode == HighValueVmTransformer.OP_RETURN_VOID;
    }

    private static final class Layer2Op {
        final int opcode, a, b, c, imm, target;
        Layer2Op(int opcode, int a, int b, int c, int imm, int target) {
            this.opcode = opcode; this.a = a; this.b = b; this.c = c;
            this.imm = imm; this.target = target;
        }
    }

    private static final class Layer2Program {
        final int id, registerCount, parameterCount;
        final boolean returnsValue;
        final int[] parameterSlots;
        final List<Layer2Op> ops;
        Layer2Program(int id, int registerCount, int parameterCount, boolean returnsValue,
                      int[] parameterSlots, List<Layer2Op> ops) {
            this.id = id; this.registerCount = registerCount; this.parameterCount = parameterCount;
            this.returnsValue = returnsValue; this.parameterSlots = parameterSlots; this.ops = ops;
        }
    }

    private static final class Layer3Cell {
        final int state, opcode, a, b, c, imm, nextState, branchState;
        Layer3Cell(int state, int opcode, int a, int b, int c, int imm,
                   int nextState, int branchState) {
            this.state = state; this.opcode = opcode; this.a = a; this.b = b; this.c = c;
            this.imm = imm; this.nextState = nextState; this.branchState = branchState;
        }
    }

    private static final class Layer3Program {
        final int id, registerCount, parameterCount;
        final boolean returnsValue;
        final int[] parameterSlots;
        final int entryState;
        final List<Layer3Cell> cells;
        Layer3Program(int id, int registerCount, int parameterCount, boolean returnsValue,
                      int[] parameterSlots, int entryState, List<Layer3Cell> cells) {
            this.id = id; this.registerCount = registerCount; this.parameterCount = parameterCount;
            this.returnsValue = returnsValue; this.parameterSlots = parameterSlots;
            this.entryState = entryState; this.cells = cells;
        }
    }

    private static final class Layer4Cell {
        final int stateEncoded, opEncoded, aEncoded, bEncoded, cEncoded;
        final int immEncoded, nextEncoded, branchEncoded, guard, noise;
        Layer4Cell(int stateEncoded, int opEncoded, int aEncoded, int bEncoded, int cEncoded,
                   int immEncoded, int nextEncoded, int branchEncoded, int guard, int noise) {
            this.stateEncoded = stateEncoded; this.opEncoded = opEncoded;
            this.aEncoded = aEncoded; this.bEncoded = bEncoded; this.cEncoded = cEncoded;
            this.immEncoded = immEncoded; this.nextEncoded = nextEncoded;
            this.branchEncoded = branchEncoded; this.guard = guard; this.noise = noise;
        }
    }

    private static final class Layer4Program {
        final int id, registerCount, parameterCount;
        final boolean returnsValue;
        final int[] parameterSlots;
        final int entryState, mask, opXor, opBias, regXor;
        final List<Layer4Cell> cells;
        Layer4Program(int id, int registerCount, int parameterCount, boolean returnsValue,
                      int[] parameterSlots, int entryState, int mask,
                      int opXor, int opBias, int regXor, List<Layer4Cell> cells) {
            this.id = id; this.registerCount = registerCount; this.parameterCount = parameterCount;
            this.returnsValue = returnsValue; this.parameterSlots = parameterSlots;
            this.entryState = entryState; this.mask = mask; this.opXor = opXor;
            this.opBias = opBias; this.regXor = regXor; this.cells = cells;
        }
    }
}
