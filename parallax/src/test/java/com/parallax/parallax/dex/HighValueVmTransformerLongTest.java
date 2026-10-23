package com.parallax.parallax.dex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21lh;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21s;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;

import org.junit.Test;

import java.util.Collections;
import java.util.List;

public class HighValueVmTransformerLongTest {

    @Test
    public void constWideHigh16UsesSignExtendedHatLiteral() throws Exception {
        Method method = longMethod("high16", List.of(
                new ImmutableInstruction21lh(Opcode.CONST_WIDE_HIGH16, 0, 0x1234L << 48),
                new ImmutableInstruction11x(Opcode.RETURN_WIDE, 0)
        ));

        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                1, "Lsample/LongOps;->high16()J", method);

        HighValueVmTransformer.VmOp op = program.ops.get(0);
        assertEquals(HighValueVmTransformer.OP_CONST_WIDE, op.opcode);
        assertEquals(0, op.imm);
        assertEquals(0x12340000, op.target);
    }

    @Test
    public void constWide16SignExtends() throws Exception {
        Method method = longMethod("negative", List.of(
                new ImmutableInstruction21s(Opcode.CONST_WIDE_16, 0, (short) -2),
                new ImmutableInstruction11x(Opcode.RETURN_WIDE, 0)
        ));

        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                2, "Lsample/LongOps;->negative()J", method);

        HighValueVmTransformer.VmOp op = program.ops.get(0);
        assertEquals(HighValueVmTransformer.OP_CONST_WIDE, op.opcode);
        assertEquals(-2, op.imm);
        assertEquals(-1, op.target);
    }

    @Test
    public void constWide32SignExtends() throws Exception {
        Method method = longMethod("negative", List.of(
                new ImmutableInstruction31i(Opcode.CONST_WIDE_32, 0, 0x89ABCDEF),
                new ImmutableInstruction11x(Opcode.RETURN_WIDE, 0)
        ));

        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                3, "Lsample/LongOps;->negative()J", method);

        HighValueVmTransformer.VmOp op = program.ops.get(0);
        assertEquals(HighValueVmTransformer.OP_CONST_WIDE, op.opcode);
        assertEquals(0x89ABCDEF, op.imm);
        assertEquals(0xFFFFFFFF, op.target);
    }

    private static Method longMethod(String name, List<Instruction> instructions) {
        Method method = new ImmutableMethod(
                "Lsample/LongOps;",
                name,
                Collections.emptyList(),
                "J",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                null,
                null,
                new ImmutableMethodImplementation(1, instructions, null, null)
        );
        assertNotNull(method.getImplementation());
        return method;
    }
}
