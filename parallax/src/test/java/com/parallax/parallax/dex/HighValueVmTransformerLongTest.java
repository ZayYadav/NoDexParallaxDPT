package com.parallax.parallax.dex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21lh;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21s;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;

import org.junit.Test;

import java.util.ArrayList;
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

    @Test
    public void floatParametersUseFloatBridgeTypes() throws Exception {
        Method method = method("scale", List.of("F", "F"), "F", 3, List.of(
                new ImmutableInstruction11x(Opcode.RETURN, 0)
        ));

        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                6, "Lsample/LongOps;->scale(FF)F", method);

        assertEquals(2, program.parameterRegisters);
        assertEquals(10, program.parameterTypes);
        assertEquals(HighValueVmTransformer.Program.RETURN_FLOAT, program.returnType);
    }

    @Test
    public void doubleParametersUseWidePairs() throws Exception {
        Method method = method("scale", List.of("D", "D"), "D", 5, List.of(
                new ImmutableInstruction11x(Opcode.RETURN_WIDE, 0)
        ));

        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                7, "Lsample/LongOps;->scale(DD)D", method);

        assertEquals(4, program.parameterRegisters);
        assertEquals(15, program.parameterTypes);
        assertEquals(HighValueVmTransformer.Program.RETURN_DOUBLE, program.returnType);
    }

    @Test
    public void mixedIntAndFloatParametersUseDoubleBridge() throws Exception {
        Method method = method("blend", List.of("I", "F"), "F", 3, List.of(
                new ImmutableInstruction11x(Opcode.RETURN, 0)
        ));
        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                8, "Lsample/LongOps;->blend(IF)F", method);
        assertEquals(2, program.parameterCount);
        assertEquals(2, program.parameterRegisters);
        assertEquals(8, program.parameterTypes);
        assertEquals(HighValueVmTransformer.Program.RETURN_FLOAT, program.returnType);
        assertEquals(true, program.doubleArguments);
    }

    @Test
    public void doubleParametersCanReturnFloat() throws Exception {
        Method method = method("narrow", List.of("D"), "F", 3, List.of(
                new ImmutableInstruction11x(Opcode.RETURN, 0)
        ));
        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                9, "Lsample/LongOps;->narrow(D)F", method);
        assertEquals(HighValueVmTransformer.Program.RETURN_FLOAT, program.returnType);
        assertEquals(true, program.doubleArguments);
    }

    @Test(expected = java.io.IOException.class)
    public void longAndFloatingParametersCannotMix() throws Exception {
        Method method = method("invalid", List.of("J", "F"), "F", 4, List.of(
                new ImmutableInstruction11x(Opcode.RETURN, 0)
        ));
        HighValueVmTransformer.compile(10, "Lsample/LongOps;->invalid(JF)F", method);
    }

    @Test
    public void mixedIntAndLongParametersAreAccepted() throws Exception {
        Method method = method("mixed", List.of("I", "J"), "J", 4, List.of(
                new ImmutableInstruction11x(Opcode.RETURN_WIDE, 0)
        ));

        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                4, "Lsample/LongOps;->mixed(IJ)J", method);

        assertEquals(2, program.parameterCount);
        assertEquals(3, program.parameterRegisters);
        assertEquals(4, program.parameterTypes);
        assertEquals(HighValueVmTransformer.Program.RETURN_LONG, program.returnType);
    }

    @Test
    public void mixedParametersCanReturnInt() throws Exception {
        Method method = method("mixedInt", List.of("J", "I"), "I", 4, List.of(
                new ImmutableInstruction11x(Opcode.RETURN, 0)
        ));

        HighValueVmTransformer.Program program = HighValueVmTransformer.compile(
                5, "Lsample/LongOps;->mixedInt(JI)I", method);

        assertEquals(3, program.parameterRegisters);
        assertEquals(1, program.parameterTypes);
        assertEquals(HighValueVmTransformer.Program.RETURN_INT, program.returnType);
    }

    private static Method longMethod(String name, List<Instruction> instructions) {
        return method(name, Collections.emptyList(), "J", 1, instructions);
    }

    private static Method method(String name, List<String> parameterTypes, String returnType,
                                 int registers, List<Instruction> instructions) {
        List<ImmutableMethodParameter> parameters = new ArrayList<>();
        for (String type : parameterTypes) {
            parameters.add(new ImmutableMethodParameter(type, null, null));
        }
        Method method = new ImmutableMethod(
                "Lsample/LongOps;",
                name,
                parameters,
                returnType,
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                null,
                null,
                new ImmutableMethodImplementation(registers, instructions, null, null)
        );
        assertNotNull(method.getImplementation());
        return method;
    }
}
