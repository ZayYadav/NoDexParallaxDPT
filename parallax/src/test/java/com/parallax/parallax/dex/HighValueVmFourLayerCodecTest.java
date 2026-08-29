package com.parallax.parallax.dex;

import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

public class HighValueVmFourLayerCodecTest {

    @Test
    public void rawPayloadUsesFourLayerStateCellFormat() throws Exception {
        HighValueVmTransformer.Program program = new HighValueVmTransformer.Program(
                7, 3, 2, true,
                List.of(
                        new HighValueVmTransformer.VmOp(HighValueVmTransformer.OP_CONST, 0, 0, 0, 9, 0),
                        new HighValueVmTransformer.VmOp(HighValueVmTransformer.OP_ADD, 0, 1, 2, 0, 0),
                        new HighValueVmTransformer.VmOp(HighValueVmTransformer.OP_RETURN, 0, 0, 0, 0, 0)
                ));

        byte[] raw = HighValueVmFourLayerCodec.serialize(List.of(program));
        Assert.assertTrue(raw.length >= 36 + 3 * 28);
        Assert.assertArrayEquals(new byte[] {'P', 'V', 'R', '4'},
                new byte[] {raw[0], raw[1], raw[2], raw[3]});

        ByteBuffer buffer = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        buffer.position(4);
        Assert.assertEquals(1, buffer.getInt());
        Assert.assertEquals(7, buffer.getInt());
        Assert.assertEquals(3, buffer.getShort() & 0xffff);
        Assert.assertEquals(2, buffer.get() & 0xff);
        Assert.assertEquals(1, buffer.get() & 0xff);

        int slot0 = buffer.get() & 0xff;
        int slot1 = buffer.get() & 0xff;
        buffer.get();
        buffer.get();
        Assert.assertTrue(slot0 < 3);
        Assert.assertTrue(slot1 < 3);
        Assert.assertNotEquals(slot0, slot1);

        Assert.assertNotEquals(0, buffer.getInt()); // entry state
        int cellCount = buffer.getInt();
        Assert.assertTrue(cellCount >= 3);
        Assert.assertTrue(cellCount <= 9);
        Assert.assertNotEquals(0, buffer.getInt()); // mask
        buffer.get(); // opcode xor
        buffer.get(); // opcode bias
        buffer.get(); // register xor
        Assert.assertEquals(4, buffer.get() & 0xff);
        Assert.assertEquals(36 + cellCount * 28, raw.length);
    }

    @Test
    public void fourLayerEncodingIsRandomizedPerBuild() throws Exception {
        HighValueVmTransformer.Program program = new HighValueVmTransformer.Program(
                11, 1, 0, true,
                List.of(
                        new HighValueVmTransformer.VmOp(HighValueVmTransformer.OP_CONST, 0, 0, 0, 123, 0),
                        new HighValueVmTransformer.VmOp(HighValueVmTransformer.OP_RETURN, 0, 0, 0, 0, 0)
                ));
        byte[] first = HighValueVmFourLayerCodec.serialize(List.of(program));
        byte[] second = HighValueVmFourLayerCodec.serialize(List.of(program));
        Assert.assertFalse(java.util.Arrays.equals(first, second));
    }

    @Test
    public void cellGuardChangesWhenEncodedCellChanges() {
        int base = HighValueVmFourLayerCodec.guard(
                1, 0x12345678, 0x11111111, 4, 5, 6, 7,
                0x22222222, 0x33333333, 0x44444444, 0x55555555);
        int changed = HighValueVmFourLayerCodec.guard(
                1, 0x12345678, 0x11111111, 4, 5, 6, 7,
                0x22222223, 0x33333333, 0x44444444, 0x55555555);
        Assert.assertNotEquals(base, changed);
    }
}
