package com.parallax.parallax.dex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AutomaticVmSelectorTest {
    @Test
    public void ordinarySupportedMethodUsesClassicVm() {
        assertEquals(AutomaticVmSelector.Tier.VM,
                AutomaticVmSelector.classify(12, 0, 4, false));
    }

    @Test
    public void branchHeavyMethodUsesVm4() {
        assertEquals(AutomaticVmSelector.Tier.VM4,
                AutomaticVmSelector.classify(20, 3, 5, false));
    }

    @Test
    public void sensitiveMethodUsesVm4EvenWhenSmall() {
        assertEquals(AutomaticVmSelector.Tier.VM4,
                AutomaticVmSelector.classify(8, 0, 2, true));
    }

    @Test
    public void automaticSelectionHasHardPerformanceCaps() {
        assertTrue(AutomaticVmSelector.MAX_VM4_METHODS < AutomaticVmSelector.MAX_TOTAL_METHODS);
        assertTrue(AutomaticVmSelector.MAX_INSTRUCTIONS >= AutomaticVmSelector.MIN_INSTRUCTIONS);
    }
}
