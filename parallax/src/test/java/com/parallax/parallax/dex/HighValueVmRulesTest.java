package com.parallax.parallax.dex;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class HighValueVmRulesTest {

    @Test
    public void exactAndWildcardRulesMatchCanonicalSignatures() throws Exception {
        Path rules = Files.createTempFile("parallax-high-value", ".rules");
        Files.writeString(rules,
                "# exact\n"
                        + "Lcom/example/Security;->mix(III)I\n"
                        + "Lcom/example/Math*;->scramble(II)I\n",
                StandardCharsets.UTF_8);
        try {
            List<HighValueVmTransformer.Rule> loaded = HighValueVmTransformer.loadRules(rules.toString());
            Assert.assertEquals(2, loaded.size());
            Assert.assertTrue(loaded.get(0).matches("Lcom/example/Security;->mix(III)I"));
            Assert.assertFalse(loaded.get(0).matches("Lcom/example/Security;->mix(II)I"));
            Assert.assertTrue(loaded.get(1).matches("Lcom/example/MathCore;->scramble(II)I"));
            HighValueVmTransformer.verifyAllRulesMatched(loaded);
        } finally {
            Files.deleteIfExists(rules);
        }
    }

    @Test(expected = java.io.IOException.class)
    public void unmatchedRulesFailClosed() throws Exception {
        Path rules = Files.createTempFile("parallax-high-value-unmatched", ".rules");
        Files.writeString(rules, "Lcom/example/Nope;->missing(I)I\n", StandardCharsets.UTF_8);
        try {
            HighValueVmTransformer.verifyAllRulesMatched(
                    HighValueVmTransformer.loadRules(rules.toString()));
        } finally {
            Files.deleteIfExists(rules);
        }
    }
}
