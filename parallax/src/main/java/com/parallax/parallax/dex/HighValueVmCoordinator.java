package com.parallax.parallax.dex;

import com.parallax.parallax.util.LogUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Build-process coordinator for the opt-in high-value native VM tier. */
public final class HighValueVmCoordinator {
    private static volatile String rulesPath;

    private HighValueVmCoordinator() {}

    public static void setRulesPath(String value) {
        rulesPath = value == null || value.trim().isEmpty() ? null : value.trim();
    }

    public static boolean isEnabled() {
        return rulesPath != null;
    }

    public static String getRulesPath() {
        return rulesPath;
    }

    public static int prepare(List<File> dexFiles, File payloadFile, byte[] encKey,
                              String jniClassSig) throws IOException {
        if (!isEnabled()) return 0;
        List<HighValueVmTransformer.Rule> rules = HighValueVmTransformer.loadRules(rulesPath);
        List<HighValueVmTransformer.Program> programs = new ArrayList<>();
        List<File> ordered = new ArrayList<>(dexFiles);
        ordered.sort(Comparator.comparing(File::getName));
        int nextId = 1;

        for (File dex : ordered) {
            File rewritten = new File(dex.getAbsolutePath() + ".pvm.dex");
            HighValueVmTransformer.Result result = HighValueVmTransformer.transform(
                    dex, rewritten, rules, nextId, jniClassSig);
            nextId = result.getNextMethodId();
            programs.addAll(result.getPrograms());
            if (!result.getPrograms().isEmpty()) {
                Files.move(rewritten.toPath(), dex.toPath(), StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.deleteIfExists(rewritten.toPath());
            }
        }

        HighValueVmTransformer.verifyAllRulesMatched(rules);
        if (programs.isEmpty()) {
            throw new IOException("High-value VM was enabled but no methods were converted");
        }
        HighValueVmTransformer.writeEncryptedPayload(payloadFile, programs, encKey);
        LogUtils.info("High-value VM prepared before DPT hollowing: %d method(s)", programs.size());
        return programs.size();
    }
}
