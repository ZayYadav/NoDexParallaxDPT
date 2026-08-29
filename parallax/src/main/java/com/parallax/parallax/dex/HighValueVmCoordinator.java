package com.parallax.parallax.dex;

import com.parallax.parallax.config.Const;
import com.parallax.parallax.util.LogUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/** Build-process coordinator for the opt-in high-value native VM tier. */
public final class HighValueVmCoordinator {
    private static final String FIXED_VM_BRIDGE_SIG = "LParallax/Enc/CrackWarTeamMC;";
    private static volatile String rulesPath;
    private static boolean prepared;

    private HighValueVmCoordinator() {}

    public static synchronized void setRulesPath(String value) {
        rulesPath = value == null || value.trim().isEmpty() ? null : value.trim();
        prepared = false;
    }

    public static boolean isEnabled() {
        return rulesPath != null;
    }

    public static String getRulesPath() {
        return rulesPath;
    }

    /**
     * Called from KeyUtils.generateKey(), which is the APK pipeline's main-thread choke point:
     * the package is already unzipped, while DEX gate injection/hollowing has not started yet.
     * This avoids the legacy worker path that intentionally tolerates ordinary gate-injection
     * errors. High-value conversion is never allowed to silently fall back.
     */
    public static synchronized int prepareCurrentWorkspace(byte[] encKey) throws IOException {
        if (!isEnabled() || prepared) return 0;
        if (encKey == null || encKey.length != 16) {
            throw new IOException("High-value VM requires the 16-byte APK build key");
        }

        File workspace = new File(Const.ROOT_OF_OUT_DIR, "parallaxOut-" + Const.RANDOM_DIR_NAME);
        if (!workspace.isDirectory()) {
            throw new IOException("High-value VM workspace is not ready: " + workspace);
        }

        File[] candidates = workspace.listFiles(file -> file.isFile()
                && file.getName().matches("classes\\d*\\.dex"));
        if (candidates == null || candidates.length == 0) {
            throw new IOException("High-value VM enabled but APK workspace contains no DEX files");
        }

        List<File> dexFiles = new ArrayList<>(Arrays.asList(candidates));
        dexFiles.sort(Comparator.comparing(File::getName));
        List<HighValueVmTransformer.Rule> rules = HighValueVmTransformer.loadRules(rulesPath);
        List<HighValueVmTransformer.Program> programs = new ArrayList<>();
        int nextId = 1;

        for (File dex : dexFiles) {
            File rewritten = new File(dex.getAbsolutePath() + ".pvm.dex");
            try {
                HighValueVmTransformer.Result result = HighValueVmTransformer.transform(
                        dex, rewritten, rules, nextId, FIXED_VM_BRIDGE_SIG);
                nextId = result.getNextMethodId();
                programs.addAll(result.getPrograms());
                if (!result.getPrograms().isEmpty()) {
                    Files.move(rewritten.toPath(), dex.toPath(), StandardCopyOption.REPLACE_EXISTING);
                } else {
                    Files.deleteIfExists(rewritten.toPath());
                }
            } finally {
                Files.deleteIfExists(rewritten.toPath());
            }
        }

        HighValueVmTransformer.verifyAllRulesMatched(rules);
        if (programs.isEmpty()) {
            throw new IOException("High-value VM was enabled but no methods were converted");
        }

        File assets = new File(workspace, "assets");
        if (!assets.isDirectory() && !assets.mkdirs()) {
            throw new IOException("Cannot create assets directory for high-value VM payload");
        }
        File payload = new File(assets, "Parallax.vm");
        HighValueVmFourLayerCodec.writeEncryptedPayload(payload, programs, encKey);
        prepared = true;
        LogUtils.info("High-value 4-layer VM prepared before DPT extraction: %d method(s)", programs.size());
        return programs.size();
    }
}
