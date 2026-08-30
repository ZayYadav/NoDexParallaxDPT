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

/** Build-process coordinator for automatic classic-VM and four-layer-VM protection. */
public final class HighValueVmCoordinator {
    private static final String FIXED_VM_BRIDGE_SIG = "LParallax/Enc/CrackWarTeamMC;";
    private static final int VM4_ID_BASE = 0x40000001;
    private static final String VM4_ASSET = "Parallax.vm";
    private static final String CLASSIC_VM_ASSET = "Parallax.vmc";

    private static volatile String rulesPath;
    private static boolean prepared;

    private HighValueVmCoordinator() {}

    public static synchronized void setRulesPath(String value) {
        rulesPath = value == null || value.trim().isEmpty() ? null : value.trim();
        prepared = false;
    }

    /** True only for the legacy explicit-rules switch; automatic APK routing is always on. */
    public static boolean isEnabled() {
        return rulesPath != null;
    }

    public static String getRulesPath() {
        return rulesPath;
    }

    /**
     * Runs at the APK pipeline's pre-hollowing choke point. With explicit rules we preserve
     * the old fail-closed behavior and route every selected method to VM4. Without rules the
     * selector automatically splits verifier-safe methods between classic VM and VM4.
     *
     * AAB calls KeyUtils before its DEX workspace exists; zero-config mode therefore returns
     * quietly when no unpacked APK DEX is present. Explicit mode remains APK-only and strict.
     */
    public static synchronized int prepareCurrentWorkspace(byte[] encKey) throws IOException {
        if (prepared) return 0;
        if (encKey == null || encKey.length != 16) {
            throw new IOException("High-value VM requires the 16-byte APK build key");
        }

        boolean explicit = isEnabled();
        File workspace = new File(Const.ROOT_OF_OUT_DIR, "parallaxOut-" + Const.RANDOM_DIR_NAME);
        if (!workspace.isDirectory()) {
            if (explicit) throw new IOException("High-value VM workspace is not ready: " + workspace);
            return 0;
        }

        File[] candidates = workspace.listFiles(file -> file.isFile()
                && file.getName().matches("classes\\d*\\.dex"));
        if (candidates == null || candidates.length == 0) {
            if (explicit) {
                throw new IOException("High-value VM enabled but APK workspace contains no DEX files");
            }
            return 0;
        }

        List<File> dexFiles = new ArrayList<>(Arrays.asList(candidates));
        dexFiles.sort(Comparator.comparing(File::getName));
        return explicit
                ? prepareExplicitVm4(workspace, dexFiles, encKey)
                : prepareAutomaticMixed(workspace, dexFiles, encKey);
    }

    private static int prepareExplicitVm4(File workspace, List<File> dexFiles, byte[] encKey)
            throws IOException {
        List<HighValueVmTransformer.Rule> rules = HighValueVmTransformer.loadRules(rulesPath);
        List<HighValueVmTransformer.Program> programs = new ArrayList<>();
        int nextId = VM4_ID_BASE;

        for (File dex : dexFiles) {
            File rewritten = new File(dex.getAbsolutePath() + ".pvm4.dex");
            try {
                HighValueVmTransformer.Result result = HighValueVmTransformer.transform(
                        dex, rewritten, rules, nextId, FIXED_VM_BRIDGE_SIG);
                nextId = result.getNextMethodId();
                programs.addAll(result.getPrograms());
                if (!result.getPrograms().isEmpty()) {
                    Files.move(rewritten.toPath(), dex.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(rewritten.toPath());
            }
        }

        HighValueVmTransformer.verifyAllRulesMatched(rules);
        if (programs.isEmpty()) {
            throw new IOException("High-value VM was enabled but no methods were converted");
        }

        File assets = ensureAssets(workspace);
        HighValueVmFourLayerCodec.writeEncryptedPayload(new File(assets, VM4_ASSET), programs, encKey);
        Files.deleteIfExists(new File(assets, CLASSIC_VM_ASSET).toPath());
        prepared = true;
        LogUtils.info("Explicit high-value VM4 prepared before DPT extraction: %d method(s)",
                programs.size());
        return programs.size();
    }

    private static int prepareAutomaticMixed(File workspace, List<File> dexFiles, byte[] encKey)
            throws IOException {
        AutomaticVmSelector.Selection selection = AutomaticVmSelector.select(dexFiles);
        if (selection.getSelectedCount() == 0) {
            prepared = true;
            LogUtils.info("Automatic VM routing: no safe eligible methods; normal DPT path retained.");
            return 0;
        }

        List<HighValueVmTransformer.Program> vmPrograms = new ArrayList<>();
        List<HighValueVmTransformer.Program> vm4Programs = new ArrayList<>();
        int nextVmId = 1;
        int nextVm4Id = VM4_ID_BASE;

        for (File dex : dexFiles) {
            File original = new File(dex.getAbsolutePath() + ".auto-vm.orig");
            File vm4Rewritten = new File(dex.getAbsolutePath() + ".auto-vm4.dex");
            File vmRewritten = new File(dex.getAbsolutePath() + ".auto-vm.dex");
            int vmStartSize = vmPrograms.size();
            int vm4StartSize = vm4Programs.size();
            int vmIdBefore = nextVmId;
            int vm4IdBefore = nextVm4Id;
            Files.copy(dex.toPath(), original.toPath(), StandardCopyOption.REPLACE_EXISTING);

            try {
                if (!selection.getVm4Rules().isEmpty()) {
                    HighValueVmTransformer.Result result = HighValueVmTransformer.transform(
                            dex, vm4Rewritten, selection.getVm4Rules(), nextVm4Id,
                            FIXED_VM_BRIDGE_SIG);
                    nextVm4Id = result.getNextMethodId();
                    vm4Programs.addAll(result.getPrograms());
                    if (!result.getPrograms().isEmpty()) {
                        Files.move(vm4Rewritten.toPath(), dex.toPath(),
                                StandardCopyOption.REPLACE_EXISTING);
                    }
                }

                if (!selection.getVmRules().isEmpty()) {
                    HighValueVmTransformer.Result result = HighValueVmTransformer.transform(
                            dex, vmRewritten, selection.getVmRules(), nextVmId,
                            FIXED_VM_BRIDGE_SIG);
                    nextVmId = result.getNextMethodId();
                    vmPrograms.addAll(result.getPrograms());
                    if (!result.getPrograms().isEmpty()) {
                        Files.move(vmRewritten.toPath(), dex.toPath(),
                                StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            } catch (IOException automaticFailure) {
                // Automatic mode is deliberately fail-soft per DEX: restore the untouched DEX,
                // discard programs produced for it, and let the normal DPT pipeline protect it.
                Files.copy(original.toPath(), dex.toPath(), StandardCopyOption.REPLACE_EXISTING);
                vmPrograms.subList(vmStartSize, vmPrograms.size()).clear();
                vm4Programs.subList(vm4StartSize, vm4Programs.size()).clear();
                nextVmId = vmIdBefore;
                nextVm4Id = vm4IdBefore;
                LogUtils.info("Automatic VM fallback for %s: %s", dex.getName(),
                        automaticFailure.getMessage());
            } finally {
                Files.deleteIfExists(original.toPath());
                Files.deleteIfExists(vm4Rewritten.toPath());
                Files.deleteIfExists(vmRewritten.toPath());
            }
        }

        int total = vmPrograms.size() + vm4Programs.size();
        if (total == 0) {
            prepared = true;
            LogUtils.info("Automatic VM routing safely fell back to normal DPT for all candidates.");
            return 0;
        }

        File assets = ensureAssets(workspace);
        File classicPayload = new File(assets, CLASSIC_VM_ASSET);
        File vm4Payload = new File(assets, VM4_ASSET);
        if (vmPrograms.isEmpty()) Files.deleteIfExists(classicPayload.toPath());
        else HighValueVmTransformer.writeEncryptedPayload(classicPayload, vmPrograms, encKey);
        if (vm4Programs.isEmpty()) Files.deleteIfExists(vm4Payload.toPath());
        else HighValueVmFourLayerCodec.writeEncryptedPayload(vm4Payload, vm4Programs, encKey);

        prepared = true;
        LogUtils.info(
                "Automatic VM routing complete: VM=%d VM4=%d selected=%d eligible=%d; unsupported methods remain on normal DPT.",
                vmPrograms.size(), vm4Programs.size(), selection.getSelectedCount(),
                selection.getEligibleCount());
        return total;
    }

    private static File ensureAssets(File workspace) throws IOException {
        File assets = new File(workspace, "assets");
        if (!assets.isDirectory() && !assets.mkdirs()) {
            throw new IOException("Cannot create assets directory for high-value VM payload");
        }
        return assets;
    }
}
