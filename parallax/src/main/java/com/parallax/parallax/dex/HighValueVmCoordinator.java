package com.parallax.parallax.dex;

import com.parallax.parallax.config.Const;
import com.parallax.parallax.res.ApkManifestEditor;
import com.parallax.parallax.util.LogUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/** Build-process coordinator for the selective high-value native VM tier. */
public final class HighValueVmCoordinator {
    private static final String FIXED_VM_BRIDGE_SIG = "LParallax/Enc/CrackWarTeamMC;";

    /** Must stay in sync with shell/src/main/cpp/parallax_vm4.cpp::kMaxPrograms. */
    public static final int MAX_VM_PROGRAMS = 4096;

    /**
     * PVM4 can inject up to two decoy cells per semantic op. Keeping automatic selection
     * below this budget guarantees the worst-case encoded cell stream remains below the
     * native 16 MiB payload ceiling with room for per-program headers and the envelope.
     */
    public static final int MAX_AUTO_SEMANTIC_OPS = 175000;

    /**
     * Automatic discovery must never rewrite platform/framework/runtime infrastructure merely
     * because a tiny helper happens to fit the scalar VM opcode subset. Those methods can be
     * bootstrap critical and are not application business logic.
     */
    private static final String[] AUTO_DENY_CLASS_PREFIXES = {
            "Landroid/",
            "Landroidx/",
            "Ljava/",
            "Ljavax/",
            "Lkotlin/",
            "Lkotlinx/",
            "Lcom/google/",
            "Lcom/mundo/",
            "LParallax/",
            "Lcom/parallax/"
    };

    private static volatile String rulesPath;
    private static volatile boolean autoEnabled;
    private static volatile int autoMaxPrograms = MAX_VM_PROGRAMS;
    private static boolean prepared;

    private HighValueVmCoordinator() {}

    /** Backward-compatible manual-rules configuration. */
    public static synchronized void setRulesPath(String value) {
        configure(value, false, MAX_VM_PROGRAMS);
    }

    public static synchronized void configure(String value, boolean enableAuto, int maxPrograms) {
        String normalized = value == null || value.trim().isEmpty() ? null : value.trim();
        if (normalized != null && enableAuto) {
            throw new IllegalArgumentException(
                    "--high-value-methods and --high-value-auto are mutually exclusive");
        }
        if (maxPrograms < 1 || maxPrograms > MAX_VM_PROGRAMS) {
            throw new IllegalArgumentException(
                    "High-value auto max must be between 1 and " + MAX_VM_PROGRAMS);
        }
        rulesPath = normalized;
        autoEnabled = enableAuto;
        autoMaxPrograms = maxPrograms;
        prepared = false;
    }

    public static boolean isEnabled() {
        return rulesPath != null || autoEnabled;
    }

    public static boolean isAutoEnabled() {
        return autoEnabled;
    }

    public static String getRulesPath() {
        return rulesPath;
    }

    public static int getAutoMaxPrograms() {
        return autoMaxPrograms;
    }

    /**
     * Called from KeyUtils.generateKey(), which is the APK pipeline's main-thread choke point:
     * the package is already unzipped, while DEX gate injection/hollowing has not started yet.
     * Manual mode is fail-closed. Auto mode probes methods first and only selects compiler-safe,
     * application-owned methods, so unsupported/framework/runtime methods continue through DPT.
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

        List<HighValueVmTransformer.Rule> rules;
        if (autoEnabled) {
            rules = discoverAutoRules(workspace, dexFiles);
            if (rules.isEmpty()) {
                prepared = true;
                LogUtils.info("High-value AUTO VM: no runtime-safe app-owned candidates; continuing with normal DPT only.");
                return 0;
            }
        } else {
            rules = HighValueVmTransformer.loadRules(rulesPath);
        }

        List<HighValueVmTransformer.Program> programs = new ArrayList<>();
        int nextId = 1;

        for (File dex : dexFiles) {
            File rewritten = new File(dex.getAbsolutePath() + ".pvm.dex");
            try {
                HighValueVmTransformer.Result result = HighValueVmTransformer.transform(
                        dex, rewritten, rules, nextId, FIXED_VM_BRIDGE_SIG);
                nextId = result.getNextMethodId();
                programs.addAll(result.getPrograms());
                if (programs.size() > MAX_VM_PROGRAMS) {
                    throw new IOException("High-value VM program count exceeds native limit: "
                            + programs.size());
                }
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
            if (autoEnabled) {
                prepared = true;
                LogUtils.info("High-value AUTO VM selected no methods after verification; normal DPT remains active.");
                return 0;
            }
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

    /** Package-private for regression tests. */
    static boolean isAutoRuleAllowedForPackage(String signature, String packageName) {
        if (signature == null || packageName == null) return false;
        String normalizedPackage = packageName.trim();
        if (normalizedPackage.isEmpty()) return false;

        String appPrefix = "L" + normalizedPackage.replace('.', '/') + "/";
        if (!signature.startsWith(appPrefix)) return false;

        for (String denied : AUTO_DENY_CLASS_PREFIXES) {
            if (signature.startsWith(denied)) return false;
        }
        return true;
    }

    private static List<HighValueVmTransformer.Rule> discoverAutoRules(
            File workspace, List<File> dexFiles) throws IOException {
        File manifest = new File(workspace, "AndroidManifest.xml");
        String packageName = manifest.isFile()
                ? ApkManifestEditor.getPackageName(manifest.getAbsolutePath())
                : null;
        if (packageName == null || packageName.trim().isEmpty()) {
            LogUtils.warn("High-value AUTO VM: package name unavailable; automatic virtualization disabled for runtime safety.");
            return new ArrayList<>();
        }

        String appDexPrefix = "L" + packageName.trim().replace('.', '/') + "/";
        LogUtils.info("High-value AUTO VM runtime-safe scope: %s", appDexPrefix);

        List<HighValueVmTransformer.Rule> rules = new ArrayList<>();
        int remainingPrograms = autoMaxPrograms;
        int remainingOps = MAX_AUTO_SEMANTIC_OPS;
        int scanned = 0;
        int compilerCompatible = 0;
        int unsupported = 0;
        int rejectedByScope = 0;
        int deferred = 0;
        int probeOps = 0;

        for (File dex : dexFiles) {
            if (remainingPrograms <= 0 || remainingOps <= 0) break;

            HighValueVmTransformer.AutoScanResult scan = HighValueVmTransformer.scanAutoCandidates(
                    dex, MAX_VM_PROGRAMS, remainingOps);
            scanned += scan.getScanned();
            compilerCompatible += scan.getCompatible();
            unsupported += scan.getUnsupported();
            probeOps += scan.getSelectedOps();

            for (HighValueVmTransformer.Rule rule : scan.getRules()) {
                if (!isAutoRuleAllowedForPackage(rule.getSource(), packageName)) {
                    rejectedByScope++;
                    continue;
                }
                if (remainingPrograms <= 0) {
                    deferred++;
                    continue;
                }
                rules.add(rule);
                remainingPrograms--;
            }

            // Conservative accounting: probe ops include candidates later rejected by scope.
            // This can reduce coverage, never exceed the native payload safety budget.
            remainingOps = Math.max(0, remainingOps - scan.getSelectedOps());
            deferred += scan.getDeferredByLimit();
        }

        LogUtils.info(
                "High-value AUTO VM report: scanned=%d compilerCompatible=%d appOwnedVirtualized=%d "
                        + "unsupported=%d rejectedByRuntimeScope=%d deferredBySafetyLimit=%d probeSemanticOps=%d/%d",
                scanned, compilerCompatible, rules.size(), unsupported, rejectedByScope, deferred,
                probeOps, MAX_AUTO_SEMANTIC_OPS);
        if (rejectedByScope > 0) {
            LogUtils.info(
                    "High-value AUTO VM kept %d compiler-compatible dependency/runtime method(s) on normal DPT.",
                    rejectedByScope);
        }
        if (deferred > 0) {
            LogUtils.warn(
                    "High-value AUTO VM deferred %d candidate method(s) to normal DPT to stay within native limits.",
                    deferred);
        }
        return rules;
    }
}
