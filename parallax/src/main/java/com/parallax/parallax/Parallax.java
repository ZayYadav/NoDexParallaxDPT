package com.parallax.parallax;

import com.android.dx.command.dexer.Main;
import com.parallax.parallax.builder.Aab;
import com.parallax.parallax.builder.AndroidPackage;
import com.parallax.parallax.builder.Apk;
import com.parallax.parallax.config.Const;
import com.parallax.parallax.dex.HighValueVmCoordinator;
import com.parallax.parallax.util.*;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.Manifest;

public class Parallax {

    private static final String MANIFEST_BUILD_KEY_ATTR = "Parallax-Build-Key";
    private static final String OPTION_HIGH_VALUE_METHODS = "high-value-methods";
    private static String expectedSignSha256;

    public static void main(String[] args) {
        try {
            AndroidPackage androidPackage = parseOptions(args);
            if(androidPackage == null) {
                return;
            }
            androidPackage.protect();
        } catch (Exception e){
            e.printStackTrace();
            // A failed protection run must not look like a successful build to CI or scripts.
            System.exit(1);
        }
    }

    private static void usage(Options options, String msg) {
        System.err.println("Error: " + msg);
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp("java -jar parallax.jar [option] -f <package_file>",options);
        System.exit(1);
    }

    private static void printVersion() {
        System.out.println(getVersion());
    }

    public static String getVersion() {
        Package pkg = Parallax.class.getPackage();
        String version = (pkg != null) ? pkg.getImplementationVersion() : null;
        if (version == null) {
            version = "unknown";
        }
        return version;
    }

    static void setExpectedSignSha256(String sha256) {
        expectedSignSha256 = sha256;
    }

    public static String getExpectedSignSha256() {
        return expectedSignSha256;
    }

    public static String getBuildKey() {
        // Prefer the key written next to shell SO artifacts so encrypt side
        // always matches the native binary being packaged.
        String executablePath = FileUtils.getExecutablePath();
        if (executablePath != null && !executablePath.isEmpty()) {
            File keyFile = new File(executablePath,
                    "shell-files" + File.separator + Const.KEY_BUILD_KEY_FILE_NAME);
            if (keyFile.isFile()) {
                try {
                    String value = Files.readString(keyFile.toPath(), StandardCharsets.UTF_8).trim();
                    if (!value.isEmpty()) {
                        return value;
                    }
                } catch (IOException ignored) {
                    // fall through to jar manifest
                }
            }
        }

        try {
            ClassLoader classLoader = Parallax.class.getClassLoader();
            if (classLoader == null) {
                return null;
            }
            Enumeration<URL> resources = classLoader.getResources("META-INF/MANIFEST.MF");
            while (resources.hasMoreElements()) {
                try (InputStream is = resources.nextElement().openStream()) {
                    String value = new Manifest(is).getMainAttributes().getValue(MANIFEST_BUILD_KEY_ATTR);
                    if (value != null && !value.isEmpty()) {
                        return value;
                    }
                }
            }
        } catch (IOException ignored) {
            // fall through
        }
        return null;
    }

    private static AndroidPackage parseOptions(String[] args) {
        Options options = new Options();
        options.addOption(new Option(Const.OPTION_VERSION, Const.OPTION_VERSION_LONG, false, "Show program's version number."));
        options.addOption(new Option(Const.OPTION_NO_SIGN_PACKAGE, Const.OPTION_NO_SIGN_PACKAGE_LONG, false, "Do not sign package."));
        options.addOption(new Option(null, Const.OPTION_DUMP_CODE_LONG, false, "Dump the code item of DEX and save it to .json files."));
        options.addOption(new Option(null, Const.OPTION_OPEN_NOISY_LOG_LONG, false, "Open noisy log."));
        options.addOption(new Option(Const.OPTION_INPUT_FILE, Const.OPTION_INPUT_FILE_LONG, true, "Need to protect android package(*.apk, *.aab) file."));
        options.addOption(new Option(null, Const.OPTION_DEBUGGABLE_LONG, false, "Make package debuggable."));
        options.addOption(new Option(null, Const.OPTION_DISABLE_APP_COMPONENT_FACTORY_LONG, false, "Disable app component factory(just use for debug)."));
        options.addOption(new Option(Const.OPTION_OUTPUT_PATH, Const.OPTION_OUTPUT_PATH_LONG, true, "Output directory for protected package."));
        options.addOption(new Option(Const.OPTION_DO_NOT_PROTECT_CLASSES_RULES, Const.OPTION_DO_NOT_PROTECT_CLASSES_RULES_LONG, true, "Rules file for class names that will not be protected.\n"));
        options.addOption(new Option(Const.OPTION_KEEP_CLASSES, Const.OPTION_KEEP_CLASSES_LONG, false, "Keeping some classes in the package can improve the app's startup speed to a certain extent, but it is not supported by some application packages.\n"));
        options.addOption(new Option(Const.OPTION_SMALLER, Const.OPTION_SMALLER_LONG, false, "Trade some of the app's performance for a smaller app size.\n"));
        options.addOption(new Option(Const.OPTION_PROTECT_CONFIG, Const.OPTION_PROTECT_CONFIG_LONG, true, "Protect config file.\n"));
        options.addOption(new Option(null, OPTION_HIGH_VALUE_METHODS, true,
                "Move explicitly selected static primitive methods out of DEX into the encrypted native Parallax VM. "
                        + "Rules use canonical signatures such as Lcom/example/Security;->mix(III)I. APK only.\n"));
        options.addOption(new Option(Const.OPTION_EXCLUDE_ABI, Const.OPTION_EXCLUDE_ABI_LONG, true, "Exclude specific ABIs (comma separated, e.g. x86,x86_64). \n"
                + "Supported ABIs:\n"
                + "- arm       (armeabi-v7a)\n"
                + "- arm64     (arm64-v8a)\n"
                + "- x86\n"
                + "- x86_64"));
        options.addOption(new Option(Const.OPTION_VERIFY_SIGN, Const.OPTION_VERIFY_SIGN_LONG, false, "Enable runtime app signature verification. The certificate SHA-256 is computed automatically from the signing keystore.\n"));
        options.addOption(new Option(null, Const.OPTION_EXPECT_SIGN_LONG, true,
                "Expected signing certificate SHA-256 for runtime pinning. Use when the APK will be re-signed after protection with your own keystore; the payload seal and runtime checks bind to this certificate instead of the temporary protection key.\n"));
        options.addOption(new Option(null, Const.OPTION_ONE_WAY_LONG, false,
                "One-way seal: refuse already-protected inputs, forbid -K/--keep-classes, force signature "
                        + "pinning and every runtime check, audit the output for original DEX bytes, and "
                        + "securely erase protection workspaces. APK only.\n"));
        options.addOption(new Option(null, Const.OPTION_DISABLE_FRIDA_DETECT_LONG, false, "Disable runtime Frida detection.\n"));
        options.addOption(new Option(null, Const.OPTION_DISABLE_CRC_DETECT_LONG, false, "Disable runtime libc .text CRC detection.\n"));
        options.addOption(new Option(null, Const.OPTION_DISABLE_ANTI_DEBUG_LONG, false, "Disable runtime anti-debug.\n"));

        CommandLineParser commandLineParser = new DefaultParser();
        try {
            CommandLine commandLine = commandLineParser.parse(options, args);

            if(commandLine.hasOption(Const.OPTION_VERSION)) {
                printVersion();
                return null;
            }

            if(!commandLine.hasOption(Const.OPTION_INPUT_FILE)) {
                usage(options,"Need a file path.");
                return null;
            }

            LogUtils.setOpenNoisyLog(commandLine.hasOption(Const.OPTION_OPEN_NOISY_LOG_LONG));

            List<String> excludedAbi = new ArrayList<>();
            if (commandLine.hasOption(Const.OPTION_EXCLUDE_ABI)) {
                String excludeAbiStr = commandLine.getOptionValue(Const.OPTION_EXCLUDE_ABI);
                if (excludeAbiStr != null && !excludeAbiStr.isEmpty()) {
                    String[] abiArray = excludeAbiStr.split(",");
                    for (String abi : abiArray) {
                        excludedAbi.add(abi.trim());
                    }
                }
            }

            String filePath = commandLine.getOptionValue(Const.OPTION_INPUT_FILE);
            HighValueVmCoordinator.setRulesPath(commandLine.getOptionValue(OPTION_HIGH_VALUE_METHODS));

            int riskCheckFlags = 0;
            if (commandLine.hasOption(Const.OPTION_DISABLE_FRIDA_DETECT_LONG)) {
                riskCheckFlags |= Const.FLAG_DISABLE_FRIDA_DETECT;
            }
            if (commandLine.hasOption(Const.OPTION_DISABLE_CRC_DETECT_LONG)) {
                riskCheckFlags |= Const.FLAG_DISABLE_CRC_DETECT;
            }
            if (commandLine.hasOption(Const.OPTION_DISABLE_ANTI_DEBUG_LONG)) {
                riskCheckFlags |= Const.FLAG_DISABLE_ANTI_DEBUG;
            }

            String expectedSign = commandLine.getOptionValue(Const.OPTION_EXPECT_SIGN_LONG);
            if (expectedSign != null) {
                expectedSign = expectedSign.trim().toLowerCase(java.util.Locale.US);
                if (!expectedSign.matches("[0-9a-f]{64}")) {
                    usage(options, "--expect-sign needs the 64-character SHA-256 of your signing certificate.");
                    return null;
                }
            }
            setExpectedSignSha256(expectedSign);

            boolean oneWaySeal = commandLine.hasOption(Const.OPTION_ONE_WAY_LONG);
            if (oneWaySeal && commandLine.hasOption(Const.OPTION_KEEP_CLASSES)) {
                usage(options, "--one-way cannot be combined with -K/--keep-classes; kept method bodies remain recoverable from the APK.");
                return null;
            }
            if (oneWaySeal && commandLine.hasOption(Const.OPTION_DO_NOT_PROTECT_CLASSES_RULES)) {
                usage(options, "--one-way cannot be combined with -r/--do-not-protect-classes; excluded classes keep their original bytecode in the APK.");
                return null;
            }
            if (oneWaySeal && riskCheckFlags != 0) {
                usage(options, "--one-way keeps every runtime check enabled; remove --disable-frida-detect/--disable-crc-detect/--disable-anti-debug.");
                return null;
            }
            if (oneWaySeal && commandLine.hasOption(Const.OPTION_DEBUGGABLE_LONG)) {
                usage(options, "--one-way cannot build a debuggable APK; the runtime check would flag it on every launch.");
                return null;
            }
            if (oneWaySeal && commandLine.hasOption(Const.OPTION_DISABLE_APP_COMPONENT_FACTORY_LONG)) {
                usage(options, "--one-way requires the bootstrap component factory; remove --disable-app-component-factory.");
                return null;
            }
            if (oneWaySeal && commandLine.hasOption(Const.OPTION_DUMP_CODE_LONG)) {
                usage(options, "--one-way cannot be combined with --dump-code; it writes original bytecode to plaintext JSON files.");
                return null;
            }
            if (oneWaySeal && commandLine.hasOption(Const.OPTION_NO_SIGN_PACKAGE)) {
                usage(options, "--one-way requires a signed APK because the runtime pins the signing certificate; remove -x/--no-sign.");
                return null;
            }

            if(filePath.endsWith(".apk")) {
                return new Apk.Builder()
                        .filePath(filePath)
                        .outputPath(commandLine.getOptionValue(Const.OPTION_OUTPUT_PATH))
                        .sign(!commandLine.hasOption(Const.OPTION_NO_SIGN_PACKAGE))
                        .debuggable(commandLine.hasOption(Const.OPTION_DEBUGGABLE_LONG))
                        .appComponentFactory(!commandLine.hasOption(Const.OPTION_DISABLE_APP_COMPONENT_FACTORY_LONG))
                        .dumpCode(commandLine.hasOption(Const.OPTION_DUMP_CODE_LONG))
                        .excludedAbi(excludedAbi)
                        .rulesFile(commandLine.getOptionValue(Const.OPTION_DO_NOT_PROTECT_CLASSES_RULES))
                        .keepClasses(commandLine.hasOption(Const.OPTION_KEEP_CLASSES))
                        .smaller(commandLine.hasOption(Const.OPTION_SMALLER))
                        .protectConfigFile(commandLine.getOptionValue(Const.OPTION_PROTECT_CONFIG))
                        .verifySign(commandLine.hasOption(Const.OPTION_VERIFY_SIGN) || expectedSign != null)
                        .oneWaySeal(oneWaySeal)
                        .riskCheckFlags(riskCheckFlags)
                        .build();
            }
            else if(filePath.endsWith(".aab")) {
                if (HighValueVmCoordinator.isEnabled()) {
                    usage(options, "--high-value-methods is currently APK-only; AAB protection is unchanged.");
                    return null;
                }
                if (oneWaySeal) {
                    usage(options, "--one-way is currently APK-only.");
                    return null;
                }
                return new Aab.Builder()
                        .filePath(filePath)
                        .outputPath(commandLine.getOptionValue(Const.OPTION_OUTPUT_PATH))
                        .sign(!commandLine.hasOption(Const.OPTION_NO_SIGN_PACKAGE))
                        .debuggable(commandLine.hasOption(Const.OPTION_DEBUGGABLE_LONG))
                        .appComponentFactory(!commandLine.hasOption(Const.OPTION_DISABLE_APP_COMPONENT_FACTORY_LONG))
                        .dumpCode(commandLine.hasOption(Const.OPTION_DUMP_CODE_LONG))
                        .excludedAbi(excludedAbi)
                        .rulesFile(commandLine.getOptionValue(Const.OPTION_DO_NOT_PROTECT_CLASSES_RULES))
                        .keepClasses(commandLine.hasOption(Const.OPTION_KEEP_CLASSES))
                        .smaller(commandLine.hasOption(Const.OPTION_SMALLER))
                        .protectConfigFile(commandLine.getOptionValue(Const.OPTION_PROTECT_CONFIG))
                        .verifySign(commandLine.hasOption(Const.OPTION_VERIFY_SIGN))
                        .riskCheckFlags(riskCheckFlags)
                        .build();
            }
            else {
                usage(options, "Unsupported file type!");
            }

        }
        catch (ParseException e) {
            usage(options, e.toString());
        }

        return null;
    }

}
