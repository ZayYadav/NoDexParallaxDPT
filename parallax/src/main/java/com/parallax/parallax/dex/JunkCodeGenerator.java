package com.parallax.parallax.dex;

import com.android.dx.Code;
import com.android.dx.DexMaker;
import com.android.dx.Local;
import com.android.dx.MethodId;
import com.android.dx.TypeId;
import com.parallax.parallax.util.LogUtils;
import com.parallax.parallax.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * @author parallax
 */
public class JunkCodeGenerator {
    private static final String BASE_CLASS_NAME = "com/parallax/parallax/junkcode/JunkClass";

    // Keep the runtime sentinel and a randomized decoy surface, but do not bloat every
    // protected APK with 50-99 throwaway classes. The old amount added size without
    // materially improving the authenticated/hollow-DEX defenses.
    private static final int MIN_GENERATE_COUNT = 12;
    private static final int MAX_GENERATE_COUNT = 24;
    private static final Set<String> classNameSet = new HashSet<>();

    private static void insertSystemExit(Code code, boolean returnVoid) {
        TypeId<System> systemType = TypeId.get(System.class);

        MethodId<System, Void> exit = systemType.getMethod(TypeId.VOID, "exit", TypeId.INT);

        Local<Integer> exitCode = code.newLocal(TypeId.INT);
        code.loadConstant(exitCode, 0);

        code.invokeStatic(exit, null, exitCode);
        if(returnVoid) {
            code.returnVoid();
        }
    }

    private static void insertNullExceptionCode(Code code) {
        TypeId<NullPointerException> nullPointerExceptionTypeId = TypeId.get(NullPointerException.class);
        Local<NullPointerException> throwableLocal = code.newLocal(nullPointerExceptionTypeId);
        MethodId<NullPointerException, Void> constructor = nullPointerExceptionTypeId.getConstructor();
        code.newInstance(throwableLocal, constructor);
        code.throwValue(throwableLocal);
    }

    private static String generateBaseClassName() {

        return String.format(Locale.US, "L%s;", BASE_CLASS_NAME);
    }

    private static String generateClassName(SecureRandom secureRandom) {
        int number = Math.floorMod(secureRandom.nextInt(), MAX_GENERATE_COUNT * 32);
        return String.format(Locale.US, "L%s%d;", BASE_CLASS_NAME, number);
    }

    public static void generateJunkCodeDex(File file) throws IOException {
        SecureRandom secureRandom = new SecureRandom();
        final int generateClassCount = MIN_GENERATE_COUNT
                + secureRandom.nextInt(MAX_GENERATE_COUNT - MIN_GENERATE_COUNT + 1);

        // The CLI can protect several packages in one JVM. Do not retain old generated
        // names across runs because that only increases collision retries and memory use.
        classNameSet.clear();

        DexMaker dexMaker = new DexMaker();

        for(int i = 0;i < generateClassCount;i++) {

            String className;
            if(i == 0) {
                className = generateBaseClassName();
            }
            else {
                do {
                    className = generateClassName(secureRandom);
                }
                while(classNameSet.contains(className));
                classNameSet.add(className);
            }

            TypeId<?> typeId = TypeId.get(className);
            dexMaker.declare(typeId, "", Modifier.PUBLIC, TypeId.OBJECT);

            // Keep the base junk behavior used by the native sentinel checks.
            MethodId<?, Void> clinitMethod = typeId.getMethod(TypeId.VOID, "<clinit>");
            Code clinitCode = dexMaker.declare(clinitMethod, Modifier.STATIC);
            insertSystemExit(clinitCode, false);

            MethodId<?, Void> initMethod = typeId.getConstructor();
            Code initCode = dexMaker.declare(initMethod, Modifier.PUBLIC);
            insertSystemExit(initCode, true);

            // One or two decoy methods are enough once the real DEX/vault integrity layers
            // are authenticated; larger junk counts mostly increase APK size.
            int methodCount = secureRandom.nextInt(2) + 1;
            for (int j = 0; j < methodCount; j++) {
                String methodName = StringUtils.generateIdentifier(3);

                MethodId<?, Void> randomMethod = typeId.getMethod(TypeId.VOID, methodName);
                Code randomMethodCode = dexMaker.declare(randomMethod, Modifier.PUBLIC);
                if(j % 2 == 0) {
                    insertSystemExit(randomMethodCode, true);
                }
                else {
                    insertNullExceptionCode(randomMethodCode);
                }

            }
        }

        byte[] generate = dexMaker.generate();
        Files.write(Paths.get(file.getAbsolutePath()), generate);
        LogUtils.info("generated compact junk class count: %d, dex bytes: %d",
                generateClassCount, generate.length);

    }
}
