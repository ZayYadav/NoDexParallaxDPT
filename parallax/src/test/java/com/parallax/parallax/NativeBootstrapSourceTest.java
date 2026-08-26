package com.parallax.parallax;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Test;

public class NativeBootstrapSourceTest {

    private static Path repositoryRoot() {
        Path current = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        while (current != null && !Files.isRegularFile(current.resolve("settings.gradle"))) {
            current = current.getParent();
        }
        if (current == null) {
            throw new AssertionError("cannot locate repository root");
        }
        return current;
    }

    private static String read(String relativePath) throws IOException {
        byte[] bytes = Files.readAllBytes(repositoryRoot().resolve(relativePath));
        return new String(bytes, StandardCharsets.UTF_8);
    }

    @Test
    public void nativeBootstrapIsPartOfTheShellTarget() throws IOException {
        String cmake = read("shell/src/main/cpp/CMakeLists.txt");
        assertTrue(cmake.contains("parallax_bootstrap.cpp"));
    }

    @Test
    public void bootstrapUsesRuntimeAddressAndWxTransition() throws IOException {
        String bootstrap = read("shell/src/main/cpp/parallax_bootstrap.cpp");
        assertTrue(bootstrap.contains("__attribute__((constructor(101)))"));
        assertTrue(bootstrap.contains("section.sh_addr"));
        assertTrue(bootstrap.contains("PROT_READ | PROT_WRITE"));
        assertTrue(bootstrap.contains("PROT_READ | PROT_EXEC"));
        assertFalse(bootstrap.contains("PROT_READ | PROT_WRITE | PROT_EXEC"));
        assertFalse(bootstrap.contains("section.sh_offset"));
    }

    @Test
    public void legacyRwxBootstrapCannotBeReintroduced() throws IOException {
        String nativeSources = read("shell/src/main/cpp/parallax.cpp")
                + read("shell/src/main/cpp/common/parallax_macro.h");
        assertFalse(nativeSources.contains("INIT_ARRAY_SECTION"));
        assertFalse(nativeSources.contains("PROT_READ | PROT_WRITE | PROT_EXEC"));
        assertFalse(nativeSources.contains("void init_parallax()"));
    }

    @Test
    public void jniFailuresAlwaysClearPendingExceptionsBeforeNullChecks() throws IOException {
        String jni = read("shell/src/main/cpp/parallax_jni.cpp");
        String nativeSources = jni
                + read("shell/src/main/cpp/parallax.cpp")
                + read("shell/src/main/cpp/parallax_risk.cpp");
        assertFalse(jni.matches("(?s).*\\w+\\s*==\\s*nullptr\\s*\\|\\|\\s*clearPendingException.*"));
        assertFalse(nativeSources.matches(
                "(?s).*\\w+\\s*==\\s*nullptr\\s*\\|\\|\\s*env->ExceptionCheck\\(\\).*"));
        assertTrue(jni.contains("clearPendingException(env) || klass == nullptr"));
        assertTrue(jni.contains("clearPendingException(env) || methodId == nullptr"));
    }

    @Test
    public void componentFactoryBootstrapsBeforeInstantiatingRealApplication() throws IOException {
        String application = read(
                "shell/src/main/java/com/parallax/shell/ParallaxKiSettingKarwaDo.java");
        String factory = read(
                "shell/src/main/java/com/parallax/shell/ParallaxKoLadkiChahiye.java");

        assertTrue(application.contains(
                "static boolean prepareClassLoader(ClassLoader classLoader, ApplicationInfo info)"));
        assertTrue(application.indexOf("\n            ia();")
                < application.indexOf("\n            cbde(classLoader);"));
        assertTrue(factory.contains(
                "ParallaxKiSettingKarwaDo.prepareClassLoader(cl, aInfo);"));
        assertTrue(factory.contains("resolveApplicationName(cl)"));
        assertTrue(factory.contains("delegate.instantiateApplication(cl, applicationName)"));
        assertTrue(factory.contains("super.instantiateApplication(cl, applicationName)"));
    }
}
