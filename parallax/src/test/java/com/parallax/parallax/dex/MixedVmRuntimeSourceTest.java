package com.parallax.parallax.dex;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Test;

public class MixedVmRuntimeSourceTest {
    private static Path repositoryRoot() {
        Path current = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        while (current != null && !Files.isRegularFile(current.resolve("settings.gradle"))) {
            current = current.getParent();
        }
        if (current == null) throw new AssertionError("cannot locate repository root");
        return current;
    }

    private static String read(String path) throws IOException {
        return new String(Files.readAllBytes(repositoryRoot().resolve(path)), StandardCharsets.UTF_8);
    }

    @Test
    public void shellBuildUsesIsolatedRuntimesAndDispatcher() throws IOException {
        String cmake = read("shell/src/main/cpp/CMakeLists.txt");
        assertTrue(cmake.contains("parallax_vm_classic_runtime.cpp"));
        assertTrue(cmake.contains("parallax_vm4_runtime.cpp"));
        assertTrue(cmake.contains("parallax_vm_dispatch.cpp"));
        assertFalse(cmake.contains("\n        parallax_vm4.cpp\n"));
    }

    @Test
    public void classicAndVm4PayloadsUseSeparateAssets() throws IOException {
        String classic = read("shell/src/main/cpp/parallax_vm_classic_runtime.cpp");
        String vm4 = read("shell/src/main/cpp/parallax_vm4.cpp");
        assertTrue(classic.contains("assets/Parallax.vmc"));
        assertTrue(vm4.contains("assets/Parallax.vm"));
    }

    @Test
    public void dispatcherUsesDedicatedVm4IdMarker() throws IOException {
        String dispatcher = read("shell/src/main/cpp/parallax_vm_dispatch.cpp");
        assertTrue(dispatcher.contains("0x40000000u"));
        assertTrue(dispatcher.contains("isVm4Method"));
    }
}
