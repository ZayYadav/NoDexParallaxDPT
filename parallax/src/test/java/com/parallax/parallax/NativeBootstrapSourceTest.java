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
    private static Path repositoryRoot(){Path c=Paths.get(System.getProperty("user.dir")).toAbsolutePath();while(c!=null&&!Files.isRegularFile(c.resolve("settings.gradle")))c=c.getParent();if(c==null)throw new AssertionError("cannot locate repository root");return c;}
    private static String read(String p)throws IOException{return new String(Files.readAllBytes(repositoryRoot().resolve(p)),StandardCharsets.UTF_8);}
    @Test public void nativeBootstrapIsPartOfTheShellTarget()throws IOException{assertTrue(read("shell/src/main/cpp/CMakeLists.txt").contains("parallax_bootstrap.cpp"));}
    @Test public void encryptedCodeIsIsolatedFromTextAndPltPages()throws IOException{String c=read("shell/src/main/cpp/CMakeLists.txt"),l=read("shell/src/main/cpp/parallax_sections.ld");assertTrue(c.contains("--script=${CMAKE_CURRENT_SOURCE_DIR}/parallax_sections.ld"));assertTrue(c.contains("LINK_DEPENDS"));assertTrue(l.contains(".bitcode ALIGN(0x4000)"));assertTrue(l.contains(". = ALIGN(0x4000);"));assertTrue(l.contains("INSERT AFTER .text"));}
    @Test public void bootstrapUsesRuntimeAddressAndWxTransition()throws IOException{String b=read("shell/src/main/cpp/parallax_bootstrap.cpp");assertTrue(b.contains("__attribute__((constructor(101)))"));assertTrue(b.contains("section.sh_addr"));assertTrue(b.contains("PROT_READ | PROT_WRITE"));assertTrue(b.contains("PROT_READ | PROT_EXEC"));assertFalse(b.contains("PROT_READ | PROT_WRITE | PROT_EXEC"));assertFalse(b.contains("section.sh_offset"));}
    @Test public void legacyRwxBootstrapCannotBeReintroduced()throws IOException{String n=read("shell/src/main/cpp/parallax.cpp")+read("shell/src/main/cpp/common/parallax_macro.h");assertFalse(n.contains("INIT_ARRAY_SECTION"));assertFalse(n.contains("PROT_READ | PROT_WRITE | PROT_EXEC"));assertFalse(n.contains("void init_parallax()"));}
    @Test public void jniFailuresAlwaysClearPendingExceptionsBeforeNullChecks()throws IOException{String j=read("shell/src/main/cpp/parallax_jni.cpp"),n=j+read("shell/src/main/cpp/parallax.cpp")+read("shell/src/main/cpp/parallax_risk.cpp");assertFalse(j.matches("(?s).*\\w+\\s*==\\s*nullptr\\s*\\|\\|\\s*clearPendingException.*"));assertFalse(n.matches("(?s).*\\w+\\s*==\\s*nullptr\\s*\\|\\|\\s*env->ExceptionCheck\\(\\).*"));assertTrue(j.contains("clearPendingException(env) || klass == nullptr"));assertTrue(j.contains("clearPendingException(env) || methodId == nullptr"));}
    @Test public void componentFactoryBootstrapsBeforeInstantiatingRealApplication()throws IOException{String a=read("shell/src/main/java/com/parallax/shell/ParallaxKiSettingKarwaDo.java"),f=read("shell/src/main/java/com/parallax/shell/Parallax2.java");assertTrue(f.contains("public class Parallax2 extends AppComponentFactory"));assertTrue(a.contains("static boolean prepareClassLoader(ClassLoader classLoader, ApplicationInfo info)"));assertTrue(a.indexOf("\n            ia();")<a.indexOf("\n            cbde(classLoader);"));assertTrue(f.contains("ParallaxKiSettingKarwaDo.prepareClassLoader(cl,aInfo);"));assertTrue(f.contains("resolveApplicationName(cl)"));assertTrue(f.contains("d.instantiateApplication(cl,app)"));assertTrue(f.contains("super.instantiateApplication(cl,app)"));}
}
