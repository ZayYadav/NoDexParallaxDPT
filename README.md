# parallax-shell

[![](https://img.shields.io/github/license/parallax/parallax-shell)](https://github.com/parallax/parallax-shell/blob/main/LICENSE) [![](https://img.shields.io/github/downloads/parallax/parallax-shell/total?color=blue)](https://github.com/parallax/parallax-shell/releases/latest) [![](https://img.shields.io/github/issues-raw/parallax/parallax-shell?color=red)](https://github.com/parallax/parallax-shell/issues) ![](https://img.shields.io/badge/Android-5.0%2B-brightgreen)

English | [简体中文](./README.zh-CN.md)

parallax-shell is an Android Dex protection shell that hollows out Dex method implementations and reconstructs them at runtime.

## Usage

### Quick uses

Go to [Releases](https://github.com/parallax/parallax-shell/releases/latest) download `executable.zip` and unzip it, run the follow command lines in terminal:

```shell
java -jar parallax.jar -f /path/to/android-package-file
```

### Manual builds

```shell
git clone --recursive https://github.com/parallax/parallax-shell
cd parallax-shell
./gradlew assemble
cd executable
java -jar parallax.jar -f /path/to/android-package-file
```

### Command line options

```text
usage: java -jar parallax.jar [option] -f <package_file>
 -c,--protect-config <arg>   Protect config file.

    --debug                  Make package debuggable.
    --disable-acf            Disable app component factory(just use for
                             debug).
    --disable-anti-debug     Disable runtime anti-debug.
    --disable-crc-detect     Disable runtime libc .text CRC detection.

    --disable-frida-detect   Disable runtime Frida detection.

    --dump-code              Dump the code item of DEX and save it to
                             .json files.
 -e,--exclude-abi <arg>      Exclude specific ABIs (comma separated, e.g.
                             x86,x86_64).
                             Supported ABIs:
                             - arm       (armeabi-v7a)
                             - arm64     (arm64-v8a)
                             - x86
                             - x86_64
 -f,--package-file <arg>     Need to protect android package(*.apk, *.aab)
                             file.
 -K,--keep-classes           Keeping some classes in the package can
                             improve the app's startup speed to a certain
                             extent, but it is not supported by some
                             application packages.
    --noisy-log              Open noisy log.
 -o,--output <arg>           Output directory for protected package.
 -r,--rules-file <arg>       Rules file for class names that will not be
                             protected.
 -S,--smaller                Trade some of the app's performance for a
                             smaller app size.
 -v,--version                Show program's version number.
 -vs,--verify-sign           Enable runtime app signature verification.
                             The certificate SHA-256 is computed
                             automatically from the signing keystore.
 -x,--no-sign                Do not sign package.
    --one-way                One-way seal: refuse already-protected inputs, forbid
                             -K/--keep-classes, force signature pinning and every
                             runtime check, audit the output for original DEX bytes,
                             and securely erase protection workspaces. APK only.
```

## One-way seal

`--one-way` is the anti-recovery mode. Once an APK is sealed, the build tool:

- refuses an input that is already Parallax-protected (double protection corrupts the
  bootstrap and cannot restore the original);
- rejects `-K/--keep-classes`, `-r/--do-not-protect-classes`, `--dump-code`,
  `--debuggable`, and `--disable-app-component-factory`, because each one leaves
  recoverable code behind or weakens the bootstrap;
- forces runtime signature pinning, Frida/CRC/anti-debug checks, and native payload
  authentication to **fail closed** (the process is killed on mismatch);
- audits the finished APK and aborts if any original `classes*.dex` header or digest is
  still present in any entry;
- overwrites and erases the workspace and every intermediate artifact;
- writes `<output>.oneway` with the input/output SHA-256 identities for auditing.

```shell
java -jar parallax.jar -f app.apk --one-way -o out
```

The built-in signing key is public, so use a private keystore for deployments:

```shell
java -jar parallax.jar -f app.apk --one-way -c protect-config.json -o out
```

The input APK is never modified or deleted. Re-sign the sealed output only with the
same key that produced the pinned certificate, otherwise the runtime check will kill it.

Known limit: packages matched by the default compatibility exclusion rules (typically
bundled AndroidX/Google libraries) stay in the hollowed dex. The seal covers the app's
own classes; it does not claim byte-for-byte erasure of third-party library code.

No client-side packer is unbreakable. The one-way seal blocks the normal
unzip/dump/repack/re-sign recovery workflows and makes tampering fail closed; it does
not defeat a determined reverse engineer with kernel-level instrumentation.

## Notice

This project has not too many tests, be careful use in prod environment. Otherwise, all consequences are at your own risk.

## Dependency or use follows project code

- [dx](https://android.googlesource.com/platform/dalvik/+/refs/heads/master/dx/)
- [Dobby](https://github.com/jmpews/Dobby)
- ~~[libzip-android](https://github.com/julienr/libzip-android)~~
- [ManifestEditor](https://github.com/WindySha/ManifestEditor)
- ~~[Xpatch](https://github.com/WindySha/Xpatch)~~
- [bhook](https://github.com/bytedance/bhook)
- [zipalign-java](https://github.com/Iyxan23/zipalign-java)
- [minizip-ng](https://github.com/zlib-ng/minizip-ng)
- [JSON-java](https://github.com/stleary/JSON-java)
- [zip4j](https://github.com/srikanth-lingala/zip4j)
- [commons-cli](https://github.com/apache/commons-cli)
- [dexmaker](https://android.googlesource.com/platform/external/dexmaker)
- [Obfuscate](https://github.com/adamyaxley/Obfuscate)
