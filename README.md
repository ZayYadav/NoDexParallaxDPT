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

The native build needs `python3`: `scripts/seal_native_hash.py` runs as a post-link
step and embeds the `.text` SHA-256.

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
                             -K/--keep-classes, force every runtime integrity check,
                             audit the output for original DEX bytes, and securely
                             erase protection workspaces. Any signing certificate is
                             accepted by default. APK only.
    --expect-sign <sha256>   Pin the certificate that will sign the APK *after*
                             protection (64 hex chars, no colons). Use this when you
                             protect first and re-sign with your own keystore later.
```

## One-way seal

`--one-way` is the anti-recovery mode. Once an APK is sealed, the build tool:

- refuses an input that is already Parallax-protected (double protection corrupts the
  bootstrap and cannot restore the original);
- rejects `-K/--keep-classes`, `-r/--do-not-protect-classes`, `--dump-code`,
  `--debuggable`, and `--disable-app-component-factory`, because each one leaves
  recoverable code behind or weakens the bootstrap;
- routes every method the native VM can compile (up to 2000) instead of the top-96
  heuristic, and logs routed/eligible/deferred/unsupported coverage for the build;
- forces Frida/CRC/anti-debug checks and native payload authentication to **fail
  closed** (the process is killed on mismatch);
- overwrites the in-memory DEX header checksum/SHA-1 after ART has opened it, so a raw
  memory dump does not begin as a valid DEX (the loaded classes keep running);
- re-randomizes those headers from the hardening watchdog and kills the process if the
  live header is repaired;
- installs ten decoy DEX buffers (six DEX-shaped with valid checksum and random
  class data) so a memory dumper emits several unusable candidates alongside the
  real stubs;
- streams every classic VM opcode array through a per-program HMAC-SHA256 keystream
  with a keyed tag and decodes one instruction at a time from ciphertext, wiping each
  short-lived local opcode after use; a live opcode patch fails the tag check;
- seals the native `.text` section with a build-time SHA-256 stored in `.data`;
  the constructor and watchdog re-hash the mapped text, so an inline Frida hook or
  a patched decoder is detected and the process is killed before app output;
- does **not** pin the signing certificate by default, so the sealed APK can be
  re-signed with any keystore;
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

The input APK is never modified or deleted. The sealed output **does not care which
certificate signs it**. Sign it during protection with any keystore, or re-sign the
result afterward:

```shell
apksigner sign --ks any-release.jks --out out/app-release.apk out/app_signed.apk
```

Pinning is optional, not required by `--one-way`:

- `--verify-sign` pins the certificate read from the signing keystore used by Parallax.
- `--expect-sign <sha256>` pins the certificate you will use later, before re-signing:

```shell
# SHA-256 of the final certificate (strip colons)
keytool -list -v -keystore release.jks -alias app | grep SHA256

java -jar parallax.jar -f app.apk --one-way \
    --expect-sign <64-hex-sha256> -o out

apksigner sign --ks release.jks --out out/app-release.apk out/app_signed.apk
```

Payload authentication uses a per-build key embedded in the native library, independent
of the APK signature, so an unpinned, re-signed APK still fails closed if its protected
DEX is modified. Re-signing changes the APK hash recorded in `<output>.oneway`; that
sidecar is audit metadata only.

A signing certificate cannot stop someone from re-signing the **original** APK and
installing that instead. Keep the original APK; the seal protects the protected build,
not the fact that an unprotected copy exists elsewhere.

Known limits: packages matched by the default compatibility exclusion rules (typically
bundled AndroidX/Google libraries) stay in the hollowed dex. The native VM intentionally
covers a bounded int/long/float/double subset; methods using unsupported object/array/
invoke patterns keep their original bodies in the runtime dex. The seal covers the app's
own classes; it does not claim byte-for-byte erasure of third-party library code.

No client-side packer is unbreakable. The one-way seal blocks static unzip/dump/repack
recovery and makes payload tampering fail closed, but it cannot block re-signing (the
protected APK accepts any certificate by default, and the original APK can always be
re-signed). It does not defeat a determined reverse engineer with kernel-level
instrumentation.

On a rooted device, the decrypted DEX still lives in the `InMemoryDexClassLoader`
direct buffer because ART must read it. The shell invalidates that buffer's DEX header
(checksum and SHA-1) right after loading and keeps re-randomizing it, so a raw dump
starts as a corrupt DEX; it also plants decoy DEX buffers. The method bodies of
VM-routed methods are native stubs, not original code. Classic VM opcodes are
keystream-encrypted in memory and decoded one instruction at a time, but the build
secret lives in the native library, so kernel-level instrumentation can eventually
recover it. The `.text` seal detects inline patching/hooking of the decoder, but not
GOT/PLT redirection, dynamic tracing, or a fully repackaged library whose `.data` seal
was recomputed. A determined attacker can repair the DEX header and ignore the stubs,
and a passive `/proc/<pid>/mem` scan still recovers the remaining bytes. `MADV_DONTDUMP`/`PROT_NONE` do not stop it
because `/proc/pid/mem` uses `FOLL_FORCE`; `memfd_secret` would help, but Android
kernels commonly ship without `CONFIG_SECRETMEM`.

Treat the seal as anti-static-recovery + tamper evidence + dump sabotage, not as
runtime-dump prevention.
If the code must never be recoverable, keep it on a server and ship only a thin client.

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
