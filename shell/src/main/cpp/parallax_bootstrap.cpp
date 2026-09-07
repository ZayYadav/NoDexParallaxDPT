#include "parallax.h"
#include "parallax_crypto.h"
#include "parallax_hook.h"
#include "parallax_util.h"

#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <vector>

namespace {

bool decryptRuntimeBitcode() {
#ifdef DECRYPT_BITCODE
    Dl_info info{};
    if (dladdr(reinterpret_cast<const void *>(&decryptRuntimeBitcode), &info) == 0
            || info.dli_fbase == nullptr) {
        return false;
    }

    std::string soPath;
    if (info.dli_fname != nullptr && info.dli_fname[0] != '\0') {
        if (info.dli_fname[0] == '/') {
            soPath.assign(info.dli_fname);
        } else {
            soPath = find_so_path(info.dli_fname);
        }
    }
    if (soPath.empty()) {
        soPath = find_so_path(SO_NAME);
    }
    if (soPath.empty()) {
        return false;
    }

    Elf_Shdr section{};
    get_elf_section(&section, soPath.c_str(), SECTION_NAME_BITCODE);
    if (section.sh_size == 0) {
        return false;
    }

    auto *target = reinterpret_cast<uint8_t *>(info.dli_fbase) + section.sh_addr;
    const size_t size = static_cast<size_t>(section.sh_size);

    // Authenticate while the code mapping is still RX. Writable permission is only
    // requested after ciphertext integrity has been established.
    const char *authLabel = "Parallax/bitcode/authentication/v2";
    auto authenticationKey = hmac_sha256(
            g_parallax_crypto_meta.master_key,
            sizeof(g_parallax_crypto_meta.master_key),
            reinterpret_cast<const uint8_t *>(authLabel),
            strlen(authLabel));
    if (authenticationKey.size() != 32) {
        return false;
    }

    std::vector<uint8_t> authenticated(sizeof(g_parallax_crypto_meta.bitcode_nonce) + size);
    memcpy(authenticated.data(),
           g_parallax_crypto_meta.bitcode_nonce,
           sizeof(g_parallax_crypto_meta.bitcode_nonce));
    memcpy(authenticated.data() + sizeof(g_parallax_crypto_meta.bitcode_nonce),
           target, size);

    auto expectedTag = hmac_sha256(authenticationKey.data(), authenticationKey.size(),
                                   authenticated.data(), authenticated.size());
    secure_zero(authenticationKey.data(), authenticationKey.size());
    secure_zero(authenticated.data(), authenticated.size());

    if (expectedTag.size() != sizeof(g_parallax_crypto_meta.bitcode_tag)
            || !constant_time_equal(expectedTag.data(),
                                    g_parallax_crypto_meta.bitcode_tag,
                                    sizeof(g_parallax_crypto_meta.bitcode_tag))) {
        secure_zero(expectedTag.data(), expectedTag.size());
        return false;
    }
    secure_zero(expectedTag.data(), expectedTag.size());

    const char *encLabel = "Parallax/bitcode/encryption/v2";
    auto encryptionKey = hmac_sha256(
            g_parallax_crypto_meta.master_key,
            sizeof(g_parallax_crypto_meta.master_key),
            reinterpret_cast<const uint8_t *>(encLabel),
            strlen(encLabel));
    if (encryptionKey.size() != 32) {
        return false;
    }

    auto plain = aes_ctr_crypt(encryptionKey.data(), 256,
                               g_parallax_crypto_meta.bitcode_nonce,
                               target, size);
    secure_zero(encryptionKey.data(), encryptionKey.size());
    if (plain.size() != size) {
        secure_zero(plain.data(), plain.size());
        return false;
    }

    // W^X: never create an RWX mapping. The authenticated plaintext is copied only
    // during a short RW window and immediately restored to RX.
    if (parallax_mprotect(target, target + size, PROT_READ | PROT_WRITE) != 0) {
        secure_zero(plain.data(), plain.size());
        return false;
    }

    memcpy(target, plain.data(), size);
    secure_zero(plain.data(), plain.size());

    __builtin___clear_cache(reinterpret_cast<char *>(target),
                            reinterpret_cast<char *>(target + size));

    if (parallax_mprotect(target, target + size, PROT_READ | PROT_EXEC) != 0) {
        return false;
    }
#endif
    return true;
}

// Priority 101 is the earliest application-defined constructor priority. The authenticated
// native runtime is restored before default-priority protection constructors or JNI_OnLoad.
__attribute__((constructor(101))) void parallaxBootstrapInit() {
    if (!decryptRuntimeBitcode()) {
        abort();
    }
    parallax_hook();
}

} // namespace
