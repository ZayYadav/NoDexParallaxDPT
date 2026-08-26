#include "parallax.h"
#include "parallax_hook.h"
#include "parallax_util.h"

#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>

extern uint8_t PARALLAX_UNKNOWN_DATA[];

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

    // sh_addr is the runtime virtual offset for an ET_DYN shared object. sh_offset is
    // only a file offset and is not guaranteed to remain equal after linker/layout changes.
    auto *target = reinterpret_cast<uint8_t *>(info.dli_fbase) + section.sh_addr;
    const size_t size = static_cast<size_t>(section.sh_size);

    // W^X: never request writable + executable memory at the same time. Modern Android
    // and hardened OEM kernels may reject RWX even for a private app mapping.
    if (parallax_mprotect(target, target + size, PROT_READ | PROT_WRITE) != 0) {
        return false;
    }

    auto *plain = static_cast<uint8_t *>(malloc(size));
    if (plain == nullptr) {
        parallax_mprotect(target, target + size, PROT_READ | PROT_EXEC);
        return false;
    }

    rc4_state state{};
    rc4_init(&state, reinterpret_cast<const u_char *>(PARALLAX_UNKNOWN_DATA), 16);
    rc4_crypt(&state, reinterpret_cast<const u_char *>(target),
              reinterpret_cast<u_char *>(plain), size);
    memcpy(target, plain, size);
    free(plain);

    // ARM has separate data/instruction caches. Explicitly invalidate the instruction
    // cache after rewriting executable bytes, before the section can be executed.
    __builtin___clear_cache(reinterpret_cast<char *>(target),
                            reinterpret_cast<char *>(target + size));

    if (parallax_mprotect(target, target + size, PROT_READ | PROT_EXEC) != 0) {
        return false;
    }
#endif
    return true;
}

__attribute__((constructor)) void parallaxBootstrapInit() {
    // JNI_OnLoad and the DEX restoration routines live in the encrypted .bitcode section,
    // so decryption must complete before the dynamic linker can enter JNI_OnLoad.
    if (!decryptRuntimeBitcode()) {
        abort();
    }
    parallax_hook();
}

} // namespace
