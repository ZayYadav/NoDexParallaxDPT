//
// Created by parallax
//

#include <mutex>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <sys/prctl.h>
#include <sys/system_properties.h>
#include "dex/CodeItem.h"
#include "common/parallax_string.h"
#include "parallax_hook.h"
#include "parallax_risk.h"
#include "parallax_util.h"
#include "bytehook.h"

using namespace parallax;

extern std::unordered_map<int, std::vector<data::CodeItem*>*> dexMap;
static std::mutex g_dex_mem_mutex;
static std::unordered_set<uintptr_t> g_writable_dex_bases;
int g_sdkLevel = 0;
extern ShellConfig g_shell_config;

namespace {

// We only need the stable prefix of ART DexFile on modern Android. Reading private
// std::string/ArrayRef fields by a version-specific layout is unnecessarily fragile and
// has caused late crashes when ART changes internal field ordering.
struct DexFilePrefix {
    void *vtable;
    const uint8_t *begin;
};

static bool looksLikeDex(const uint8_t *begin, size_t size) {
    if (begin == nullptr || size < sizeof(dex::Header)) {
        return false;
    }
    return begin[0] == 'd' && begin[1] == 'e' && begin[2] == 'x' && begin[3] == '\n';
}

static bool ensureDexWritable(uint8_t *begin, size_t dexSize) {
    if (begin == nullptr || dexSize < sizeof(dex::Header)) {
        return false;
    }

    const uintptr_t key = reinterpret_cast<uintptr_t>(begin);
    std::lock_guard<std::mutex> lock(g_dex_mem_mutex);
    if (g_writable_dex_bases.find(key) != g_writable_dex_bases.end()) {
        return true;
    }

    // mprotect the exact DEX range once. Multiple ART verifier/class-loader threads can
    // arrive here together when a game starts; serialize this transition to avoid racing
    // std::map writes and duplicate permission changes.
    for (int attempt = 0; attempt < 3; ++attempt) {
        int ret = parallax_mprotect(begin, begin + dexSize, PROT_READ | PROT_WRITE);
        if (ret == 0) {
            g_writable_dex_bases.insert(key);
            DLOGD("mprotect dex success, address: %p, size=%zu", begin, dexSize);
            return true;
        }
        DLOGW("mprotect dex failed, address: %p, attempt=%d, reason=%d",
              begin, attempt + 1, ret);
    }
    return false;
}

static int resolveInMemoryDexIndex(const uint8_t *begin, size_t dexSize) {
    const auto &dexFiles = getInMemoryDexFiles();
    if (begin == nullptr || dexFiles.empty()) {
        return -1;
    }

    // Best case: ART retained the same DirectByteBuffer backing address.
    for (size_t i = 0; i < dexFiles.size(); ++i) {
        if (dexFiles[i].first == begin) {
            return static_cast<int>(i);
        }
    }

    // Some ART releases copy the input buffer. Match the immutable DEX header instead of
    // guessing from size alone. Header signature/checksum/file-size uniquely identify the
    // protected DEX in normal multidex packages.
    int headerMatch = -1;
    int headerMatches = 0;
    if (looksLikeDex(begin, dexSize)) {
        constexpr size_t kIdentityBytes = 32; // magic + checksum + SHA-1 signature
        for (size_t i = 0; i < dexFiles.size(); ++i) {
            const uint8_t *candidate = dexFiles[i].first;
            const size_t candidateSize = dexFiles[i].second;
            if (candidate != nullptr
                    && candidateSize == dexSize
                    && candidateSize >= kIdentityBytes
                    && memcmp(candidate, begin, kIdentityBytes) == 0) {
                headerMatch = static_cast<int>(i);
                headerMatches++;
            }
        }
        if (headerMatches == 1) {
            return headerMatch;
        }
    }

    // Size-only fallback is allowed only when it is unambiguous. The previous code picked
    // the first same-sized DEX, which could restore instructions from the wrong multidex
    // file and crash only when a later game class was first loaded.
    int sizeMatch = -1;
    int sizeMatches = 0;
    for (size_t i = 0; i < dexFiles.size(); ++i) {
        if (dexFiles[i].second == dexSize) {
            sizeMatch = static_cast<int>(i);
            sizeMatches++;
        }
    }
    return sizeMatches == 1 ? sizeMatch : -1;
}

} // namespace

void parallax_hook() {
    g_sdkLevel = android_get_device_api_level();

    // Keep only the hook required to restore protected methods. Do not globally intercept
    // libc write(), execve()/dex2oat or mmap for the whole app: games and plugin systems
    // legitimately create/optimize secondary DEX files after login and those broad hooks
    // can break them at the exact moment a game/engine module starts.
    bool hookSuccess = hook_DefineClass();
    if (!hookSuccess) {
        hookSuccess = hook_LoadClass();
    }
    if (!hookSuccess) {
        DLOGE("no ART class restoration hook available");
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
    }
}

const char *GetArtLibPath() {
    if(g_sdkLevel < 29)
        return  "/system/" LIB_DIR "/libart.so" ;
    else if(g_sdkLevel == 29) {
        return "/apex/com.android.runtime/" LIB_DIR "/libart.so";
    }
    else {
        return "/apex/com.android.art/" LIB_DIR "/libart.so";
    }
}

const char *GetArtBaseLibPath() {
    if(g_sdkLevel == 29) {
        return "/apex/com.android.runtime/" LIB_DIR "/libartbase.so";
    }
    else {
        return "/apex/com.android.art/" LIB_DIR "/libartbase.so";
    }
}

const char *GetClassLinkerDefineClassLibPath(){
    return GetArtLibPath();
}

PARALLAX_ENCRYPT
ALWAYS_INLINE
void patchMethod(uint8_t *begin,
                 __unused const char *location,
                 uint32_t dexSize,
                 int dexIndex,
                 uint32_t methodIdx,
                 uint32_t codeOff) {
    if (begin == nullptr || dexIndex < 0 || !looksLikeDex(begin, dexSize)) {
        return;
    }

    auto dexIt = dexMap.find(dexIndex);
    if (UNLIKELY(dexIt == dexMap.end() || dexIt->second == nullptr)) {
        DLOGW("cannot find protected dex index %d (%s)", dexIndex,
              location == nullptr ? "" : location);
        return;
    }

    auto codeItemVec = dexIt->second;
    if (UNLIKELY(methodIdx >= codeItemVec->size())) {
        DLOGW("method index out of range: dex=%d method=%u", dexIndex, methodIdx);
        return;
    }

    auto codeItem = codeItemVec->at(methodIdx);
    if (codeItem == nullptr || codeOff == 0) {
        return;
    }

    // A wrong/changed ART mapping must never become an out-of-bounds native write.
    if (UNLIKELY(codeOff > dexSize || dexSize - codeOff < 16u)) {
        DLOGW("invalid code offset: dex=%d method=%u codeOff=%u size=%u",
              dexIndex, methodIdx, codeOff, dexSize);
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return;
    }

    if (UNLIKELY(!ensureDexWritable(begin, dexSize))) {
        DLOGW("cannot make protected dex writable: dex=%d", dexIndex);
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return;
    }

    auto *dexCodeItem = reinterpret_cast<dex::CodeItem *>(begin + codeOff);
    auto *realInsnsPtr = reinterpret_cast<uint8_t *>(dexCodeItem->insns_);
    const size_t realOffset = static_cast<size_t>(realInsnsPtr - begin);
    const uint32_t restoreSize = codeItem->getInsnsSize();
    if (UNLIKELY(realOffset > dexSize || restoreSize > dexSize - realOffset)) {
        DLOGW("instruction restore out of range: dex=%d method=%u off=%zu bytes=%u size=%u",
              dexIndex, methodIdx, realOffset, restoreSize, dexSize);
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return;
    }

    NLOG("codeItem patch, methodIndex = %d, insnsSize = %d >>> %p(0x%x)",
         codeItem->getMethodIdx(), restoreSize, realInsnsPtr,
         (unsigned int)(realInsnsPtr - begin));

    uint32_t xorKey = g_shell_config.insns_xor_key;
    if (xorKey == 0) {
        memcpy(realInsnsPtr, codeItem->getInsns(), restoreSize);
    } else {
        thread_local std::vector<uint8_t> tmp;
        tmp.resize(restoreSize);
        const uint8_t* enc = codeItem->getInsns();
        for (uint32_t i = 0; i < restoreSize; i++) {
            uint32_t shift = (i & 3u) << 3u;
            tmp[i] = static_cast<uint8_t>(enc[i] ^ ((xorKey >> shift) & 0xffu));
        }
        memcpy(realInsnsPtr, tmp.data(), restoreSize);
    }
}

PARALLAX_ENCRYPT void patchClass(__unused const char* descriptor,
                                 const void* dex_file,
                                 const void* dex_class_def) {
    // Numbered junk classes can be touched by ART verification, reflection scanners and
    // game engines. Class definition itself is not proof of dumping; never intentionally
    // crash the app here.
    const char *junkClassName = AY_OBFUSCATE(JUNK_CLASS_FULL_NAME);
    if (descriptor != nullptr && parallax_strstr(descriptor, junkClassName) != nullptr) {
        size_t descriptorLength = parallax_strlen(descriptor);
        if (descriptorLength >= 2
                && isdigit(static_cast<unsigned char>(descriptor[descriptorLength - 2]))) {
            DLOGD("ignore numbered junk class definition: %s", descriptor);
            return;
        }
    }

    if (dex_file == nullptr || dex_class_def == nullptr) {
        return;
    }

    uint8_t *begin = nullptr;
    uint64_t dexSize64 = 0;
    int dexIndex = -1;
    std::string location;

    if (g_sdkLevel >= 26) {
        // Modern protected DEX files are loaded from ByteBuffers. Use only DexFile's stable
        // prefix and the raw DEX header; do not read private ART std::string/layout fields.
        auto *prefix = reinterpret_cast<const DexFilePrefix *>(dex_file);
        begin = const_cast<uint8_t *>(prefix->begin);
        if (begin == nullptr) {
            return;
        }
        const auto *header = reinterpret_cast<const dex::Header *>(begin);
        dexSize64 = header->file_size_;
        if (dexSize64 == 0 || dexSize64 > UINT32_MAX || !looksLikeDex(begin, dexSize64)) {
            return;
        }
        dexIndex = resolveInMemoryDexIndex(begin, static_cast<size_t>(dexSize64));
        if (dexIndex < 0) {
            // Not one of our in-memory DEX files (or ART made identity ambiguous): leave
            // unrelated plugin/game DEX untouched. Do not guess an index.
            return;
        }
        location.assign("ParallaxInMemoryDex");
    } else {
        auto *dexFileV21 = reinterpret_cast<const V21::DexFile *>(dex_file);
        begin = const_cast<uint8_t *>(dexFileV21->begin_);
        dexSize64 = dexFileV21->size_ == 0 && dexFileV21->header_ != nullptr
                    ? dexFileV21->header_->file_size_ : dexFileV21->size_;
        location = dexFileV21->location_;
        if (location.rfind(DEXES_ZIP_NAME) == std::string::npos) {
            return;
        }
        dexIndex = parse_dex_number(location);
    }

    if (begin == nullptr || dexSize64 == 0 || dexSize64 > UINT32_MAX || dexIndex < 0) {
        return;
    }
    const uint32_t dexSize = static_cast<uint32_t>(dexSize64);

    // Verify that ART's class_def pointer actually lies inside this DEX before parsing it.
    const uintptr_t baseAddress = reinterpret_cast<uintptr_t>(begin);
    const uintptr_t classDefAddress = reinterpret_cast<uintptr_t>(dex_class_def);
    if (classDefAddress < baseAddress
            || classDefAddress - baseAddress > dexSize
            || dexSize - static_cast<uint32_t>(classDefAddress - baseAddress) < sizeof(dex::ClassDef)) {
        DLOGW("class_def outside protected dex: dex=%d", dexIndex);
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return;
    }

    auto *class_def = reinterpret_cast<const dex::ClassDef *>(dex_class_def);
    if (class_def->class_data_off_ == 0) {
        return;
    }
    if (class_def->class_data_off_ >= dexSize) {
        DLOGW("class_data offset outside protected dex: dex=%d off=%u size=%u",
              dexIndex, class_def->class_data_off_, dexSize);
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return;
    }

    size_t read = 0;
    auto *class_data = begin + class_def->class_data_off_;

    uint64_t static_fields_size = 0;
    read += DexFileUtils::readUleb128(class_data + read, &static_fields_size);
    uint64_t instance_fields_size = 0;
    read += DexFileUtils::readUleb128(class_data + read, &instance_fields_size);
    uint64_t direct_methods_size = 0;
    read += DexFileUtils::readUleb128(class_data + read, &direct_methods_size);
    uint64_t virtual_methods_size = 0;
    read += DexFileUtils::readUleb128(class_data + read, &virtual_methods_size);

    // Valid DEX method counts are bounded by method_ids. Refuse absurd values rather than
    // allocating/parsing attacker- or layout-corrupted sizes in a class-loader callback.
    if (direct_methods_size > 65535u || virtual_methods_size > 65535u
            || direct_methods_size + virtual_methods_size > 65535u) {
        DLOGW("invalid class method counts in protected dex=%d", dexIndex);
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return;
    }

    read += DexFileUtils::getFieldsSize(class_data + read, static_fields_size);
    read += DexFileUtils::getFieldsSize(class_data + read, instance_fields_size);
    if (class_def->class_data_off_ + read >= dexSize) {
        DLOGW("class_data fields exceed protected dex=%d", dexIndex);
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return;
    }

    auto *directMethods = new dex::ClassDataMethod[direct_methods_size];
    read += DexFileUtils::readMethods(class_data + read, directMethods, direct_methods_size);
    auto *virtualMethods = new dex::ClassDataMethod[virtual_methods_size];
    read += DexFileUtils::readMethods(class_data + read, virtualMethods, virtual_methods_size);

    if (class_def->class_data_off_ + read > dexSize) {
        delete[] directMethods;
        delete[] virtualMethods;
        DLOGW("class_data methods exceed protected dex=%d", dexIndex);
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return;
    }

    for (uint64_t i = 0; i < direct_methods_size; i++) {
        auto method = directMethods[i];
        patchMethod(begin, location.c_str(), dexSize, dexIndex,
                    method.method_idx_delta_, method.code_off_);
    }
    for (uint64_t i = 0; i < virtual_methods_size; i++) {
        auto method = virtualMethods[i];
        patchMethod(begin, location.c_str(), dexSize, dexIndex,
                    method.method_idx_delta_, method.code_off_);
    }

    delete[] directMethods;
    delete[] virtualMethods;
}

PARALLAX_ENCRYPT void LoadClassV23(void* thiz,
                                   const void* self,
                                   const void* dex_file,
                                   const void* dex_class_def,
                                   const char* klass) {
    if(LIKELY(g_originLoadClassV23 != nullptr)) {
        patchClass(nullptr,dex_file,dex_class_def);
        g_originLoadClassV23(thiz, self, dex_file, dex_class_def, klass);
    }
}

PARALLAX_ENCRYPT bool hook_LoadClass() {
    if(g_sdkLevel < __ANDROID_API_M__) {
        return false;
    }

    char sym[256] = {0};
    find_symbol_in_elf_file(GetClassLinkerDefineClassLibPath(), sym, ARRAY_LENGTH(sym), 2,
                            "ClassLinker", "LoadClass");
    if (strlen(sym) == 0) {
        DLOGW("cannot find symbol: LoadClass");
        return false;
    }

    void *loadClassAddress = DobbySymbolResolver(GetArtLibPath(), sym);
    if (loadClassAddress == nullptr) {
        DLOGW("LoadClass address is null");
        return false;
    }

    int hookResult = DobbyHook(loadClassAddress, (dobby_dummy_func_t) LoadClassV23,
                               (dobby_dummy_func_t *) &g_originLoadClassV23);
    DLOGD("LoadClass hook result: %d", hookResult);
    return hookResult == 0;
}

PARALLAX_ENCRYPT void *DefineClassV22(void* thiz,void* self,
                                      const char* descriptor,
                                      size_t hash,
                                      void* class_loader,
                                      const void* dex_file,
                                      const void* dex_class_def) {
    if(LIKELY(g_originDefineClassV22 != nullptr)) {
        patchClass(descriptor,dex_file,dex_class_def);
        return g_originDefineClassV22(thiz,self,descriptor,hash,class_loader,dex_file,dex_class_def);
    }
    return nullptr;
}

PARALLAX_ENCRYPT void *DefineClassV21(void* thiz,
                                      const char* descriptor,
                                      void* class_loader,
                                      const void* dex_file,
                                      const void* dex_class_def) {
    if(LIKELY(g_originDefineClassV21 != nullptr)) {
        patchClass(descriptor,dex_file,dex_class_def);
        return g_originDefineClassV21(thiz,descriptor,class_loader,dex_file,dex_class_def);
    }
    return nullptr;
}

PARALLAX_ENCRYPT bool hook_DefineClass() {
    char sym[256] = {0};
    find_symbol_in_elf_file(GetClassLinkerDefineClassLibPath(), sym, ARRAY_LENGTH(sym), 2,
                            "ClassLinker", "DefineClass");

    if(strlen(sym) == 0) {
        DLOGW("cannot find symbol: DefineClass");
        return false;
    }

    void* defineClassAddress = DobbySymbolResolver(GetClassLinkerDefineClassLibPath(), sym);
    if(defineClassAddress == nullptr) {
        DLOGE("DefineClass address is null, sym: %s", sym);
        return false;
    }

    int hookResult;
    if(g_sdkLevel >= __ANDROID_API_L_MR1__) {
        hookResult = DobbyHook(defineClassAddress, (dobby_dummy_func_t) DefineClassV22,
                               (dobby_dummy_func_t *) &g_originDefineClassV22);
    } else {
        hookResult = DobbyHook(defineClassAddress, (dobby_dummy_func_t) DefineClassV21,
                               (dobby_dummy_func_t *) &g_originDefineClassV21);
    }

    if(hookResult == 0) {
        DLOGD("DefineClass hook success");
        return true;
    }
    DLOGE("DefineClass hook fail: %d", hookResult);
    return false;
}

// Retained as dormant compatibility helpers for older configurations. The default runtime
// no longer installs these broad process-wide hooks from parallax_hook().
const char *getArtLibName() {
    if (g_sdkLevel >= 29) {
        return "libartbase.so";
    }
    return "libart.so";
}

PARALLAX_ENCRYPT void* fake_mmap(void* __addr, size_t __size, int __prot, int __flags,
                                 int __fd, off_t __offset){
    BYTEHOOK_STACK_SCOPE();
    return BYTEHOOK_CALL_PREV(fake_mmap,__addr,__size,__prot,__flags,__fd,__offset);
}

PARALLAX_ENCRYPT void hook_mmap(){
    // Intentionally disabled for compatibility. Method restoration uses targeted mprotect.
}

PARALLAX_ENCRYPT int fake_execve(const char *pathname, char *const argv[], char *const envp[]) {
    BYTEHOOK_STACK_SCOPE();
    return BYTEHOOK_CALL_PREV(fake_execve, pathname, argv, envp);
}

PARALLAX_ENCRYPT ssize_t fake_write(int fd, const void *const buf, size_t count) {
    BYTEHOOK_STACK_SCOPE();
    return BYTEHOOK_CALL_PREV(fake_write, fd, buf, count);
}

PARALLAX_ENCRYPT void hook_execve(){
    // Intentionally disabled: ART/game plugin optimization is legitimate runtime behavior.
}

PARALLAX_ENCRYPT void hook_write(){
    // Intentionally disabled: do not intercept unrelated app/game DEX or file writes.
}
