//
// Created by parallax
//

#include "MultiDexCode.h"

#include <limits>
#include <string>
#include <utility>
#include <sys/mman.h>
#include <unistd.h>

#include "common/obfuscate.h"
#include "parallax_crypto.h"
#include "parallax_risk.h"

extern uint8_t PARALLAX_UNKNOWN_DATA[];

namespace {
constexpr uint8_t CODE_ITEM_MAGIC[] = {'P', 'C', 'I', '2'};
constexpr size_t CODE_ITEM_MAGIC_SIZE = sizeof(CODE_ITEM_MAGIC);
constexpr size_t CODE_ITEM_NONCE_SIZE = 12;
constexpr size_t CODE_ITEM_GCM_TAG_SIZE = 16;
constexpr uint8_t INVALID_CODE_ITEM_BUFFER[4] = {0, 0, 0, 0};
constexpr uint32_t MAX_METHOD_INDEX = 65535u;

bool isSealedCodeItem(const uint8_t *buffer, size_t size) {
    return buffer != nullptr
           && size > CODE_ITEM_MAGIC_SIZE + CODE_ITEM_NONCE_SIZE + CODE_ITEM_GCM_TAG_SIZE
           && memcmp(buffer, CODE_ITEM_MAGIC, CODE_ITEM_MAGIC_SIZE) == 0;
}

size_t pageSize() {
    const long value = sysconf(_SC_PAGESIZE);
    return value > 0 ? static_cast<size_t>(value) : 4096u;
}

bool roundUpToPage(size_t size, size_t *roundedOut) {
    if (roundedOut == nullptr || size == 0) {
        return false;
    }
    const size_t page = pageSize();
    if (size > std::numeric_limits<size_t>::max() - (page - 1u)) {
        return false;
    }
    *roundedOut = ((size + page - 1u) / page) * page;
    return true;
}

void releaseOwnedVault(uint8_t *&mapping,
                       size_t &mappingSize,
                       uint8_t *&buffer,
                       size_t &bufferSize) {
    if (mapping == nullptr || mappingSize == 0) {
        mapping = nullptr;
        mappingSize = 0;
        buffer = nullptr;
        bufferSize = 0;
        return;
    }

    if (buffer != nullptr && bufferSize != 0) {
        size_t rounded = 0;
        if (roundUpToPage(bufferSize, &rounded)) {
            // The useful middle pages are normally RW, but explicitly restore write access
            // before zeroization so this remains safe if a future hardening pass makes them RO.
            (void) mprotect(buffer, rounded, PROT_READ | PROT_WRITE);
            secure_zero(buffer, bufferSize);
            (void) munlock(buffer, rounded);
        }
    }

    (void) munmap(mapping, mappingSize);
    mapping = nullptr;
    mappingSize = 0;
    buffer = nullptr;
    bufferSize = 0;
}

uint8_t *allocateProtectedVault(const uint8_t *plaintext,
                                size_t size,
                                uint8_t **mappingOut,
                                size_t *mappingSizeOut) {
    if (plaintext == nullptr || size == 0 || mappingOut == nullptr || mappingSizeOut == nullptr) {
        return nullptr;
    }
    *mappingOut = nullptr;
    *mappingSizeOut = 0;

    size_t dataMapSize = 0;
    if (!roundUpToPage(size, &dataMapSize)) {
        return nullptr;
    }

    const size_t page = pageSize();
    if (dataMapSize > std::numeric_limits<size_t>::max() - (page * 2u)) {
        return nullptr;
    }
    const size_t totalSize = dataMapSize + page * 2u;

    // Reserve the whole range as inaccessible, then open only the middle pages. The first
    // and last pages stay PROT_NONE guard pages so linear over-read/over-write attempts hit
    // an immediate process-local fault instead of adjacent heap/native objects.
    void *raw = mmap(nullptr,
                     totalSize,
                     PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1,
                     0);
    if (raw == MAP_FAILED) {
        return nullptr;
    }

    auto *base = static_cast<uint8_t *>(raw);
    uint8_t *data = base + page;
    if (mprotect(data, dataMapSize, PROT_READ | PROT_WRITE) != 0) {
        (void) munmap(raw, totalSize);
        return nullptr;
    }

    memcpy(data, plaintext, size);

#ifdef MADV_DONTDUMP
    // Keep the long-lived authenticated vault out of ordinary core/process dump paths.
    (void) madvise(data, dataMapSize, MADV_DONTDUMP);
#endif
#ifdef MADV_DONTFORK
    // A child process does not need a clone of the protected method vault. Avoid creating
    // a second copy through fork-style process creation where the platform supports it.
    (void) madvise(data, dataMapSize, MADV_DONTFORK);
#endif

    // Best effort: prevent paging the sensitive runtime vault to swap. Android may reject
    // this under a strict memlock limit; failure is non-fatal because DONTDUMP + wrapping
    // and process dump hardening remain active.
    (void) mlock(data, dataMapSize);

    *mappingOut = base;
    *mappingSizeOut = totalSize;
    return data;
}

parallax::data::CodeItem *invalidCodeItem() {
    reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
    return new parallax::data::CodeItem(0, 0, nullptr);
}
} // namespace

parallax::data::MultiDexCode* parallax::data::MultiDexCode::getInst(){
    static auto *m_inst = new MultiDexCode();
    return m_inst;
}

void parallax::data::MultiDexCode::init(uint8_t* buffer, size_t size){
    // init_app can be reached more than once in unusual lifecycle/plugin flows. Re-parsing
    // the same envelope would construct CodeItem objects over bytes that are already
    // runtime-wrapped and corrupt the instruction vault. Keep the first authenticated
    // parse alive and make subsequent reads report zero new DEX entries.
    if (m_source_buffer == buffer
        && m_source_size == size
        && m_buffer != nullptr
        && (m_owned_buffer != nullptr
#ifndef DEBUG
            || m_buffer == INVALID_CODE_ITEM_BUFFER
#endif
           )) {
        m_skip_parse = true;
        DLOGD("code-item vault already initialized; skip duplicate parse");
        return;
    }

    m_skip_parse = false;
    releaseOwnedVault(m_owned_mapping,
                      m_owned_mapping_size,
                      m_owned_buffer,
                      m_owned_buffer_size);
    m_source_buffer = buffer;
    m_source_size = size;

    // Fail closed in release builds: the method-body sidecar must be the authenticated
    // PCI2 envelope emitted by the matching Parallax packer. A raw/plain sidecar would
    // make APK extraction immediately reusable, which defeats DEX hollowing.
    if (!isSealedCodeItem(buffer, size)) {
#ifdef DEBUG
        DLOGW("debug build accepted legacy plaintext code-item payload");
        m_buffer = buffer;
        m_size = size;
        return;
#else
        DLOGE("missing PCI2 protected code-item envelope");
        reportSecurityRisk(PARALLAX_SECURITY_PAYLOAD_TAMPER_BIT);
        m_buffer = const_cast<uint8_t *>(INVALID_CODE_ITEM_BUFFER);
        m_size = sizeof(INVALID_CODE_ITEM_BUFFER);
        return;
#endif
    }

    const char *buildKey = AY_OBFUSCATE(PARALLAX_BUILD_KEY);
    const char *keyPrefix = AY_OBFUSCATE("Parallax/codeitem/encryption/v2/");
    std::string keyMaterial = std::string(keyPrefix) + buildKey;
    auto payloadKey = hmac_sha256(
            PARALLAX_UNKNOWN_DATA,
            16,
            reinterpret_cast<const uint8_t *>(keyMaterial.data()),
            keyMaterial.size());
    if (payloadKey.size() != 32) {
        DLOGE("cannot derive code-item payload key");
        reportSecurityRisk(PARALLAX_SECURITY_PAYLOAD_TAMPER_BIT);
        m_buffer = const_cast<uint8_t *>(INVALID_CODE_ITEM_BUFFER);
        m_size = sizeof(INVALID_CODE_ITEM_BUFFER);
        return;
    }

    const uint8_t *nonce = buffer + CODE_ITEM_MAGIC_SIZE;
    const uint8_t *ciphertext = nonce + CODE_ITEM_NONCE_SIZE;
    const size_t ciphertextSize = size - CODE_ITEM_MAGIC_SIZE - CODE_ITEM_NONCE_SIZE;
    const char *aad = AY_OBFUSCATE("Parallax/codeitem/payload/v2");

    auto plaintext = aes_gcm_decrypt(payloadKey.data(),
                                     256,
                                     nonce,
                                     CODE_ITEM_NONCE_SIZE,
                                     reinterpret_cast<const uint8_t *>(aad),
                                     strlen(aad),
                                     ciphertext,
                                     ciphertextSize);
    secure_zero(payloadKey.data(), payloadKey.size());

    if (plaintext.size() < 4) {
        DLOGE("code-item AES-GCM authentication failed");
        reportSecurityRisk(PARALLAX_SECURITY_PAYLOAD_TAMPER_BIT);
        m_buffer = const_cast<uint8_t *>(INVALID_CODE_ITEM_BUFFER);
        m_size = sizeof(INVALID_CODE_ITEM_BUFFER);
        return;
    }

    m_owned_buffer = allocateProtectedVault(plaintext.data(),
                                            plaintext.size(),
                                            &m_owned_mapping,
                                            &m_owned_mapping_size);
    m_owned_buffer_size = plaintext.size();
    secure_zero(plaintext.data(), plaintext.size());
    plaintext.clear();
    plaintext.shrink_to_fit();

    if (m_owned_buffer == nullptr) {
        m_owned_buffer_size = 0;
        m_owned_mapping = nullptr;
        m_owned_mapping_size = 0;
        DLOGE("cannot allocate guarded native method vault");
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        m_buffer = const_cast<uint8_t *>(INVALID_CODE_ITEM_BUFFER);
        m_size = sizeof(INVALID_CODE_ITEM_BUFFER);
        return;
    }

    m_buffer = m_owned_buffer;
    m_size = m_owned_buffer_size;
    DLOGD("authenticated code-item vault opened in guarded DONTDUMP native pages: %zu bytes",
          m_size);
}

uint16_t parallax::data::MultiDexCode::readVersion(){
    return readUInt16(0);
}

uint16_t parallax::data::MultiDexCode::readDexCount(){
    if (m_skip_parse) {
        return 0;
    }
    return readUInt16(2);
}

uint32_t* parallax::data::MultiDexCode::readDexCodeIndex(int* count){
    if (count == nullptr || m_buffer == nullptr || m_size < 4) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        if (count != nullptr) {
            *count = 0;
        }
        return nullptr;
    }

    const uint16_t dexCount = readDexCount();
    const size_t indexBytes = static_cast<size_t>(dexCount) * sizeof(uint32_t);
    if (indexBytes > m_size - 4) {
        DLOGE("runtime vault DEX index table exceeds payload");
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        *count = 0;
        return reinterpret_cast<uint32_t *>(m_buffer + 4);
    }

    *count = dexCount;
    return reinterpret_cast<uint32_t *>(m_buffer + 4);
}

parallax::data::CodeItem* parallax::data::MultiDexCode::nextCodeItem(uint32_t* offset) {
    if (offset == nullptr || m_buffer == nullptr || *offset > m_size || m_size - *offset < 8) {
        DLOGE("runtime vault code-item header exceeds payload");
        return invalidCodeItem();
    }

    const uint32_t itemOffset = *offset;
    const uint32_t methodIdx = readUInt32(itemOffset);
    const uint32_t insnsSize = readUInt32(itemOffset + 4);
    const size_t insnsOffset = static_cast<size_t>(itemOffset) + 8u;
    if (methodIdx > MAX_METHOD_INDEX
            || insnsOffset > m_size
            || static_cast<size_t>(insnsSize) > m_size - insnsOffset) {
        DLOGE("runtime vault code-item metadata is invalid");
        *offset = static_cast<uint32_t>(m_size > UINT32_MAX ? UINT32_MAX : m_size);
        return invalidCodeItem();
    }

    auto* insns = m_buffer + insnsOffset;
    const size_t nextOffset = insnsOffset + static_cast<size_t>(insnsSize);
    *offset = static_cast<uint32_t>(nextOffset);
    return new CodeItem(methodIdx, insnsSize, insns);
}

uint8_t parallax::data::MultiDexCode::readUInt8(uint32_t offset){
    uint8_t t = 0;
    if (m_buffer == nullptr || static_cast<size_t>(offset) >= m_size) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return t;
    }
    memcpy(&t, m_buffer + offset, sizeof(uint8_t));
    return t;
}

uint16_t parallax::data::MultiDexCode::readUInt16(uint32_t offset){
    uint16_t t = 0;
    const size_t off = static_cast<size_t>(offset);
    if (m_buffer == nullptr || off > m_size || m_size - off < sizeof(uint16_t)) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return t;
    }
    memcpy(&t, m_buffer + offset, sizeof(uint16_t));
    return t;
}

uint32_t parallax::data::MultiDexCode::readUInt32(uint32_t offset){
    uint32_t t = 0;
    const size_t off = static_cast<size_t>(offset);
    if (m_buffer == nullptr || off > m_size || m_size - off < sizeof(uint32_t)) {
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return t;
    }
    memcpy(&t, m_buffer + offset, sizeof(uint32_t));
    return t;
}
