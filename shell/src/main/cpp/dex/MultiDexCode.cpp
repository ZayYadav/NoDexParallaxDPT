//
// Created by parallax
//

#include "MultiDexCode.h"

#include <string>
#include <utility>

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

bool isSealedCodeItem(const uint8_t *buffer, size_t size) {
    return buffer != nullptr
           && size > CODE_ITEM_MAGIC_SIZE + CODE_ITEM_NONCE_SIZE + CODE_ITEM_GCM_TAG_SIZE
           && memcmp(buffer, CODE_ITEM_MAGIC, CODE_ITEM_MAGIC_SIZE) == 0;
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
        && (!m_owned_buffer.empty()
#ifndef DEBUG
            || m_buffer == INVALID_CODE_ITEM_BUFFER
#endif
           )) {
        m_skip_parse = true;
        DLOGD("code-item vault already initialized; skip duplicate parse");
        return;
    }

    m_skip_parse = false;
    if (!m_owned_buffer.empty()) {
        secure_zero(m_owned_buffer.data(), m_owned_buffer.size());
        m_owned_buffer.clear();
        m_owned_buffer.shrink_to_fit();
    }
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

    m_owned_buffer = std::move(plaintext);
    m_buffer = m_owned_buffer.data();
    m_size = m_owned_buffer.size();
    DLOGD("authenticated code-item vault opened in native memory: %zu bytes", m_size);
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
    uint16_t dexCount = readDexCount();
    *count = dexCount;
    return (uint32_t*)(m_buffer + 4);
}

parallax::data::CodeItem* parallax::data::MultiDexCode::nextCodeItem(uint32_t* offset) {
    uint32_t methodIdx = readUInt32(*offset);
    uint32_t insnsSize = readUInt32(*offset + 4);
    auto* insns = (uint8_t*)(m_buffer + *offset + 8);
    *offset = (*offset + 8 + insnsSize);
    auto* codeItem = new CodeItem(methodIdx, insnsSize, insns);

    return codeItem;
}

uint8_t parallax::data::MultiDexCode::readUInt8(uint32_t offset){
    uint8_t t = 0;
    memcpy(&t, m_buffer + offset, sizeof(uint8_t));
    return t;
}

uint16_t parallax::data::MultiDexCode::readUInt16(uint32_t offset){
    uint16_t t = 0;
    memcpy(&t, m_buffer + offset, sizeof(uint16_t));
    return t;
}

uint32_t parallax::data::MultiDexCode::readUInt32(uint32_t offset){
    uint32_t t = 0;
    memcpy(&t, m_buffer + offset, sizeof(uint32_t));
    return t;
}
