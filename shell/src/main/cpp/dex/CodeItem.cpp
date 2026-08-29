//
// Created by parallax
//
#include "CodeItem.h"

#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <random>
#include <unistd.h>
#include <vector>

#include "parallax_crypto.h"
#include "parallax_risk.h"

extern uint8_t PARALLAX_UNKNOWN_DATA[];

namespace {
std::once_flag g_runtime_key_once;
std::array<uint8_t, 32> g_runtime_key{};
std::atomic<uint64_t> g_runtime_nonce_counter{1};
constexpr size_t RUNTIME_TAG_SIZE = 16;

void initRuntimeKey() {
    // Mix fresh process entropy through the already build-bound native secret. This key
    // never exists in the APK and changes on every process start, so a snapshot of the
    // persistent code-item vault contains only runtime-wrapped instruction bytes.
    std::array<uint8_t, 48> seed{};
    std::random_device random;
    for (size_t i = 0; i < 32; ++i) {
        seed[i] = static_cast<uint8_t>(random());
    }
    const uint64_t pid = static_cast<uint64_t>(getpid());
    const uintptr_t addressSalt = reinterpret_cast<uintptr_t>(&g_runtime_key);
    memcpy(seed.data() + 32, &pid, sizeof(pid));
    memcpy(seed.data() + 40, &addressSalt,
           sizeof(addressSalt) < 8 ? sizeof(addressSalt) : 8);

    auto derived = hmac_sha256(PARALLAX_UNKNOWN_DATA,
                               16,
                               seed.data(),
                               seed.size());
    secure_zero(seed.data(), seed.size());
    if (derived.size() == g_runtime_key.size()) {
        memcpy(g_runtime_key.data(), derived.data(), g_runtime_key.size());
        secure_zero(derived.data(), derived.size());
        return;
    }

    // Cryptographic helper failure should be vanishingly rare; still avoid leaving an all
    // zero wrapper key because that would turn this layer into a predictable no-op.
    for (size_t i = 0; i < g_runtime_key.size(); ++i) {
        g_runtime_key[i] = static_cast<uint8_t>(random());
    }
}

uint64_t newRuntimeNonce(const void *itemAddress, uint32_t methodIdx) {
    std::call_once(g_runtime_key_once, initRuntimeKey);
    const uint64_t sequence = g_runtime_nonce_counter.fetch_add(1, std::memory_order_relaxed);
    const uintptr_t address = reinterpret_cast<uintptr_t>(itemAddress);
    uint8_t material[24] = {0};
    memcpy(material, &sequence, sizeof(sequence));
    memcpy(material + 8, &address, sizeof(address) < 8 ? sizeof(address) : 8);
    memcpy(material + 16, &methodIdx, sizeof(methodIdx));
    const uint32_t pid = static_cast<uint32_t>(getpid());
    memcpy(material + 20, &pid, sizeof(pid));
    auto digest = hmac_sha256(g_runtime_key.data(), g_runtime_key.size(), material, sizeof(material));
    secure_zero(material, sizeof(material));
    uint64_t nonce = sequence;
    if (digest.size() >= sizeof(nonce)) {
        memcpy(&nonce, digest.data(), sizeof(nonce));
        secure_zero(digest.data(), digest.size());
    }
    return nonce;
}

bool runtimeCrypt(uint32_t methodIdx,
                  uint64_t runtimeNonce,
                  const uint8_t *input,
                  uint8_t *output,
                  size_t length) {
    if (input == nullptr || output == nullptr || length == 0) {
        return false;
    }
    std::call_once(g_runtime_key_once, initRuntimeKey);

    // AES-CTR is intentionally used only for this transient in-process re-wrap. The
    // persistent APK payload is AES-GCM authenticated. Here we need a fast reversible
    // stream so the long-lived method vault is not directly reusable while avoiding the
    // huge cost of one HMAC per tiny block on large applications.
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int ret = mbedtls_aes_setkey_enc(&ctx, g_runtime_key.data(), 256);
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    uint8_t nonceCounter[16] = {0};
    memcpy(nonceCounter, &runtimeNonce, sizeof(runtimeNonce));
    memcpy(nonceCounter + 8, &methodIdx, sizeof(methodIdx));
    const uint32_t domain = 0x32545850u; // "PXT2" domain separator, little-endian.
    memcpy(nonceCounter + 12, &domain, sizeof(domain));

    uint8_t streamBlock[16] = {0};
    size_t nonceOffset = 0;
    ret = mbedtls_aes_crypt_ctr(&ctx,
                                length,
                                &nonceOffset,
                                nonceCounter,
                                streamBlock,
                                input,
                                output);

    secure_zero(nonceCounter, sizeof(nonceCounter));
    secure_zero(streamBlock, sizeof(streamBlock));
    mbedtls_aes_free(&ctx);
    return ret == 0;
}

bool computeRuntimeTag(uint32_t methodIdx,
                       uint64_t runtimeNonce,
                       const uint8_t *wrapped,
                       size_t length,
                       uint8_t out[RUNTIME_TAG_SIZE]) {
    if (wrapped == nullptr || out == nullptr || length == 0) {
        return false;
    }
    std::call_once(g_runtime_key_once, initRuntimeKey);

    uint8_t context[16] = {0};
    memcpy(context, &methodIdx, sizeof(methodIdx));
    memcpy(context + 4, &runtimeNonce, sizeof(runtimeNonce));
    const uint32_t size32 = static_cast<uint32_t>(length);
    memcpy(context + 12, &size32, sizeof(size32));

    auto tagKey = hmac_sha256(g_runtime_key.data(),
                              g_runtime_key.size(),
                              context,
                              sizeof(context));
    secure_zero(context, sizeof(context));
    if (tagKey.size() != 32) {
        if (!tagKey.empty()) {
            secure_zero(tagKey.data(), tagKey.size());
        }
        return false;
    }

    auto tag = hmac_sha256(tagKey.data(), tagKey.size(), wrapped, length);
    secure_zero(tagKey.data(), tagKey.size());
    if (tag.size() < RUNTIME_TAG_SIZE) {
        if (!tag.empty()) {
            secure_zero(tag.data(), tag.size());
        }
        return false;
    }

    memcpy(out, tag.data(), RUNTIME_TAG_SIZE);
    secure_zero(tag.data(), tag.size());
    return true;
}

bool verifyRuntimeTag(uint32_t methodIdx,
                      uint64_t runtimeNonce,
                      const uint8_t *wrapped,
                      size_t length,
                      const uint8_t expected[RUNTIME_TAG_SIZE]) {
    uint8_t actual[RUNTIME_TAG_SIZE] = {0};
    if (!computeRuntimeTag(methodIdx, runtimeNonce, wrapped, length, actual)) {
        secure_zero(actual, sizeof(actual));
        return false;
    }
    const bool valid = constant_time_equal(actual, expected, RUNTIME_TAG_SIZE);
    secure_zero(actual, sizeof(actual));
    return valid;
}
} // namespace

uint32_t parallax::data::CodeItem::getMethodIdx() const {
    return mMethodIdx;
}

void parallax::data::CodeItem::setMethodIdx(uint32_t methodIdx) {
    CodeItem::mMethodIdx = methodIdx;
}

uint32_t parallax::data::CodeItem::getInsnsSize() const {
    return mInsnsSize;
}

void parallax::data::CodeItem::setInsnsSize(uint32_t size) {
    CodeItem::mInsnsSize = size;
}

uint8_t *parallax::data::CodeItem::getInsns() const {
    // Do not leave the builder-XOR instruction stream sitting plaintext-equivalent in the
    // long-lived vault. Verify the wrapped bytes first, then decrypt only into per-thread
    // scratch for the short copy window used by patchMethod().
    thread_local std::vector<uint8_t> scratch;
    if (!scratch.empty()) {
        secure_zero(scratch.data(), scratch.size());
    }
    if (mInsns == nullptr || mInsnsSize == 0
            || !verifyRuntimeTag(mMethodIdx, mRuntimeNonce, mInsns, mInsnsSize, mRuntimeTag)) {
        if (!scratch.empty()) {
            secure_zero(scratch.data(), scratch.size());
        }
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return nullptr;
    }

    scratch.resize(mInsnsSize);
    if (!runtimeCrypt(mMethodIdx, mRuntimeNonce, mInsns, scratch.data(), mInsnsSize)) {
        secure_zero(scratch.data(), scratch.size());
        reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        return nullptr;
    }
    return scratch.data();
}

void parallax::data::CodeItem::setInsns(uint8_t *insns) {
    CodeItem::mInsns = insns;
}

parallax::data::CodeItem::CodeItem(uint32_t methodIdx, uint32_t size,
                   uint8_t *insns): mMethodIdx(methodIdx),
                                    mOffsetDex(0),
                                    mInsnsSize(size),
                                    mRuntimeNonce(newRuntimeNonce(this, methodIdx)),
                                    mRuntimeTag{0},
                                    mInsns(insns) {
    // Symmetric stream operation: constructor converts builder-XOR bytes into the
    // per-process wrapped representation in place. A keyed runtime tag then binds the
    // wrapped bytes to this method/nonce so memory edits are rejected before restoration.
    if (mInsns != nullptr && mInsnsSize != 0) {
        std::vector<uint8_t> wrapped(mInsnsSize);
        if (runtimeCrypt(mMethodIdx, mRuntimeNonce, mInsns, wrapped.data(), wrapped.size())) {
            memcpy(mInsns, wrapped.data(), wrapped.size());
            if (!computeRuntimeTag(mMethodIdx,
                                   mRuntimeNonce,
                                   mInsns,
                                   mInsnsSize,
                                   mRuntimeTag)) {
                mInsnsSize = 0;
                reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
            }
        } else {
            mInsnsSize = 0;
            reportSecurityRisk(PARALLAX_SECURITY_RUNTIME_TAMPER_BIT);
        }
        secure_zero(wrapped.data(), wrapped.size());
    }
}

parallax::data::CodeItem::~CodeItem() {
    secure_zero(mRuntimeTag, sizeof(mRuntimeTag));
}
