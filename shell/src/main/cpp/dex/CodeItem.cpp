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

#include "parallax_crypto.h"

extern uint8_t PARALLAX_UNKNOWN_DATA[];

namespace {
std::once_flag g_runtime_key_once;
std::array<uint8_t, 32> g_runtime_key{};

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

void runtimeCrypt(uint32_t methodIdx,
                  const uint8_t *input,
                  uint8_t *output,
                  size_t length) {
    if (input == nullptr || output == nullptr || length == 0) {
        return;
    }
    std::call_once(g_runtime_key_once, initRuntimeKey);

    size_t offset = 0;
    uint32_t blockCounter = 0;
    while (offset < length) {
        uint8_t blockInput[8] = {0};
        memcpy(blockInput, &methodIdx, sizeof(methodIdx));
        memcpy(blockInput + sizeof(methodIdx), &blockCounter, sizeof(blockCounter));
        auto stream = hmac_sha256(g_runtime_key.data(),
                                  g_runtime_key.size(),
                                  blockInput,
                                  sizeof(blockInput));
        if (stream.empty()) {
            return;
        }
        const size_t remaining = length - offset;
        const size_t take = remaining < stream.size() ? remaining : stream.size();
        for (size_t i = 0; i < take; ++i) {
            output[offset + i] = static_cast<uint8_t>(input[offset + i] ^ stream[i]);
        }
        secure_zero(stream.data(), stream.size());
        offset += take;
        ++blockCounter;
    }
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
    // long-lived vault. Decrypt the per-process wrapper only into per-thread scratch for
    // the short copy window used by patchMethod().
    thread_local std::vector<uint8_t> scratch;
    if (!scratch.empty()) {
        secure_zero(scratch.data(), scratch.size());
    }
    scratch.resize(mInsnsSize);
    runtimeCrypt(mMethodIdx, mInsns, scratch.data(), mInsnsSize);
    return scratch.data();
}

void parallax::data::CodeItem::setInsns(uint8_t *insns) {
    CodeItem::mInsns = insns;
}

parallax::data::CodeItem::CodeItem(uint32_t methodIdx, uint32_t size,
                   uint8_t *insns): mMethodIdx(methodIdx), mOffsetDex(0), mInsnsSize(size), mInsns(insns) {
    // Symmetric stream operation: constructor converts builder-XOR bytes into the
    // per-process wrapped representation in place. getInsns() reverses it on demand.
    if (mInsns != nullptr && mInsnsSize != 0) {
        std::vector<uint8_t> wrapped(mInsnsSize);
        runtimeCrypt(mMethodIdx, mInsns, wrapped.data(), wrapped.size());
        memcpy(mInsns, wrapped.data(), wrapped.size());
        secure_zero(wrapped.data(), wrapped.size());
    }
}

parallax::data::CodeItem::~CodeItem() {

}
