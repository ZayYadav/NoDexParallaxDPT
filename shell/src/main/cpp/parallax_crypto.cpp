//
// Created by parallax on 2025/11/26.
//

#include "parallax_crypto.h"
#include <cstring>
#include <mbedtls/platform_util.h>

bool constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    if (left == nullptr || right == nullptr) return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}

void secure_zero(void *data, size_t length) {
    if (data != nullptr && length != 0) {
        mbedtls_platform_zeroize(data, length);
    }
}

std::vector<uint8_t> hmac_sha256(const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *input,
                                 size_t input_len) {
    if (key == nullptr || key_len == 0 || input == nullptr || input_len == 0) {
        DLOGE("invalid hmac input");
        return {};
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == nullptr) {
        DLOGE("mbedtls sha256 unavailable");
        return {};
    }

    std::vector<uint8_t> out(32);
    int ret = mbedtls_md_hmac(md_info, key, key_len, input, input_len, out.data());
    if (ret != 0) {
        DLOGE("hmac-sha256 failed: %d", ret);
        return {};
    }
    return out;
}

std::vector<uint8_t> aes_cbc_decrypt(const uint8_t *key,
                                     size_t key_bits,
                                     const uint8_t *iv,
                                     const uint8_t *in,
                                     size_t inlen) {
    if (key == nullptr || iv == nullptr || in == nullptr || inlen == 0 || (inlen % 16) != 0) {
        DLOGE("invalid aes cbc input");
        return {};
    }
    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        DLOGE("unsupported aes key bits: %zu", key_bits);
        return {};
    }

    std::vector<uint8_t> out_vec(inlen);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int setkey_ret = mbedtls_aes_setkey_dec(&ctx, key, static_cast<unsigned int>(key_bits));

    if(setkey_ret == 0) {
        DLOGD("set key success");
    }
    else {
        DLOGE("set key fail");
        mbedtls_aes_free(&ctx);
        return {};
    }

    uint8_t new_iv[16] = {0};
    memcpy(new_iv, iv, 16);

    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, inlen, new_iv, in, out_vec.data());

    if(ret == 0) {
        DLOGD("decrypt ret: %d", ret);
    }
    else {
        DLOGE("decrypt fail");
        mbedtls_aes_free(&ctx);
        return {};
    }

    if (!out_vec.empty()) {
        uint8_t pad = out_vec.back();
        DLOGD("padding: %d", pad);
        if (pad > 0 && pad <= 16 && pad <= out_vec.size()) {
            out_vec.resize(out_vec.size() - pad);
        } else {
            DLOGE("invalid padding");
            mbedtls_aes_free(&ctx);
            return {};
        }
    }

    mbedtls_aes_free(&ctx);

    return out_vec;
}

std::vector<uint8_t> aes_ctr_crypt(const uint8_t *key,
                                  size_t key_bits,
                                  const uint8_t *nonce_counter,
                                  const uint8_t *in,
                                  size_t inlen) {
    if (key == nullptr || nonce_counter == nullptr || in == nullptr || inlen == 0) {
        return {};
    }
    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        return {};
    }

    std::vector<uint8_t> out(inlen);
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(&ctx, key, static_cast<unsigned int>(key_bits));
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        secure_zero(out.data(), out.size());
        return {};
    }

    size_t nc_off = 0;
    uint8_t counter[16] = {0};
    uint8_t stream_block[16] = {0};
    memcpy(counter, nonce_counter, sizeof(counter));

    ret = mbedtls_aes_crypt_ctr(&ctx, inlen, &nc_off, counter, stream_block,
                                in, out.data());
    secure_zero(counter, sizeof(counter));
    secure_zero(stream_block, sizeof(stream_block));
    mbedtls_aes_free(&ctx);

    if (ret != 0) {
        secure_zero(out.data(), out.size());
        return {};
    }
    return out;
}

std::vector<uint8_t> aes_gcm_decrypt(const uint8_t *key,
                                     size_t key_bits,
                                     const uint8_t *nonce,
                                     size_t nonce_len,
                                     const uint8_t *aad,
                                     size_t aad_len,
                                     const uint8_t *in,
                                     size_t inlen) {
    constexpr size_t kTagSize = 16;
    if (key == nullptr || nonce == nullptr || nonce_len == 0 || in == nullptr || inlen <= kTagSize) {
        DLOGE("invalid aes gcm input");
        return {};
    }
    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        DLOGE("unsupported aes gcm key bits: %zu", key_bits);
        return {};
    }
    if (aad_len != 0 && aad == nullptr) {
        DLOGE("invalid aes gcm aad");
        return {};
    }

    const size_t ciphertext_len = inlen - kTagSize;
    const uint8_t *tag = in + ciphertext_len;
    std::vector<uint8_t> out(ciphertext_len);

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                 key, static_cast<unsigned int>(key_bits));
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&ctx,
                                       ciphertext_len,
                                       nonce,
                                       nonce_len,
                                       aad,
                                       aad_len,
                                       tag,
                                       kTagSize,
                                       in,
                                       out.data());
    }
    mbedtls_gcm_free(&ctx);

    if (ret != 0) {
        DLOGE("aes-gcm authentication/decryption failed: %d", ret);
        secure_zero(out.data(), out.size());
        return {};
    }
    return out;
}
