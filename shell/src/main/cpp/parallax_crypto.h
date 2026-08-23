//
// Created by parallax on 2025/11/26.
//

#ifndef PARALLAX_PARALLAX_CRYPTO_H
#define PARALLAX_PARALLAX_CRYPTO_H

#include <vector>
#include <stdint.h>
#include <stddef.h>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include "common/parallax_log.h"

std::vector<uint8_t> hmac_sha256(const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *input,
                                 size_t input_len);

std::vector<uint8_t> aes_cbc_decrypt(const uint8_t *key,
                                     size_t key_bits,
                                     const uint8_t *iv,
                                     const uint8_t *in,
                                     size_t inlen);
bool constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length);
#endif //PARALLAX_PARALLAX_CRYPTO_H
