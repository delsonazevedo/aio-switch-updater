#pragma once

#include <stdint.h>
#include <vector>

namespace crypto {

// AES-XTS (Nintendo style, big-endian sector tweak)
bool aes_xts_decrypt(const uint8_t* key_256bit, uint64_t sector_offset, const uint8_t* input, uint8_t* output, size_t size);

// AES-CTR
bool aes_ctr_decrypt(const uint8_t* key_128bit, const uint8_t* ctr_16byte, const uint8_t* input, uint8_t* output, size_t size);

// AES-ECB
bool aes_ecb_decrypt(const uint8_t* key_128bit, const uint8_t* input, uint8_t* output, size_t size);

} // namespace crypto
