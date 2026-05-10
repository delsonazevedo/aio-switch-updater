#include "crypto/aes.hpp"
#include <mbedtls/aes.h>
#include <string.h>

namespace crypto {

bool aes_xts_decrypt(const uint8_t* key_256bit, uint64_t sector_offset, const uint8_t* input, uint8_t* output, size_t size) {
    if (size % 0x200 != 0) return false;

    mbedtls_aes_xts_context ctx;
    mbedtls_aes_xts_init(&ctx);
    
    // mbedtls uses keybits = 256 for 2x128 bit XTS keys
    if (mbedtls_aes_xts_setkey_dec(&ctx, key_256bit, 256) != 0) {
        mbedtls_aes_xts_free(&ctx);
        return false;
    }

    uint8_t data_unit[16];
    uint64_t sector = sector_offset;
    
    for (size_t i = 0; i < size; i += 0x200) {
        memset(data_unit, 0, 16);
        // Nintendo uses Big-Endian sector representation
        uint64_t s = sector++;
        for (int j = 15; j >= 0; j--) {
            data_unit[j] = (uint8_t)(s & 0xFF);
            s >>= 8;
        }

        if (mbedtls_aes_crypt_xts(&ctx, MBEDTLS_AES_DECRYPT, 0x200, data_unit, input + i, output + i) != 0) {
            mbedtls_aes_xts_free(&ctx);
            return false;
        }
    }

    mbedtls_aes_xts_free(&ctx);
    return true;
}

bool aes_ctr_decrypt(const uint8_t* key_128bit, const uint8_t* ctr_16byte, const uint8_t* input, uint8_t* output, size_t size) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    
    if (mbedtls_aes_setkey_enc(&ctx, key_128bit, 128) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    uint8_t nonce_counter[16];
    memcpy(nonce_counter, ctr_16byte, 16);
    
    uint8_t stream_block[16];
    size_t nc_off = 0;

    if (mbedtls_aes_crypt_ctr(&ctx, size, &nc_off, nonce_counter, stream_block, input, output) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    mbedtls_aes_free(&ctx);
    return true;
}

bool aes_ecb_decrypt(const uint8_t* key_128bit, const uint8_t* input, uint8_t* output, size_t size) {
    if (size % 16 != 0) return false;

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    
    if (mbedtls_aes_setkey_dec(&ctx, key_128bit, 128) != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    for (size_t i = 0; i < size; i += 16) {
        if (mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, input + i, output + i) != 0) {
            mbedtls_aes_free(&ctx);
            return false;
        }
    }

    mbedtls_aes_free(&ctx);
    return true;
}

} // namespace crypto
