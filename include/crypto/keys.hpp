#pragma once

#include <string>
#include <vector>
#include <map>
#include <stdint.h>

namespace crypto {

struct KeySet {
    uint8_t header_key[32]; // AES-XTS requires 32 bytes (256-bit total, two 128-bit keys)
    std::map<uint8_t, std::vector<uint8_t>> key_area_key_application; // key revision -> 16 bytes key
    std::map<uint8_t, std::vector<uint8_t>> key_area_key_ocean; // key revision -> 16 bytes key
    std::map<uint8_t, std::vector<uint8_t>> key_area_key_system; // key revision -> 16 bytes key
    std::map<uint8_t, std::vector<uint8_t>> titlekeks; // key revision -> 16 bytes key
    std::map<uint8_t, std::vector<uint8_t>> master_keys; // key revision -> 16 bytes key
    bool loaded = false;
    std::map<std::string, std::vector<uint8_t>> title_keys;
};

extern KeySet g_keys;

// Loads keys from sdmc:/switch/prod.keys or sdmc:/prod.keys
bool LoadKeys(KeySet& keys);

// Hex string to bytes
std::vector<uint8_t> ParseHexKey(const std::string& hex);

} // namespace crypto
