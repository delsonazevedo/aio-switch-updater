#include "crypto/keys.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <string.h>

namespace crypto {

KeySet g_keys;

std::vector<uint8_t> ParseHexKey(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        if (i + 1 < hex.length()) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
    }
    return bytes;
}

bool LoadKeys(KeySet& keys) {
    std::vector<std::string> search_paths = {
        "/switch/prod.keys",
        "/prod.keys"
    };

    std::string key_path = "";
    for (const auto& path : search_paths) {
        if (std::filesystem::exists(path)) {
            key_path = path;
            break;
        }
    }

    if (key_path.empty()) {
        return false; // No keys found
    }

    std::ifstream file(key_path);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        // remove whitespace
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        auto delim = line.find('=');
        if (delim != std::string::npos) {
            std::string key_name = line.substr(0, delim);
            std::string key_value = line.substr(delim + 1);

            if (key_name == "header_key") {
                std::vector<uint8_t> bytes = ParseHexKey(key_value);
                if (bytes.size() >= 32) {
                    memcpy(keys.header_key, bytes.data(), 32);
                }
            } else if (key_name.find("key_area_key_application_") == 0) {
                std::string rev_str = key_name.substr(25); // len("key_area_key_application_")
                uint8_t rev = (uint8_t)strtol(rev_str.c_str(), NULL, 16);
                std::vector<uint8_t> bytes = ParseHexKey(key_value);
                if (bytes.size() >= 16) {
                    keys.key_area_key_application[rev] = bytes;
                }
            } else if (key_name.find("key_area_key_ocean_") == 0) {
                std::string rev_str = key_name.substr(19);
                uint8_t rev = (uint8_t)strtol(rev_str.c_str(), NULL, 16);
                std::vector<uint8_t> bytes = ParseHexKey(key_value);
                if (bytes.size() >= 16) {
                    keys.key_area_key_ocean[rev] = bytes;
                }
            } else if (key_name.find("key_area_key_system_") == 0) {
                std::string rev_str = key_name.substr(20);
                uint8_t rev = (uint8_t)strtol(rev_str.c_str(), NULL, 16);
                std::vector<uint8_t> bytes = ParseHexKey(key_value);
                if (bytes.size() >= 16) {
                    keys.key_area_key_system[rev] = bytes;
                }
            } else if (key_name.find("master_key_") == 0) {
                std::string rev_str = key_name.substr(11); // len("master_key_")
                uint8_t rev = (uint8_t)strtol(rev_str.c_str(), NULL, 16);
                std::vector<uint8_t> bytes = ParseHexKey(key_value);
                if (bytes.size() >= 16) {
                    keys.master_keys[rev] = bytes;
                }
            } else if (key_name.find("titlekek_") == 0) {
                std::string rev_str = key_name.substr(9); // len("titlekek_")
                uint8_t rev = (uint8_t)strtol(rev_str.c_str(), NULL, 16);
                std::vector<uint8_t> bytes = ParseHexKey(key_value);
                if (bytes.size() >= 16) {
                    keys.titlekeks[rev] = bytes;
                }
            }
        }
    }

    std::vector<std::string> title_search_paths = {
        "/switch/title.keys",
        "/title.keys"
    };

    std::string title_key_path = "";
    for (const auto& path : title_search_paths) {
        if (std::filesystem::exists(path)) {
            title_key_path = path;
            break;
        }
    }

    if (!title_key_path.empty()) {
        std::ifstream tfile(title_key_path);
        if (tfile.is_open()) {
            std::string tline;
            while (std::getline(tfile, tline)) {
                tline.erase(std::remove_if(tline.begin(), tline.end(), ::isspace), tline.end());
                if (tline.empty() || tline[0] == '#' || tline[0] == ';') continue;

                auto delim = tline.find('=');
                if (delim != std::string::npos) {
                    std::string rights_id = tline.substr(0, delim);
                    std::string key_value = tline.substr(delim + 1);
                    std::vector<uint8_t> bytes = ParseHexKey(key_value);
                    if (bytes.size() >= 16) {
                        std::transform(rights_id.begin(), rights_id.end(), rights_id.begin(), ::tolower);
                        keys.title_keys[rights_id] = bytes;
                    }
                }
            }
        }
    }

    // Must have at least header key
    bool has_header_key = false;
    for (int i = 0; i < 32; i++) {
        if (keys.header_key[i] != 0) has_header_key = true;
    }
    
    keys.loaded = has_header_key;
    return keys.loaded;
}

} // namespace crypto
