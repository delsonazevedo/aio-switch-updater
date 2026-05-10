#include "crypto/nca.hpp"
#include "crypto/aes.hpp"
#include "crypto/keys.hpp"
#include <fstream>
#include <sstream>
#include <vector>
#include <string.h>
#include <stdio.h>
#include <switch.h>

namespace crypto {

extern KeySet g_keys;

#pragma pack(push, 1)

struct NcaHeader {
    uint8_t rsa_sig_1[0x100];
    uint8_t rsa_sig_2[0x100];
    uint32_t magic;
    uint8_t distribution_type;
    uint8_t content_type;
    uint8_t key_generation_old;
    uint8_t key_area_encryption_key_index;
    uint64_t nca_size;
    uint64_t program_id;
    uint32_t content_index;
    uint32_t sdk_addon_version;
    uint8_t key_generation;
    uint8_t signature_key_generation;
    uint8_t reserved[0xE];
    uint8_t rights_id[0x10];
    uint32_t section_entries[4][4]; // 4 entries of 0x10 bytes
    uint8_t section_hashes[4][0x20];
    uint8_t encrypted_keys[4][0x10]; // 0x300
    uint8_t _0x340[0xC0];
};

struct FsHeader {
    uint8_t _0x0;
    uint8_t _0x1;
    uint8_t partition_type;
    uint8_t fs_type;
    uint8_t crypt_type;
    uint8_t _0x5[0x3];
    uint8_t superblock[0x138];
    uint8_t section_ctr[0x8];
    uint8_t pad[0xB8];
};

struct Pfs0Superblock {
    uint8_t master_hash[0x20];
    uint32_t block_size;
    uint32_t always_2;
    uint64_t hash_table_offset;
    uint64_t hash_table_size;
    uint64_t pfs0_offset;
    uint64_t pfs0_size;
};

struct Pfs0Header {
    uint32_t magic; // PFS0
    uint32_t num_files;
    uint32_t string_table_size;
    uint32_t reserved;
};

struct Pfs0FileEntry {
    uint64_t offset;
    uint64_t size;
    uint32_t string_table_offset;
    uint32_t reserved;
};

#pragma pack(pop)

std::string GetBuildIdFromNca(const std::string& nca_path) {
    std::ostringstream log;
    if (!g_keys.loaded) { log << "nca: g_keys not loaded\n"; return ""; }

    // Parse path to NcmStorageId and NcmContentId
    NcmStorageId storage_id = NcmStorageId_SdCard;
    if (nca_path.find("user:/") == 0) {
        storage_id = NcmStorageId_BuiltInUser;
    }

    size_t last_slash = nca_path.find_last_of('/');
    if (last_slash == std::string::npos) { log << "nca: invalid path\n"; return ""; }
    
    std::string filename = nca_path.substr(last_slash + 1);
    size_t dot = filename.find(".nca");
    if (dot != std::string::npos) filename = filename.substr(0, dot);

    if (filename.length() != 32) { log << "nca: invalid content id length\n"; return ""; }

    NcmContentId content_id;
    auto bytes = ParseHexKey(filename);
    if (bytes.size() != 16) { log << "nca: failed to parse content id\n"; return ""; }
    memcpy(content_id.c, bytes.data(), 16);

    if (R_FAILED(ncmInitialize())) { log << "nca: ncmInitialize failed\n"; return ""; }

    NcmContentStorage cs;
    if (R_FAILED(ncmOpenContentStorage(&cs, storage_id))) {
        log << "nca: ncmOpenContentStorage failed\n";
        ncmExit();
        return "";
    }

    auto ReadData = [&](uint64_t offset, void* buffer, size_t size) -> bool {
        return R_SUCCEEDED(ncmContentStorageReadContentIdFile(&cs, buffer, size, &content_id, offset));
    };

    uint8_t raw_header[0xC00];
    if (!ReadData(0, raw_header, 0xC00)) { 
        log << "nca: failed to read header via NCM\n"; 
        ncmContentStorageClose(&cs);
        ncmExit();
        return ""; 
    }

    // Decrypt Header
    uint8_t dec_header[0xC00];
    if (!aes_xts_decrypt(g_keys.header_key, 0, raw_header, dec_header, 0xC00)) { 
        log << "nca: failed to decrypt xts header\n"; 
        ncmContentStorageClose(&cs);
        ncmExit();
        return ""; 
    }

    NcaHeader* hdr = (NcaHeader*)dec_header;
    if (hdr->magic != 0x3341434E && hdr->magic != 0x3241434E) { 
        log << "nca: invalid magic " << std::hex << hdr->magic << "\n"; 
        ncmContentStorageClose(&cs);
        ncmExit();
        return ""; 
    }

    bool has_rights_id = false;
    for (int i = 0; i < 16; i++) {
        if (hdr->rights_id[i] != 0) has_rights_id = true;
    }

    // Find ExeFS section
    int exefs_idx = -1;
    uint64_t exefs_offset = 0;
    uint64_t pfs0_offset_in_section = 0;

    for (int i = 0; i < 4; i++) {
        uint32_t start_blk = hdr->section_entries[i][0];
        if (start_blk > 0) {
            uint8_t* fs_hdr_raw = dec_header + 0x400 + i * 0x200;
            FsHeader* fs_hdr = (FsHeader*)fs_hdr_raw;
            if (fs_hdr->fs_type == 2) { // 2 = PFS0
                exefs_idx = i;
                exefs_offset = (uint64_t)start_blk * 0x200;
                
                Pfs0Superblock* sb = (Pfs0Superblock*)fs_hdr->superblock;
                pfs0_offset_in_section = sb->pfs0_offset;
                break;
            }
        }
    }

    if (exefs_idx == -1) { 
        log << "nca: exefs not found\n"; 
        ncmContentStorageClose(&cs);
        ncmExit();
        return ""; 
    }

    // Decrypt Key Area and find correct Application Key via Brute-Force
    uint8_t dec_keys[4][0x10];
    uint8_t* titlekek = nullptr;
    uint8_t dec_pfs0_hdr[0x200];
    bool found_pfs0 = false;

    // CTR generation for ExeFS:
    uint8_t ctr_base[16] = {0};
    FsHeader* fs_hdr = (FsHeader*)(dec_header + 0x400 + exefs_idx * 0x200);
    for (int j = 0; j < 8; j++) {
        ctr_base[j] = fs_hdr->section_ctr[8 - j - 1];
    }
    uint64_t ofs_blocks = (exefs_offset + pfs0_offset_in_section) >> 4;
    for (int j = 0; j < 8; j++) {
        ctr_base[15 - j] = (uint8_t)(ofs_blocks & 0xFF);
        ofs_blocks >>= 8;
    }

    uint8_t enc_pfs0_hdr[0x200];
    if (!ReadData(exefs_offset + pfs0_offset_in_section, enc_pfs0_hdr, 0x200)) { 
        ncmContentStorageClose(&cs);
        ncmExit();
        return ""; 
    }

    // Check if it's already PLAINTEXT
    Pfs0Header* raw_phdr = (Pfs0Header*)enc_pfs0_hdr;
    if (raw_phdr->magic == 0x30534650) {
        memcpy(dec_pfs0_hdr, enc_pfs0_hdr, 0x200);
        found_pfs0 = true;
    }

    if (has_rights_id) {
        char rid_hex[33];
        for (int i = 0; i < 16; i++) {
            sprintf(&rid_hex[i * 2], "%02x", hdr->rights_id[i]);
        }
        rid_hex[32] = 0;
        std::string rid_str(rid_hex);

        log << "nca: has rights_id " << rid_str << "\n";

        if (g_keys.title_keys.find(rid_str) != g_keys.title_keys.end()) {
            uint8_t* enc_titlekey = g_keys.title_keys[rid_str].data();
            uint8_t dec_titlekey[16];

            uint8_t crypto_rev = hdr->key_generation;
            if (crypto_rev == 0) crypto_rev = hdr->key_generation_old;
            uint8_t tk_index = crypto_rev > 0 ? crypto_rev - 1 : 0;

            if (g_keys.titlekeks.find(tk_index) != g_keys.titlekeks.end()) {
                const std::vector<uint8_t>& tkek = g_keys.titlekeks[tk_index];
                if (aes_ecb_decrypt(tkek.data(), enc_titlekey, dec_titlekey, 16)) {
                    titlekek = dec_titlekey;
                }
            } else {
                titlekek = enc_titlekey; // Fallback to unencrypted
            }

            if (titlekek) {
                aes_ctr_decrypt(titlekek, ctr_base, enc_pfs0_hdr, dec_pfs0_hdr, 0x200);
                Pfs0Header* phdr = (Pfs0Header*)dec_pfs0_hdr;
                if (phdr->magic == 0x30534650) {
                    found_pfs0 = true;
                    log << "nca: titlekey decrypted pfs0 successfully!\n";
                } else {
                    log << "nca: titlekey failed to decrypt pfs0, magic=" << std::hex << phdr->magic << "\n";
                }
            }
        } else {
            log << "nca: MISSING TITLEKEY in title.keys for rights_id " << rid_str << "!\n";
        }
    } else {
        log << "nca: no rights_id, using standard crypto fallback. "
            << "key_gen: " << (int)hdr->key_generation 
            << " key_gen_old: " << (int)hdr->key_generation_old 
            << " kae_index: " << (int)hdr->key_area_encryption_key_index 
            << "\n";
        
        log << "nca debug: loaded apps=" << g_keys.key_area_key_application.size() 
            << " ocean=" << g_keys.key_area_key_ocean.size() 
            << " sys=" << g_keys.key_area_key_system.size() 
            << " master=" << g_keys.master_keys.size() 
            << " tkek=" << g_keys.titlekeks.size() << "\n";
    }

    if (!found_pfs0) {
        // Collect all potential ECB decryption keys
        std::vector<std::vector<uint8_t>> ecb_keys_to_test;
        for (const auto& pair : g_keys.key_area_key_application) ecb_keys_to_test.push_back(pair.second);
        for (const auto& pair : g_keys.key_area_key_ocean) ecb_keys_to_test.push_back(pair.second);
        for (const auto& pair : g_keys.key_area_key_system) ecb_keys_to_test.push_back(pair.second);
        for (const auto& pair : g_keys.master_keys) ecb_keys_to_test.push_back(pair.second);
        for (const auto& pair : g_keys.titlekeks) ecb_keys_to_test.push_back(pair.second);
        
        std::vector<uint8_t> hk1(g_keys.header_key, g_keys.header_key + 16);
        std::vector<uint8_t> hk2(g_keys.header_key + 16, g_keys.header_key + 32);
        ecb_keys_to_test.push_back(hk1);
        ecb_keys_to_test.push_back(hk2);

        // 1. Try decrypting Key Area with all potential ECB keys, and check ALL 4 slots!
        for (const auto& kak : ecb_keys_to_test) {
            if (kak.size() < 16) continue;
            if (aes_ecb_decrypt(kak.data(), (uint8_t*)hdr->encrypted_keys, (uint8_t*)dec_keys, 0x40)) {
                for (int slot = 0; slot < 4; slot++) {
                    uint8_t* candidate_titlekek = dec_keys[slot];
                    aes_ctr_decrypt(candidate_titlekek, ctr_base, enc_pfs0_hdr, dec_pfs0_hdr, 0x200);
                    Pfs0Header* phdr = (Pfs0Header*)dec_pfs0_hdr;
                    if (phdr->magic == 0x30534650) {
                        static uint8_t ultimate_tkek[16];
                        memcpy(ultimate_tkek, candidate_titlekek, 16);
                        titlekek = ultimate_tkek;
                        found_pfs0 = true;
                        log << "nca: standard crypto fallback success!\n";
                        break;
                    }
                }
            }
            if (found_pfs0) break;
        }

        // 2. Try using the encrypted_keys directly as plaintext Titlekek (check ALL 4 slots)
        if (!found_pfs0) {
            for (int slot = 0; slot < 4; slot++) {
                uint8_t* raw_titlekek = hdr->encrypted_keys[slot];
                aes_ctr_decrypt(raw_titlekek, ctr_base, enc_pfs0_hdr, dec_pfs0_hdr, 0x200);
                Pfs0Header* phdr = (Pfs0Header*)dec_pfs0_hdr;
                if (phdr->magic == 0x30534650) {
                    titlekek = raw_titlekek;
                    found_pfs0 = true;
                    break;
                }
            }
        }

        // 3. Try hardcoded common plaintext Titlekeks
        if (!found_pfs0) {
            std::vector<std::vector<uint8_t>> hardcoded_keys;
            hardcoded_keys.push_back(std::vector<uint8_t>(16, 0x00)); // All zeros
            hardcoded_keys.push_back(std::vector<uint8_t>(16, 0xFF)); // All FFs
            hardcoded_keys.push_back(hk1); // Header key 1
            hardcoded_keys.push_back(hk2); // Header key 2

            for (const auto& k : ecb_keys_to_test) {
                hardcoded_keys.push_back(k);
            }

            for (const auto& hc_key : hardcoded_keys) {
                aes_ctr_decrypt(hc_key.data(), ctr_base, enc_pfs0_hdr, dec_pfs0_hdr, 0x200);
                Pfs0Header* phdr = (Pfs0Header*)dec_pfs0_hdr;
                if (phdr->magic == 0x30534650) {
                    static uint8_t hc_tkek_static[16];
                    memcpy(hc_tkek_static, hc_key.data(), 16);
                    titlekek = hc_tkek_static;
                    found_pfs0 = true;
                    break;
                }
            }
        }
    }

    if (!found_pfs0) {
        log << "nca: failed to find valid pfs0 in ExeFS! (brute force failed)\n";
        ncmContentStorageClose(&cs);
        ncmExit();
        return "";
    }

    Pfs0Header* phdr = (Pfs0Header*)dec_pfs0_hdr;
    char* string_table = (char*)(dec_pfs0_hdr + sizeof(Pfs0Header) + phdr->num_files * sizeof(Pfs0FileEntry));

    bool found_main = false;
    uint64_t main_offset = 0;
    for (uint32_t i = 0; i < phdr->num_files; i++) {
        Pfs0FileEntry* entry = (Pfs0FileEntry*)(dec_pfs0_hdr + sizeof(Pfs0Header) + i * sizeof(Pfs0FileEntry));
        std::string filename(string_table + entry->string_table_offset);
        if (filename == "main") {
            found_main = true;
            main_offset = entry->offset;
            break;
        }
    }

    if (!found_main) { 
        log << "nca: 'main' file not found in ExeFS string table\n";
        ncmContentStorageClose(&cs);
        ncmExit();
        return ""; 
    }

    // Read first 0x100 bytes of main
    uint64_t main_abs_offset = exefs_offset + pfs0_offset_in_section + 0x10 + phdr->num_files * sizeof(Pfs0FileEntry) + phdr->string_table_size + main_offset;
    
    uint8_t enc_nso[0x100];
    if (!ReadData(main_abs_offset, enc_nso, 0x100)) { 
        log << "nca: failed to read first 0x100 of main\n";
        ncmContentStorageClose(&cs);
        ncmExit();
        return ""; 
    }

    uint8_t dec_nso[0x100];
    
    // Check if NSO is plaintext too (or crypt_type == 1)
    if (enc_nso[0] == 'N' && enc_nso[1] == 'S' && enc_nso[2] == 'O' && enc_nso[3] == '0') {
        memcpy(dec_nso, enc_nso, 0x100);
    } else if (raw_phdr->magic == 0x30534650 || fs_hdr->crypt_type == 1) { // PLAINTEXT
        memcpy(dec_nso, enc_nso, 0x100);
    } else {
        uint8_t nso_ctr[16] = {0};
        for (int j = 0; j < 8; j++) {
            nso_ctr[j] = fs_hdr->section_ctr[8 - j - 1];
        }
        uint64_t nso_ofs_blocks = main_abs_offset >> 4;
        for (int j = 0; j < 8; j++) {
            nso_ctr[15 - j] = (uint8_t)(nso_ofs_blocks & 0xFF);
            nso_ofs_blocks >>= 8;
        }

        aes_ctr_decrypt(titlekek, nso_ctr, enc_nso, dec_nso, 0x100);
    }

    if (dec_nso[0] != 'N' || dec_nso[1] != 'S' || dec_nso[2] != 'O' || dec_nso[3] != '0') { 
        log << "nca: invalid nso magic: " << std::hex << (int)dec_nso[0] << " " << (int)dec_nso[1] << " " << (int)dec_nso[2] << " " << (int)dec_nso[3] << "\n";
        ncmContentStorageClose(&cs);
        ncmExit();
        return ""; 
    }

    char hex[17];
    for (int i = 0; i < 8; i++) {
        sprintf(&hex[i * 2], "%02X", dec_nso[0x40 + i]);
    }
    hex[16] = 0;

    ncmContentStorageClose(&cs);
    ncmExit();

    return std::string(hex);
}

} // namespace crypto
