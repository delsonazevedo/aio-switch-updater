#include "crypto/nca.hpp"
#include <switch.h>
#include <string.h>
#include <iostream>
#include <fstream>

namespace crypto {

std::string FindMainNcaPath(uint64_t title_id) {
    {
        std::ofstream log("sdmc:/config/aio-switch-updater/crypto_debug.txt", std::ios::app);
        if (R_FAILED(lrInitialize())) { log << "ncm: lrInitialize failed\n"; return ""; }
    }

    LrRegisteredLocationResolver reg;
    if (R_FAILED(lrOpenRegisteredLocationResolver(&reg))) {
        std::ofstream log("sdmc:/config/aio-switch-updater/crypto_debug.txt", std::ios::app);
        log << "ncm: lrOpenRegistered failed\n";
        lrExit();
        return "";
    }

    char path[FS_MAX_PATH] = {0};
    Result rc = lrRegLrResolveProgramPath(&reg, title_id, path);
    serviceClose(&reg.s);
    lrExit();

    if (R_FAILED(rc)) {
        std::ofstream log("sdmc:/config/aio-switch-updater/crypto_debug.txt", std::ios::app);
        log << "ncm: lrRegLrResolveProgramPath failed " << std::hex << rc << ", trying LrLocationResolver...\n";
        
        if (R_SUCCEEDED(lrInitialize())) {
            LrLocationResolver loc;
            if (R_SUCCEEDED(lrOpenLocationResolver(NcmStorageId_SdCard, &loc))) {
                rc = lrLrResolveProgramPath(&loc, title_id, path);
                serviceClose(&loc.s);
            }
            if (R_FAILED(rc) && R_SUCCEEDED(lrOpenLocationResolver(NcmStorageId_BuiltInUser, &loc))) {
                rc = lrLrResolveProgramPath(&loc, title_id, path);
                serviceClose(&loc.s);
            }
            lrExit();
        }

        if (R_FAILED(rc)) {
            log << "ncm: all lr paths failed\n";
            return "";
        }
    }

    std::string str_path = path;
    {
        std::ofstream log("sdmc:/config/aio-switch-updater/crypto_debug.txt", std::ios::app);
        log << "ncm: raw path = '" << str_path << "'\n";
    }
    
    // Replace mounts
    if (str_path.find("@SdCardContent://") == 0) {
        str_path.replace(0, 17, "sdmc:/Nintendo/Contents/");
    } else if (str_path.find("@Sdcard:/") == 0) {
        str_path.replace(0, 9, "sdmc:/");
    } else if (str_path.find("@UserContent://") == 0) {
        str_path.replace(0, 15, "user:/Contents/");
    } else if (str_path.find("@User:/") == 0) {
        str_path.replace(0, 7, "user:/");
    }

    return str_path;
}

} // namespace crypto
