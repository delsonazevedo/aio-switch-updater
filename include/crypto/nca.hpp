#pragma once

#include <string>

namespace crypto {

// Extracts the 16-character Build ID from the main NSO inside an NCA.
// Requires keys to be loaded first via LoadKeys().
std::string GetBuildIdFromNca(const std::string& nca_path);

// Resolves the absolute path of the main NCA for a given Title ID.
std::string FindMainNcaPath(uint64_t title_id);

} // namespace crypto
