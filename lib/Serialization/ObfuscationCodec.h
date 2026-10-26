#pragma once

#include <cstring>

// On-disk form of an obfuscated secret. "v2." is not valid base64 (it contains
// '.'), so firmware that only base64-decodes the field treats a v2 blob as empty.
namespace obfuscation {

inline constexpr char V2_PREFIX[] = "v2.";
inline constexpr size_t V2_PREFIX_LEN = 3;
inline constexpr size_t V2_KEY_LEN = 16;

inline bool isV2Blob(const char* encoded) {
  return encoded != nullptr && std::strncmp(encoded, V2_PREFIX, V2_PREFIX_LEN) == 0;
}

// True when the blob is the older MAC form and a v2 key exists, so the caller
// should write it back. Empty and already-v2 blobs are left alone. A missing
// key must not request a resave: the writer would have no v2 key to use.
inline bool shouldUpgradeStoredForm(const char* encoded, bool v2KeyAvailable) {
  return v2KeyAvailable && encoded != nullptr && encoded[0] != '\0' && !isV2Blob(encoded);
}

}  // namespace obfuscation
