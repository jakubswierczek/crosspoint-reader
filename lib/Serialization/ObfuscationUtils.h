#pragma once

#include <Arduino.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "ObfuscationCodec.h"

/**
 * Credential obfuscation. New blobs are XOR'd with a random 16-byte NVS key and
 * stored as "v2." plus base64. Older blobs (MAC key, no prefix) still decode.
 * This is not cryptography: it keeps a copied SD card from being readable on
 * another machine. The NVS key does not travel with the card.
 *
 */
namespace obfuscation {

// XOR obfuscate/deobfuscate in-place using hardware MAC key (symmetric operation)
void xorTransform(std::string& data);

// Legacy overload for binary migration (uses the old per-store hardcoded keys)
void xorTransform(std::string& data, const uint8_t* key, size_t keyLen);

// Obfuscate a plaintext string for JSON storage. Uses the NVS key when it can
// be read or created; otherwise the MAC form, so a failed NVS write does not
// drop the secret.
String obfuscateToBase64(const std::string& plaintext);

// Decode base64 and de-obfuscate back to plaintext.
// Returns empty string on invalid base64 input; sets *ok to false if decode fails.
// *legacy is set when the blob was the MAC form and a v2 key is available.
std::string deobfuscateFromBase64(const char* encoded, bool* ok = nullptr, bool* legacy = nullptr);

// Bounded variant. Rejects decoded output larger than maxDecodedLength before
// allocating its result buffer and reports that case through tooLong.
std::string deobfuscateFromBase64(const char* encoded, size_t maxDecodedLength, bool* ok, bool* tooLong,
                                  bool* legacy = nullptr);

// Self-test: verifies round-trip obfuscation with hardware key. Logs PASS/FAIL.
void selfTest();

}  // namespace obfuscation
