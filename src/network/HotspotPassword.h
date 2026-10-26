#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

// Per-session WPA2 passphrase for the file-transfer hotspot. The alphabet is
// 32 characters with no QR separators, so a phone can join from the on-screen
// code without escaping. The activity owns the 11-byte buffer; nothing here
// allocates.
namespace hotspot {

inline constexpr char PASSWORD_ALPHABET[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
inline constexpr size_t PASSWORD_ALPHABET_LEN = sizeof(PASSWORD_ALPHABET) - 1;
inline constexpr size_t PASSWORD_LEN = 10;

template <typename NextRandom>
inline void generatePassword(char (&out)[PASSWORD_LEN + 1], NextRandom&& next) {
  static_assert(PASSWORD_ALPHABET_LEN == 32, "esp_random() % 32 is unbiased only for a 32-character alphabet");
  for (size_t i = 0; i < PASSWORD_LEN; ++i) {
    out[i] = PASSWORD_ALPHABET[static_cast<uint32_t>(next()) % PASSWORD_ALPHABET_LEN];
  }
  out[PASSWORD_LEN] = '\0';
}

inline bool passwordCharsOk(const char* password) {
  if (!password) return false;
  size_t length = 0;
  for (; password[length] != '\0'; ++length) {
    if (length >= PASSWORD_LEN || strchr(PASSWORD_ALPHABET, password[length]) == nullptr) return false;
  }
  return length == PASSWORD_LEN;
}

// WIFI:T:WPA;S:<ssid>;P:<password>;;  — false when the inputs contain a QR
// separator or the buffer cannot hold the payload.
inline bool formatWifiQr(char* out, size_t outLen, const char* ssid, const char* password) {
  if (!out || outLen == 0 || !ssid || ssid[0] == '\0' || !passwordCharsOk(password)) return false;
  if (strpbrk(ssid, ";:\\,\"") != nullptr) return false;
  const int written = snprintf(out, outLen, "WIFI:T:WPA;S:%s;P:%s;;", ssid, password);
  return written > 0 && static_cast<size_t>(written) < outLen;
}

}  // namespace hotspot
