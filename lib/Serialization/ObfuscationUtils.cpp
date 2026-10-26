#include "ObfuscationUtils.h"

#include <Logging.h>
#include <base64.h>
#include <esp_mac.h>
#include <esp_random.h>
#include <mbedtls/base64.h>
#include <nvs.h>

#include <array>
#include <cstring>
#include <limits>
#include <mutex>

namespace obfuscation {

namespace {
constexpr size_t HW_KEY_LEN = 6;

// Random key in NVS. A failed read is not cached, so the next save can retry.
// The key stays in this static for the boot; it is not written to the SD card.
bool copyV2Key(uint8_t (&out)[V2_KEY_LEN]) {
  static uint8_t key[V2_KEY_LEN];
  static bool loaded = false;
  static std::mutex lock;
  std::lock_guard<std::mutex> guard(lock);
  if (!loaded) {
    nvs_handle_t handle;
    if (nvs_open("obfkey", NVS_READWRITE, &handle) == ESP_OK) {
      size_t stored = sizeof(key);
      const esp_err_t err = nvs_get_blob(handle, "k", key, &stored);
      if (err == ESP_OK) {
        loaded = stored == sizeof(key);
      } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        esp_fill_random(key, sizeof(key));
        loaded = nvs_set_blob(handle, "k", key, sizeof(key)) == ESP_OK && nvs_commit(handle) == ESP_OK;
      }
      nvs_close(handle);
    }
    if (!loaded) {
      LOG_ERR("OBF", "Obfuscation key unavailable");
      return false;
    }
  }
  memcpy(out, key, sizeof(key));
  return true;
}

const uint8_t* getHwKey() {
  // Function-local static initialization is synchronized by C++, including
  // on dual-core targets. The previous hand-rolled boolean could expose a
  // partially initialized key to another task.
  static const std::array<uint8_t, HW_KEY_LEN> key = [] {
    std::array<uint8_t, HW_KEY_LEN> value{};
    esp_efuse_mac_get_default(value.data());
    return value;
  }();
  return key.data();
}
}  // namespace

void xorTransform(std::string& data) {
  const uint8_t* key = getHwKey();
  for (size_t i = 0; i < data.size(); i++) {
    data[i] ^= key[i % HW_KEY_LEN];
  }
}

void xorTransform(std::string& data, const uint8_t* key, size_t keyLen) {
  if (keyLen == 0 || key == nullptr) return;
  for (size_t i = 0; i < data.size(); i++) {
    data[i] ^= key[i % keyLen];
  }
}

bool obfuscateToBase64(const std::string& plaintext, String& out) {
  if (plaintext.empty()) {
    out = "";
    return true;
  }
  uint8_t v2Key[V2_KEY_LEN];
  if (!copyV2Key(v2Key)) return false;
  std::string temp = plaintext;
  xorTransform(temp, v2Key, V2_KEY_LEN);
  out = V2_PREFIX;
  out += base64::encode(reinterpret_cast<const uint8_t*>(temp.data()), temp.size());
  return true;
}

std::string deobfuscateFromBase64(const char* encoded, bool* ok, bool* legacy) {
  return deobfuscateFromBase64(encoded, std::numeric_limits<size_t>::max(), ok, nullptr, legacy);
}

std::string deobfuscateFromBase64(const char* encoded, const size_t maxDecodedLength, bool* ok, bool* tooLong,
                                  bool* legacy) {
  if (tooLong) *tooLong = false;
  if (legacy) *legacy = false;
  if (encoded == nullptr || encoded[0] == '\0') {
    if (ok) *ok = false;
    return "";
  }
  uint8_t v2Key[V2_KEY_LEN];
  const bool haveV2 = copyV2Key(v2Key);
  const char* payload = encoded;
  bool useV2 = false;
  if (isV2Blob(encoded)) {
    if (!haveV2) {
      if (ok) *ok = false;
      return "";
    }
    payload = encoded + V2_PREFIX_LEN;
    useV2 = true;
  }
  if (ok) *ok = true;
  size_t encodedLen = strlen(payload);
  // First call: get required output buffer size
  size_t decodedLen = 0;
  int ret = mbedtls_base64_decode(nullptr, 0, &decodedLen, reinterpret_cast<const unsigned char*>(payload), encodedLen);
  if (ret != 0 && ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
    LOG_ERR("OBF", "Base64 decode size query failed (ret=%d)", ret);
    if (ok) *ok = false;
    return "";
  }
  if (decodedLen > maxDecodedLength) {
    if (ok) *ok = false;
    if (tooLong) *tooLong = true;
    return "";
  }
  std::string result(decodedLen, '\0');
  ret = mbedtls_base64_decode(reinterpret_cast<unsigned char*>(&result[0]), decodedLen, &decodedLen,
                              reinterpret_cast<const unsigned char*>(payload), encodedLen);
  if (ret != 0) {
    LOG_ERR("OBF", "Base64 decode failed (ret=%d)", ret);
    if (ok) *ok = false;
    return "";
  }
  result.resize(decodedLen);
  if (useV2) {
    xorTransform(result, v2Key, V2_KEY_LEN);
  } else {
    xorTransform(result);
  }
  if (legacy) *legacy = shouldUpgradeStoredForm(encoded, haveV2);
  return result;
}

void selfTest() {
  const char* testInputs[] = {"", "hello", "WiFi P@ssw0rd!", "a"};
  bool allPassed = true;
  for (const char* input : testInputs) {
    String encoded;
    if (!obfuscateToBase64(std::string(input), encoded)) {
      LOG_ERR("OBF", "FAIL: key unavailable for \"%s\"", input);
      allPassed = false;
      continue;
    }
    std::string decoded = deobfuscateFromBase64(encoded.c_str());
    if (decoded != input) {
      LOG_ERR("OBF", "FAIL: \"%s\" -> \"%s\" -> \"%s\"", input, encoded.c_str(), decoded.c_str());
      allPassed = false;
    }
  }
  // Verify obfuscated form differs from plaintext
  String enc;
  if (!obfuscateToBase64("test123", enc)) {
    LOG_ERR("OBF", "FAIL: key unavailable");
    allPassed = false;
  }
  if (enc == "test123") {
    LOG_ERR("OBF", "FAIL: obfuscated output identical to plaintext");
    allPassed = false;
  }
  if (allPassed) {
    LOG_DBG("OBF", "Obfuscation self-test PASSED");
  }
}

}  // namespace obfuscation
