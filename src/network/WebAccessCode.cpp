#include "WebAccessCode.h"

#include <Logging.h>
#include <esp_random.h>
#include <nvs.h>

#include <cstring>
#include <mutex>

#include "WebAccess.h"

namespace {

char code[webaccess::CODE_LEN + 1] = {};
bool loaded = false;
std::mutex lock;  // render task and the web task can both ask first

bool wellFormed(const char* value) {
  if (!value || std::strlen(value) != static_cast<size_t>(webaccess::CODE_LEN)) return false;
  for (int i = 0; i < webaccess::CODE_LEN; ++i) {
    if (std::strchr(webaccess::ALPHABET, value[i]) == nullptr) return false;
  }
  return true;
}

void generate(char* out) {
  // 2^32 and 256 are divisible by 32, so one byte modulo the alphabet is uniform.
  for (int i = 0; i < webaccess::CODE_LEN; ++i) {
    const uint32_t r = esp_random();
    out[i] = webaccess::ALPHABET[static_cast<uint8_t>(r) % 32];
  }
  out[webaccess::CODE_LEN] = 0;
}

}  // namespace

const char* webAccessCode() {
  std::lock_guard<std::mutex> guard(lock);
  if (loaded && wellFormed(code)) return code;

  nvs_handle_t handle;
  if (nvs_open("webauth", NVS_READWRITE, &handle) == ESP_OK) {
    size_t stored = sizeof(code);
    const esp_err_t err = nvs_get_str(handle, "code", code, &stored);
    if (err == ESP_OK && wellFormed(code)) {
      loaded = true;
    } else if (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND || err == ESP_ERR_NVS_INVALID_LENGTH) {
      generate(code);
      loaded = nvs_set_str(handle, "code", code) == ESP_OK && nvs_commit(handle) == ESP_OK && wellFormed(code);
    }
    nvs_close(handle);
  }

  if (!loaded) {
    if (!wellFormed(code)) generate(code);
    loaded = true;
    LOG_ERR("WEB", "Access code will last for this boot only");
  }
  return code;
}
