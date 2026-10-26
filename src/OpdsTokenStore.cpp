#include "OpdsTokenStore.h"

#include <Logging.h>
#include <ObfuscationUtils.h>

#include <algorithm>

namespace {
// Access/refresh tokens (JWTs) run long; cap the decode to avoid a malformed
// file ballooning the heap.
constexpr size_t MAX_TOKEN_CHARS = 2048;
}  // namespace

bool OpdsTokenStore::toJson(JsonDocument& doc) const {
  JsonArray arr = doc["tokens"].to<JsonArray>();
  for (const auto& entry : entries) {
    JsonObject obj = arr.add<JsonObject>();
    obj["url"] = entry.url;
    String accessObf;
    String refreshObf;
    if (!obfuscation::obfuscateToBase64(entry.tokens.accessToken, accessObf)) return false;
    if (!obfuscation::obfuscateToBase64(entry.tokens.refreshToken, refreshObf)) return false;
    obj["access_obf"] = accessObf;
    obj["refresh_obf"] = refreshObf;
    obj["refresh_url"] = entry.tokens.refreshUrl;
  }
  return true;
}

bool OpdsTokenStore::fromJson(JsonVariantConst doc) {
  entries.clear();
  JsonArrayConst arr = doc["tokens"].as<JsonArrayConst>();
  entries.reserve(std::min(arr.size(), MAX_SERVERS));
  bool needsResave = false;
  bool preserveFile = false;
  for (JsonObjectConst obj : arr) {
    if (entries.size() >= MAX_SERVERS) break;
    Entry entry;
    entry.url = obj["url"] | "";
    if (entry.url.empty()) continue;
    bool ok = false;
    bool tooLong = false;
    bool legacy = false;
    const char* storedAccess = obj["access_obf"] | "";
    entry.tokens.accessToken =
        obfuscation::deobfuscateFromBase64(storedAccess, MAX_TOKEN_CHARS, &ok, &tooLong, &legacy);
    if (legacy) needsResave = true;
    if (storedAccess[0] != '\0' && (!ok || tooLong)) preserveFile = true;
    legacy = false;
    ok = false;
    tooLong = false;
    const char* storedRefresh = obj["refresh_obf"] | "";
    entry.tokens.refreshToken =
        obfuscation::deobfuscateFromBase64(storedRefresh, MAX_TOKEN_CHARS, &ok, &tooLong, &legacy);
    if (legacy) needsResave = true;
    if (storedRefresh[0] != '\0' && (!ok || tooLong)) preserveFile = true;
    entry.tokens.refreshUrl = obj["refresh_url"] | "";
    entries.push_back(std::move(entry));
  }
  if (needsResave && !preserveFile) requestResave();
  LOG_DBG("OPDSTOK", "Loaded %zu OPDS token entries", entries.size());
  return true;
}

OpdsTokens OpdsTokenStore::get(const std::string& url) const {
  for (const auto& entry : entries) {
    if (entry.url == url) return entry.tokens;
  }
  return {};
}

bool OpdsTokenStore::put(const std::string& url, const OpdsTokens& tokens) {
  const auto it = std::find_if(entries.begin(), entries.end(), [&](const Entry& e) { return e.url == url; });

  if (tokens.empty()) {
    // Clearing: drop the entry if present; nothing to write otherwise.
    if (it == entries.end()) return true;
    entries.erase(it);
    return saveToFile();
  }

  if (it != entries.end()) {
    if (it->tokens.accessToken == tokens.accessToken && it->tokens.refreshToken == tokens.refreshToken &&
        it->tokens.refreshUrl == tokens.refreshUrl) {
      return true;  // unchanged: skip the SD write
    }
    it->tokens = tokens;
    return saveToFile();
  }

  if (entries.size() >= MAX_SERVERS) {
    // Full: evict the oldest entry so a new server can still be remembered.
    entries.erase(entries.begin());
  }
  entries.push_back(Entry{url, tokens});
  return saveToFile();
}
