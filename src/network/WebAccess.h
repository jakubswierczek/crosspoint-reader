#pragma once

#include <ctype.h>
#include <stdint.h>
#include <string.h>

// Pure HTTP access-code decision. No Arduino, NVS, or heap: the web server
// supplies the code and the host allowlist, and stores the lockout state.
// The code is 8 characters from the on-screen alphabet.

namespace webaccess {

inline constexpr char ALPHABET[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
inline constexpr int CODE_LEN = 8;
inline constexpr int MAX_FAILURES = 8;
inline constexpr uint32_t LOCKOUT_MS = 30000;

enum class Decision : uint8_t {
  Allow = 0,
  AllowSetCookie,
  RedirectStripQuery,
  Unauthorized,
  Forbidden,
  Locked,
};

struct State {
  uint8_t failures = 0;
  uint32_t lockoutUntilMs = 0;
};

// Present means the client sent that credential. Well-formed means it was
// exactly CODE_LEN characters; a present but malformed value is a failed guess.
struct Credentials {
  char queryKey[CODE_LEN + 1] = {};
  char cookie[CODE_LEN + 1] = {};
  char bearer[CODE_LEN + 1] = {};
  char basicPassword[CODE_LEN + 1] = {};
  bool hasQuery = false;
  bool hasCookie = false;
  bool hasBearer = false;
  bool hasBasic = false;
};

struct Request {
  const char* method = nullptr;
  const char* path = nullptr;  // no query string
  const char* host = nullptr;
  const char* origin = nullptr;
  const Credentials* credentials = nullptr;
  bool apMode = false;
  uint32_t nowMs = 0;
  const char* const* allowedHosts = nullptr;
  size_t allowedHostCount = 0;
};

inline char lowerAscii(char c) {
  if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
  return c;
}

inline bool equalsIgnoreCase(const char* a, const char* b) {
  if (!a || !b) return false;
  while (*a && *b && lowerAscii(*a) == lowerAscii(*b)) {
    ++a;
    ++b;
  }
  return *a == 0 && *b == 0;
}

inline bool codeEquals(const char* given, const char* code) {
  if (!given || !code) return false;
  unsigned diff = 0;
  for (int i = 0; i < CODE_LEN; ++i) {
    if (code[i] == 0) return false;
    const unsigned char g = static_cast<unsigned char>(given[i]);
    diff |= static_cast<unsigned>(g ^ static_cast<unsigned char>(code[i]));
    if (g == 0) {
      for (int j = i + 1; j < CODE_LEN; ++j) diff |= static_cast<unsigned char>(code[j]);
      return false;
    }
  }
  if (given[CODE_LEN] != 0 || code[CODE_LEN] != 0) return false;
  return diff == 0;
}

inline bool isPublicRead(const char* method, const char* path) {
  if (!method || !path) return false;
  if (equalsIgnoreCase(method, "OPTIONS")) return true;
  if (!equalsIgnoreCase(method, "GET") && !equalsIgnoreCase(method, "HEAD")) return false;
  if (strcmp(path, "/") == 0 || strcmp(path, "/files") == 0 || strcmp(path, "/settings") == 0 ||
      strcmp(path, "/fonts") == 0 || strcmp(path, "/plugins-run") == 0 || strcmp(path, "/api/status") == 0) {
    return true;
  }
  // Exact asset URLs only. A prefix would let WebDAV serve /js/../Books/Title.epub
  // with no code after it collapses the parent segment.
  return strcmp(path, "/assets/web.css") == 0 || strcmp(path, "/assets/icons.svg") == 0 ||
         strcmp(path, "/assets/crosspoint-icon.svg") == 0 || strcmp(path, "/js/jszip.min.js") == 0;
}

inline bool copyWithoutPort80(const char* in, char* out, size_t cap) {
  if (!in || !out || cap < 2) return false;
  const size_t n = strlen(in);
  if (n >= cap) return false;
  memcpy(out, in, n + 1);
  if (n >= 3 && out[n - 3] == ':' && out[n - 2] == '8' && out[n - 1] == '0') out[n - 3] = 0;
  return out[0] != 0;
}

inline bool hostAllowed(const char* host, const char* const* allowed, size_t count) {
  char presented[96];
  if (!copyWithoutPort80(host, presented, sizeof(presented))) return false;
  for (size_t i = 0; i < count; ++i) {
    char item[96];
    if (!allowed[i] || !copyWithoutPort80(allowed[i], item, sizeof(item))) continue;
    if (equalsIgnoreCase(presented, item)) return true;
  }
  return false;
}

inline bool originMatchesHost(const char* origin, const char* host) {
  if (!origin || !host) return false;
  if (strncasecmp(origin, "http://", 7) != 0) return false;
  char originHost[96];
  char requestHost[96];
  if (!copyWithoutPort80(origin + 7, originHost, sizeof(originHost))) return false;
  if (!copyWithoutPort80(host, requestHost, sizeof(requestHost))) return false;
  // An origin with a path or userinfo is not the device itself.
  if (strchr(originHost, '/') || strchr(originHost, '@') || strchr(originHost, '?')) return false;
  return equalsIgnoreCase(originHost, requestHost);
}

inline bool safeMethod(const char* method) {
  return equalsIgnoreCase(method, "GET") || equalsIgnoreCase(method, "HEAD") || equalsIgnoreCase(method, "OPTIONS");
}

inline int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Decode one query or cookie value. Sets *present when the key exists.
// A value that is not exactly CODE_LEN characters leaves the buffer empty.
inline bool takeExactCode(const char* value, size_t len, char out[CODE_LEN + 1]) {
  if (len != static_cast<size_t>(CODE_LEN)) {
    out[0] = 0;
    return false;
  }
  memcpy(out, value, CODE_LEN);
  out[CODE_LEN] = 0;
  return true;
}

inline void copyQueryCode(const char* query, char out[CODE_LEN + 1], bool* present) {
  out[0] = 0;
  *present = false;
  if (!query) return;
  const char* p = query;
  while (*p) {
    if (*p == '?' || *p == '&') ++p;
    const char* name = p;
    while (*p && *p != '=' && *p != '&') {
      // "/?k=..." is a request target, not a bare query string.
      if (*p == '?') name = p + 1;
      ++p;
    }
    const bool namedK = (p - name == 1 && (name[0] == 'k' || name[0] == 'K'));
    if (*p != '=') {
      if (*p == '&') ++p;
      continue;
    }
    ++p;
    char decoded[16];
    size_t n = 0;
    bool overflow = false;
    while (*p && *p != '&') {
      char c = *p++;
      if (c == '%' && hexValue(p[0]) >= 0 && hexValue(p[1]) >= 0) {
        c = static_cast<char>((hexValue(p[0]) << 4) | hexValue(p[1]));
        p += 2;
      }
      if (n + 1 < sizeof(decoded)) {
        decoded[n++] = c;
      } else {
        overflow = true;
      }
    }
    if (namedK) {
      *present = true;
      if (!overflow) takeExactCode(decoded, n, out);
      return;
    }
  }
}

inline void copyCookieCode(const char* cookieHeader, char out[CODE_LEN + 1], bool* present) {
  out[0] = 0;
  *present = false;
  if (!cookieHeader) return;
  const char* p = cookieHeader;
  while (*p) {
    while (*p == ' ' || *p == ';') ++p;
    const char* name = p;
    while (*p && *p != '=' && *p != ';') ++p;
    const bool named = (p - name == 2 && strncasecmp(name, "cp", 2) == 0);
    if (*p != '=') {
      if (*p == ';') ++p;
      continue;
    }
    ++p;
    const char* value = p;
    while (*p && *p != ';') ++p;
    if (named) {
      *present = true;
      takeExactCode(value, static_cast<size_t>(p - value), out);
      return;
    }
  }
}

inline void copyBearer(const char* authorization, char out[CODE_LEN + 1], bool* present) {
  out[0] = 0;
  *present = false;
  if (!authorization) return;
  if (strncasecmp(authorization, "Bearer ", 7) != 0) return;
  *present = true;
  const char* value = authorization + 7;
  takeExactCode(value, strlen(value), out);
}

inline int base64Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// Decode a Basic password (the part after the first colon). Username is ignored.
inline void copyBasicPassword(const char* authorization, char out[CODE_LEN + 1], bool* present) {
  out[0] = 0;
  *present = false;
  if (!authorization || strncasecmp(authorization, "Basic ", 6) != 0) return;
  *present = true;
  const char* b64 = authorization + 6;
  char decoded[48];
  size_t n = 0;
  int val = 0;
  int valb = -8;
  for (const char* p = b64; *p && *p != ' ' && n + 1 < sizeof(decoded); ++p) {
    if (*p == '=') break;
    const int d = base64Value(*p);
    if (d < 0) {
      out[0] = 0;
      return;
    }
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      decoded[n++] = static_cast<char>((val >> valb) & 0xFF);
      valb -= 8;
    }
  }
  decoded[n] = 0;
  const char* colon = static_cast<const char*>(memchr(decoded, ':', n));
  if (!colon) return;
  takeExactCode(colon + 1, n - static_cast<size_t>(colon + 1 - decoded), out);
}

inline bool lockoutActive(uint32_t now, uint32_t until) { return until != 0 && static_cast<int32_t>(until - now) > 0; }

inline bool credentialMatches(const Credentials& creds, const char* code, bool* anyPresent) {
  *anyPresent = creds.hasBearer || creds.hasBasic || creds.hasQuery || creds.hasCookie;
  if (!*anyPresent || !code) return false;
  // One presented secret has to match. A wrong bearer does not fall through to a cookie.
  if (creds.hasBearer) return creds.bearer[0] && codeEquals(creds.bearer, code);
  if (creds.hasBasic) return creds.basicPassword[0] && codeEquals(creds.basicPassword, code);
  if (creds.hasQuery) return creds.queryKey[0] && codeEquals(creds.queryKey, code);
  return creds.cookie[0] && codeEquals(creds.cookie, code);
}

inline void noteFailure(State& state, uint32_t now) {
  if (state.failures < 255) state.failures++;
  if (state.failures >= MAX_FAILURES) {
    uint32_t deadline = now + LOCKOUT_MS;
    if (deadline == 0) deadline = 1;
    state.lockoutUntilMs = deadline;
    state.failures = MAX_FAILURES;
  }
}

inline Decision decide(const Request& req, const char* code, State& state) {
  if (state.lockoutUntilMs != 0 && !lockoutActive(req.nowMs, state.lockoutUntilMs)) {
    state.failures = 0;
    state.lockoutUntilMs = 0;
  }

  const bool pub = isPublicRead(req.method, req.path);
  const bool hostOk = hostAllowed(req.host, req.allowedHosts, req.allowedHostCount);
  const bool queryPresented = req.credentials && req.credentials->hasQuery;
  // A presented ?k= counts even on the shell. Otherwise eight wrong guesses stay
  // 200, and a correct code still sets the cookie during lockout.
  if (queryPresented && lockoutActive(req.nowMs, state.lockoutUntilMs)) return Decision::Locked;
  if (pub && (req.apMode || hostOk)) {
    const bool queryOk =
        queryPresented && req.credentials->queryKey[0] && code && codeEquals(req.credentials->queryKey, code);
    if (queryOk && (equalsIgnoreCase(req.method, "GET") || equalsIgnoreCase(req.method, "HEAD"))) {
      state.failures = 0;
      state.lockoutUntilMs = 0;
      return Decision::RedirectStripQuery;
    }
    if (queryPresented) {
      noteFailure(state, req.nowMs);
      if (lockoutActive(req.nowMs, state.lockoutUntilMs)) return Decision::Locked;
    }
    return Decision::Allow;
  }
  if (pub) return Decision::Forbidden;

  if (lockoutActive(req.nowMs, state.lockoutUntilMs)) return Decision::Locked;
  if (!hostOk) return Decision::Forbidden;

  bool anyPresent = false;
  const bool ok = req.credentials && credentialMatches(*req.credentials, code, &anyPresent);
  if (!ok) {
    if (anyPresent) noteFailure(state, req.nowMs);
    return lockoutActive(req.nowMs, state.lockoutUntilMs) ? Decision::Locked : Decision::Unauthorized;
  }

  state.failures = 0;
  state.lockoutUntilMs = 0;
  const bool viaQuery = req.credentials->hasQuery && !req.credentials->hasBearer && !req.credentials->hasBasic;
  if (viaQuery && (equalsIgnoreCase(req.method, "GET") || equalsIgnoreCase(req.method, "HEAD"))) {
    return Decision::RedirectStripQuery;
  }
  if (viaQuery) return Decision::AllowSetCookie;

  const bool viaCookie = req.credentials->hasCookie && !req.credentials->hasBearer && !req.credentials->hasBasic &&
                         !req.credentials->hasQuery;
  if (viaCookie && !safeMethod(req.method) && !originMatchesHost(req.origin, req.host)) {
    return Decision::Forbidden;
  }
  return Decision::Allow;
}

}  // namespace webaccess
