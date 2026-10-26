#pragma once

#include <string.h>
#include <strings.h>

#include <string>

// Credential stores no web request (file manager, plugin endpoints) or plugin
// manifest may read or write. Plugin token files are refused on read and on
// WebDAV, but isPluginPath still allows /api/plugin-fs to write them.
// Prefix match, so temp and backup siblings of a store are covered too.
namespace protectedpaths {

inline constexpr const char* SENSITIVE_FILES[] = {"/.crosspoint/wifi.json",
                                                  "/.crosspoint/opds.json",
                                                  "/.crosspoint/koreader.json",
                                                  "/.crosspoint/opds_tokens.json",
                                                  "/.crosspoint/lcp_passphrases.json",
                                                  "/.crosspoint/lcp_device.json"};

inline constexpr const char* CREDENTIAL_BASENAMES[] = {
    "wifi.json", "opds.json", "koreader.json", "opds_tokens.json", "lcp_passphrases.json", "lcp_device.json"};

// Read over the network. Not part of isSensitivePath, so plugin-fs can still
// write token.json. Book content keys are "<path>.key".
inline constexpr const char* NETWORK_SECRET_NAMES[] = {"token.json", "secret.json", "credentials.json"};

// 8.3 lossy names keep at most six characters of the stem. These stems are how
// SdFat spells the secret files when the long name is not what the client sent.
inline constexpr const char* SECRET_STEMS[] = {"token",    "secret",      "credentials",     "wifi",      "opds",
                                               "koreader", "opds_tokens", "lcp_passphrases", "lcp_device"};

inline constexpr const char* HIDDEN_VOLUME_NAMES[] = {"System Volume Information", "XTCache"};

// SdFat also opens a name by its generated 8.3 alias (".crosspoint" is
// CROSSP~1), which no spelling check can map back to the long name.
inline bool isShortAlias(const char* first, const char* last) {
  const char* tilde = static_cast<const char*>(memchr(first, '~', static_cast<size_t>(last - first)));
  if (!tilde || tilde + 1 >= last || tilde[1] < '0' || tilde[1] > '9') return false;
  const char* dot = static_cast<const char*>(memchr(first, '.', static_cast<size_t>(last - first)));
  const size_t base = static_cast<size_t>((dot ? dot : last) - first);
  const size_t ext = dot ? static_cast<size_t>(last - dot - 1) : 0;
  return base <= 8 && ext <= 3;
}

inline bool segmentEquals(const char* first, const char* last, const char* literal) {
  const size_t n = strlen(literal);
  return static_cast<size_t>(last - first) == n && strncasecmp(first, literal, n) == 0;
}

inline bool segmentEndsWith(const char* first, const char* last, const char* literal) {
  const size_t n = strlen(literal);
  return static_cast<size_t>(last - first) >= n && strncasecmp(last - n, literal, n) == 0;
}

struct CanonPath {
  std::string path;
  bool shallowAlias = false;
};

// Collapse slashes, "." and "..", and trim the spaces and trailing dots SdFat
// ignores, so later compares see the name that would actually be opened.
inline CanonPath canonicalize(const char* path) {
  CanonPath out;
  if (!path) return out;
  out.path.reserve(strlen(path) + 1);
  int depth = 0;
  for (const char* seg = path; *seg;) {
    while (*seg == '/') seg++;
    const char* end = strchr(seg, '/');
    const size_t len = end ? static_cast<size_t>(end - seg) : strlen(seg);
    // Spaces first. SdFat drops them and then treats " .. " as a parent, so the
    // parent test has to see the trimmed segment. Do not strip dots off ".."
    // or that name disappears before the pop.
    const char* first = seg;
    const char* last = seg + len;
    while (first < last && *first == ' ') first++;
    while (last > first && last[-1] == ' ') last--;
    const bool parent = last - first == 2 && first[0] == '.' && first[1] == '.';
    const bool dot = last - first == 1 && first[0] == '.';
    if (parent) {
      const size_t slash = out.path.rfind('/');
      out.path.erase(slash == std::string::npos ? 0 : slash);
      if (depth > 0) depth--;
    } else if (!dot) {
      // A trailing dot can hide a space ("dir ."), which SdFat also drops.
      while (last > first && (last[-1] == '.' || last[-1] == ' ')) last--;
      // The stores sit two levels deep; an alias further down cannot reach one.
      if (depth < 2 && first < last && isShortAlias(first, last)) out.shallowAlias = true;
      if (first < last) {
        out.path += '/';
        out.path.append(first, static_cast<size_t>(last - first));
        depth++;
      }
    }
    seg += len;
  }
  return out;
}

inline bool sensitiveCanon(const CanonPath& canon) {
  if (canon.shallowAlias) return true;
  for (const char* file : SENSITIVE_FILES) {
    // FAT names are case-insensitive. Prefix match covers temp siblings.
    if (strncasecmp(canon.path.c_str(), file, strlen(file)) == 0) return true;
  }
  return false;
}

inline bool isSensitivePath(const char* path) { return sensitiveCanon(canonicalize(path)); }

inline const char* lastSegment(const CanonPath& canon) {
  const size_t slash = canon.path.rfind('/');
  if (slash == std::string::npos) return canon.path.c_str();
  return canon.path.c_str() + slash + 1;
}

inline void trimBounds(const char*& first, const char*& last) {
  while (first < last && *first == ' ') first++;
  while (last > first && (last[-1] == '.' || last[-1] == ' ')) last--;
}

// A generated 8.3 name whose stem and extension could be one of the secret files.
inline bool isSecretShortAlias(const char* first, const char* last) {
  if (first >= last || !isShortAlias(first, last)) return false;
  const char* dot = nullptr;
  for (const char* p = first; p < last; ++p) {
    if (*p == '.') dot = p;
  }
  const char* ext = dot ? dot + 1 : last;
  // .key, and the .tmp / .bak a key is staged or copied as. The stem is the
  // book title, so it will not match the credential-store list below.
  if (segmentEquals(ext, last, "key") || segmentEquals(ext, last, "tmp") || segmentEquals(ext, last, "bak")) {
    return true;
  }
  if (!segmentEquals(ext, last, "jso")) return false;
  const char* tilde = static_cast<const char*>(memchr(first, '~', static_cast<size_t>(last - first)));
  const size_t prefixLen = static_cast<size_t>(tilde - first);
  // Real lossy aliases keep at least four characters of these stems.
  if (prefixLen < 4) return false;
  for (const char* stem : SECRET_STEMS) {
    if (strlen(stem) >= prefixLen && strncasecmp(stem, first, prefixLen) == 0) return true;
  }
  return false;
}

inline bool nameMatchesList(const char* first, const char* last, const char* const* names, size_t count) {
  const size_t len = static_cast<size_t>(last - first);
  for (size_t i = 0; i < count; ++i) {
    const size_t nlen = strlen(names[i]);
    if (len >= nlen && strncasecmp(first, names[i], nlen) == 0 && (len == nlen || first[nlen] == '.')) return true;
  }
  return false;
}

inline bool isNetworkSecretName(const char* name) {
  if (!name) return false;
  const char* first = name;
  const char* last = name + strlen(name);
  trimBounds(first, last);
  if (first >= last) return false;
  if (isSecretShortAlias(first, last)) return true;
  if (nameMatchesList(first, last, NETWORK_SECRET_NAMES,
                      sizeof(NETWORK_SECRET_NAMES) / sizeof(NETWORK_SECRET_NAMES[0]))) {
    return true;
  }
  // A book key is the final extension, or that extension plus .bak / .tmp.
  // "my.key.epub" is a book name and stays transferable.
  if (segmentEndsWith(first, last, ".key")) return true;
  if (segmentEndsWith(first, last, ".key.bak") || segmentEndsWith(first, last, ".key.tmp")) return true;
  // A short name with no tilde: "a.epub.key.tmp" becomes "AEPUBKEY.TMP".
  const char* dot = nullptr;
  for (const char* p = first; p < last; ++p) {
    if (*p == '.') dot = p;
  }
  if (memchr(first, '~', static_cast<size_t>(last - first)) == nullptr && dot != nullptr) {
    const size_t base = static_cast<size_t>(dot - first);
    const size_t extLen = static_cast<size_t>(last - dot - 1);
    if (base >= 3 && base <= 8 && extLen <= 3 &&
        (segmentEquals(dot + 1, last, "tmp") || segmentEquals(dot + 1, last, "bak")) &&
        strncasecmp(dot - 3, "key", 3) == 0) {
      return true;
    }
  }
  return false;
}

inline bool isCredentialFileName(const char* name) {
  if (!name) return false;
  const char* first = name;
  const char* last = name + strlen(name);
  trimBounds(first, last);
  if (first >= last) return false;
  if (isSecretShortAlias(first, last)) return true;
  return nameMatchesList(first, last, CREDENTIAL_BASENAMES,
                         sizeof(CREDENTIAL_BASENAMES) / sizeof(CREDENTIAL_BASENAMES[0]));
}

inline bool isNetworkSecretPath(const char* path) {
  const CanonPath canon = canonicalize(path);
  if (canon.path.empty()) return false;
  return isNetworkSecretName(lastSegment(canon));
}

// File-manager and WebDAV denial. Plugin writes use isPluginPath instead.
inline bool isNetworkDeniedPath(const char* path) {
  const CanonPath canon = canonicalize(path);
  if (sensitiveCanon(canon)) return true;
  return !canon.path.empty() && isNetworkSecretName(lastSegment(canon));
}

inline bool isCredentialStoreDir(const char* path) {
  const CanonPath canon = canonicalize(path);
  if (canon.path.size() == strlen("/.crosspoint") &&
      strncasecmp(canon.path.c_str(), "/.crosspoint", canon.path.size()) == 0) {
    return true;
  }
  // CROSSP~1 and any other single shallow alias opens the same directory slot.
  return canon.shallowAlias && canon.path.find('/', 1) == std::string::npos;
}

inline bool containsDotSegment(const CanonPath& canon) {
  const char* s = canon.path.c_str();
  while (*s) {
    if (*s == '/') s++;
    if (*s == '.') return true;
    const char* slash = strchr(s, '/');
    if (!slash) return false;
    s = slash;
  }
  return false;
}

inline bool containsHiddenVolume(const CanonPath& canon) {
  const char* s = canon.path.c_str();
  while (*s) {
    if (*s == '/') s++;
    const char* slash = strchr(s, '/');
    const char* end = slash ? slash : s + strlen(s);
    for (const char* name : HIDDEN_VOLUME_NAMES) {
      if (segmentEquals(s, end, name)) return true;
    }
    if (!slash) return false;
    s = slash;
  }
  return false;
}

// WebDAV has no "show hidden files" switch: dot directories, volume metadata,
// credential stores, and network secret names are all refused.
inline bool isWebDavBlocked(const char* path) {
  const CanonPath canon = canonicalize(path);
  if (sensitiveCanon(canon)) return true;
  if (!canon.path.empty() && isNetworkSecretName(lastSegment(canon))) return true;
  if (containsDotSegment(canon)) return true;
  return containsHiddenVolume(canon);
}

// A plugin-supplied path (web request or device.json): absolute, no parent
// refs, not a credential store. token.json remains writable here.
inline bool isPluginPath(const std::string& p) {
  return p.size() > 1 && p[0] == '/' && p.find("..") == std::string::npos && !isSensitivePath(p.c_str());
}

}  // namespace protectedpaths
