#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>

// Decides whether /api/relay and /api/fetch may open a URL. The check is on
// the URL text only: a name that later resolves somewhere else is not
// re-checked. Private LAN addresses stay allowed so a companion on the same
// network can reach a local server. Loopback, the unspecified address, and
// link-local addresses are refused.
namespace pluginrelay {

enum class UrlReject : uint8_t {
  Ok = 0,
  Empty,
  Scheme,
  Userinfo,
  Host,
  Port,
  Loopback,
  LinkLocal,
};

inline bool urlAllowed(const char* url);

namespace detail {

inline int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Same shapes lwIP ip4addr_aton accepts: hex (0x), octal (leading 0), and
// one to four parts (a, a.b, a.b.c, a.b.c.d). The TCP stack parses these
// before DNS, so a name-shaped allow would still connect.
inline bool parseLwipIpv4(const char* begin, const char* end, uint8_t out[4]) {
  if (begin == nullptr || end < begin || static_cast<size_t>(end - begin) > 253) return false;
  const char* cp = begin;
  uint32_t parts[4];
  uint32_t* pp = parts;
  uint32_t val = 0;
  auto advance = [&]() -> char {
    if (cp >= end) return '\0';
    ++cp;
    return cp < end ? *cp : '\0';
  };
  char c = cp < end ? *cp : '\0';
  for (;;) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    val = 0;
    int base = 10;
    if (c == '0') {
      c = advance();
      if (c == 'x' || c == 'X') {
        base = 16;
        c = advance();
      } else {
        base = 8;
      }
    }
    for (;;) {
      if (std::isdigit(static_cast<unsigned char>(c))) {
        if (base == 8 && static_cast<unsigned>(c - '0') >= 8) break;
        val = val * static_cast<uint32_t>(base) + static_cast<uint32_t>(c - '0');
        c = advance();
      } else if (base == 16 && std::isxdigit(static_cast<unsigned char>(c))) {
        const unsigned char lower = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(c)));
        val = (val << 4) | static_cast<uint32_t>(lower <= '9' ? lower - '0' : lower - 'a' + 10);
        c = advance();
      } else {
        break;
      }
    }
    if (c == '.') {
      if (pp >= parts + 3) return false;
      *pp++ = val;
      c = advance();
    } else {
      break;
    }
  }
  if (c != '\0' || cp != end) return false;

  switch (pp - parts + 1) {
    case 1:
      break;
    case 2:
      if (val > 0xffffffUL || parts[0] > 0xff) return false;
      val |= parts[0] << 24;
      break;
    case 3:
      if (val > 0xffffUL || parts[0] > 0xff || parts[1] > 0xff) return false;
      val |= (parts[0] << 24) | (parts[1] << 16);
      break;
    case 4:
      if (val > 0xff || parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xff) return false;
      val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
      break;
    default:
      return false;
  }
  out[0] = static_cast<uint8_t>(val >> 24);
  out[1] = static_cast<uint8_t>((val >> 16) & 0xff);
  out[2] = static_cast<uint8_t>((val >> 8) & 0xff);
  out[3] = static_cast<uint8_t>(val & 0xff);
  return true;
}

inline bool parseIpv4(const char* begin, const char* end, uint8_t out[4]) {
  const char* cursor = begin;
  for (int octet = 0; octet < 4; ++octet) {
    if (cursor >= end || !std::isdigit(static_cast<unsigned char>(*cursor))) return false;
    if (*cursor == '0' && cursor + 1 < end && std::isdigit(static_cast<unsigned char>(cursor[1]))) return false;
    int value = 0;
    const char* start = cursor;
    while (cursor < end && std::isdigit(static_cast<unsigned char>(*cursor))) {
      value = value * 10 + (*cursor - '0');
      if (value > 255) return false;
      ++cursor;
    }
    if (cursor == start) return false;
    out[octet] = static_cast<uint8_t>(value);
    if (octet < 3) {
      if (cursor >= end || *cursor != '.') return false;
      ++cursor;
    }
  }
  return cursor == end;
}

inline UrlReject classifyIpv4(const uint8_t ip[4]) {
  if (ip[0] == 127 || ip[0] == 0) return UrlReject::Loopback;
  if (ip[0] == 169 && ip[1] == 254) return UrlReject::LinkLocal;
  return UrlReject::Ok;
}

inline int parseGroups(const char* text, int* out, int maxGroups) {
  if (text[0] == '\0') return 0;
  int count = 0;
  const char* cursor = text;
  while (*cursor && count < maxGroups) {
    const char* colon = std::strchr(cursor, ':');
    const char* dot = std::strchr(cursor, '.');
    if (dot != nullptr && (colon == nullptr || dot < colon)) {
      if (colon != nullptr) return -1;
      uint8_t ip[4];
      if (!parseIpv4(cursor, cursor + std::strlen(cursor), ip) || count + 2 > maxGroups) return -1;
      out[count++] = (ip[0] << 8) | ip[1];
      out[count++] = (ip[2] << 8) | ip[3];
      return count;
    }
    int value = 0;
    int digits = 0;
    while (*cursor && *cursor != ':') {
      const int digit = hexValue(*cursor);
      if (digit < 0) return -1;
      value = (value << 4) | digit;
      if (++digits > 4) return -1;
      ++cursor;
    }
    if (digits == 0) return -1;
    out[count++] = value;
    if (*cursor == ':') ++cursor;
  }
  if (*cursor) return -1;
  return count;
}

inline UrlReject classifyIpv6(const char* inside, size_t length) {
  if (length == 0 || length > 64) return UrlReject::Host;
  char text[65];
  for (size_t i = 0; i < length; ++i) text[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(inside[i])));
  text[length] = '\0';
  if (std::strchr(text, '%') != nullptr) return UrlReject::Host;

  int groups[8] = {};
  const char* gap = std::strstr(text, "::");
  if (gap != nullptr) {
    if (std::strstr(gap + 2, "::") != nullptr) return UrlReject::Host;
    char leftText[65];
    char rightText[65];
    const size_t leftLength = static_cast<size_t>(gap - text);
    std::memcpy(leftText, text, leftLength);
    leftText[leftLength] = '\0';
    std::memcpy(rightText, gap + 2, length - leftLength - 2);
    rightText[length - leftLength - 2] = '\0';
    int left[8];
    int right[8];
    const int leftCount = leftLength == 0 ? 0 : parseGroups(leftText, left, 8);
    const int rightCount = rightText[0] == '\0' ? 0 : parseGroups(rightText, right, 8);
    if (leftCount < 0 || rightCount < 0 || leftCount + rightCount > 8) return UrlReject::Host;
    for (int i = 0; i < leftCount; ++i) groups[i] = left[i];
    for (int i = 0; i < rightCount; ++i) groups[8 - rightCount + i] = right[i];
  } else {
    const int count = parseGroups(text, groups, 8);
    if (count != 8) return UrlReject::Host;
  }

  bool unspecified = true;
  for (int group : groups) unspecified = unspecified && group == 0;
  if (unspecified || (groups[7] == 1 && groups[0] == 0 && groups[1] == 0 && groups[2] == 0 && groups[3] == 0 &&
                      groups[4] == 0 && groups[5] == 0 && groups[6] == 0)) {
    return UrlReject::Loopback;
  }
  if ((groups[0] & 0xffc0) == 0xfe80) return UrlReject::LinkLocal;
  if (groups[0] == 0 && groups[1] == 0 && groups[2] == 0 && groups[3] == 0 && groups[4] == 0 && groups[5] == 0xffff) {
    const uint8_t ip[4] = {static_cast<uint8_t>(groups[6] >> 8), static_cast<uint8_t>(groups[6] & 0xff),
                           static_cast<uint8_t>(groups[7] >> 8), static_cast<uint8_t>(groups[7] & 0xff)};
    return classifyIpv4(ip);
  }
  return UrlReject::Ok;
}

inline bool parsePort(const char* begin, const char* end) {
  if (begin >= end || *begin == '0') return false;
  int value = 0;
  for (const char* cursor = begin; cursor < end; ++cursor) {
    if (!std::isdigit(static_cast<unsigned char>(*cursor))) return false;
    value = value * 10 + (*cursor - '0');
    if (value > 65535) return false;
  }
  return value >= 1;
}

inline UrlReject classifyHost(const char* host, size_t length) {
  while (length > 0 && host[length - 1] == '.') --length;
  if (length == 0 || length > 253) return UrlReject::Host;
  for (size_t i = 0; i < length; ++i) {
    const unsigned char c = static_cast<unsigned char>(host[i]);
    if (c <= 0x20 || c == '%' || c == '\\' || c == '@') return UrlReject::Host;
  }

  if (host[0] == '[') {
    if (host[length - 1] != ']') return UrlReject::Host;
    return classifyIpv6(host + 1, length - 2);
  }

  char lower[254];
  for (size_t i = 0; i < length; ++i) lower[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(host[i])));
  lower[length] = '\0';
  if (std::strcmp(lower, "localhost") == 0) return UrlReject::Loopback;
  if (length >= 10 && std::strcmp(lower + length - 10, ".localhost") == 0) return UrlReject::Loopback;

  bool onlyDigitsAndDots = true;
  for (size_t i = 0; i < length; ++i) {
    if (lower[i] != '.' && !std::isdigit(static_cast<unsigned char>(lower[i]))) onlyDigitsAndDots = false;
  }
  uint8_t ip[4];
  if (parseLwipIpv4(lower, lower + length, ip)) return classifyIpv4(ip);
  if (onlyDigitsAndDots) return UrlReject::Host;

  const char* label = lower;
  while (*label) {
    const char* dot = std::strchr(label, '.');
    const size_t labelLength = dot ? static_cast<size_t>(dot - label) : std::strlen(label);
    if (labelLength == 0 || labelLength > 63) return UrlReject::Host;
    if (label[0] == '-' || label[labelLength - 1] == '-') return UrlReject::Host;
    for (size_t i = 0; i < labelLength; ++i) {
      const unsigned char c = static_cast<unsigned char>(label[i]);
      if (!std::isalnum(c) && c != '-') return UrlReject::Host;
    }
    if (!dot) break;
    label = dot + 1;
  }
  return UrlReject::Ok;
}

inline bool startsWithScheme(const char* url, size_t length, const char* scheme, size_t schemeLength) {
  if (length < schemeLength) return false;
  for (size_t i = 0; i < schemeLength; ++i) {
    if (std::tolower(static_cast<unsigned char>(url[i])) != scheme[i]) return false;
  }
  return true;
}

}  // namespace detail

inline UrlReject checkUrl(const char* url) {
  if (url == nullptr || url[0] == '\0') return UrlReject::Empty;
  const size_t length = std::strlen(url);
  if (length > 2048) return UrlReject::Scheme;

  size_t schemeLength = 0;
  if (detail::startsWithScheme(url, length, "https://", 8))
    schemeLength = 8;
  else if (detail::startsWithScheme(url, length, "http://", 7))
    schemeLength = 7;
  else
    return UrlReject::Scheme;

  const char* authority = url + schemeLength;
  const char* authorityEnd = authority;
  while (*authorityEnd && *authorityEnd != '/' && *authorityEnd != '?' && *authorityEnd != '#') ++authorityEnd;
  if (authority == authorityEnd) return UrlReject::Host;
  for (const char* cursor = authority; cursor < authorityEnd; ++cursor) {
    if (*cursor == '@') return UrlReject::Userinfo;
  }

  const char* host = authority;
  const char* hostEnd = authorityEnd;
  const char* port = nullptr;
  if (*host == '[') {
    const char* bracket = static_cast<const char*>(std::memchr(host, ']', static_cast<size_t>(authorityEnd - host)));
    if (bracket == nullptr) return UrlReject::Host;
    hostEnd = bracket + 1;
    if (hostEnd < authorityEnd) {
      if (*hostEnd != ':') return UrlReject::Host;
      port = hostEnd + 1;
    }
  } else {
    const char* colon = nullptr;
    for (const char* cursor = host; cursor < authorityEnd; ++cursor) {
      if (*cursor == ':') {
        if (colon != nullptr) return UrlReject::Host;
        colon = cursor;
      }
    }
    if (colon != nullptr) {
      hostEnd = colon;
      port = colon + 1;
    }
  }
  if (port != nullptr && !detail::parsePort(port, authorityEnd)) return UrlReject::Port;

  const UrlReject hostDecision = detail::classifyHost(host, static_cast<size_t>(hostEnd - host));
  if (hostDecision != UrlReject::Ok) return hostDecision;

  for (const char* cursor = authorityEnd; *cursor; ++cursor) {
    const unsigned char c = static_cast<unsigned char>(*cursor);
    if (c < 0x20 || c == 0x7f || c == '\\') return UrlReject::Host;
  }
  return UrlReject::Ok;
}

inline bool urlAllowed(const char* url) { return checkUrl(url) == UrlReject::Ok; }

}  // namespace pluginrelay
