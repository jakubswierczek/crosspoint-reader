#pragma once

#include <cstddef>
#include <cstdint>

// Same codepoints as isPunctuation() in HyphenationCommon.cpp. Kept here so the
// HTML parser test does not have to link that file (it stubs the hyphen helpers).
inline bool polishGlueIsPunctuation(const uint32_t cp) {
  switch (cp) {
    case '-':
    case '.':
    case ',':
    case '!':
    case '?':
    case ';':
    case ':':
    case '"':
    case '\'':
    case ')':
    case '(':
    case 0x00AB:  // «
    case 0x00BB:  // »
    case 0x2018:  // ‘
    case 0x2019:  // ’
    case 0x201A:  // ‚
    case 0x201C:  // “
    case 0x201D:  // ”
    case 0x201E:  // „
    case 0x00A0:  // no-break space
    case '{':
    case '}':
    case '[':
    case ']':
    case '/':
    case 0x2039:  // ‹
    case 0x203A:  // ›
    case 0x2026:  // …
      return true;
    default:
      return false;
  }
}

// a, i, o, u, w, z — the one-letter Polish words that stay with the next word.
inline bool isPolishSingleLetterCp(const uint32_t cp) {
  switch (cp) {
    case 'a':
    case 'A':
    case 'i':
    case 'I':
    case 'o':
    case 'O':
    case 'u':
    case 'U':
    case 'w':
    case 'W':
    case 'z':
    case 'Z':
      return true;
    default:
      return false;
  }
}

// One UTF-8 codepoint inside [0, bytes). False on a short or invalid sequence.
inline bool polishGlueNextCp(const char* word, const size_t bytes, size_t* index, uint32_t* cp) {
  if (word == nullptr || index == nullptr || cp == nullptr || *index >= bytes) return false;
  const auto lead = static_cast<unsigned char>(word[*index]);
  size_t len = 1;
  uint32_t value = lead;
  if (lead < 0x80) {
    value = lead;
  } else if ((lead & 0xE0) == 0xC0 && *index + 1 < bytes) {
    len = 2;
    value = static_cast<uint32_t>(lead & 0x1F) << 6;
    value |= static_cast<unsigned char>(word[*index + 1]) & 0x3F;
  } else if ((lead & 0xF0) == 0xE0 && *index + 2 < bytes) {
    len = 3;
    value = static_cast<uint32_t>(lead & 0x0F) << 12;
    value |= static_cast<uint32_t>(static_cast<unsigned char>(word[*index + 1]) & 0x3F) << 6;
    value |= static_cast<unsigned char>(word[*index + 2]) & 0x3F;
  } else if ((lead & 0xF8) == 0xF0 && *index + 3 < bytes) {
    len = 4;
    value = static_cast<uint32_t>(lead & 0x07) << 18;
    value |= static_cast<uint32_t>(static_cast<unsigned char>(word[*index + 1]) & 0x3F) << 12;
    value |= static_cast<uint32_t>(static_cast<unsigned char>(word[*index + 2]) & 0x3F) << 6;
    value |= static_cast<unsigned char>(word[*index + 3]) & 0x3F;
  } else {
    return false;
  }
  *cp = value;
  *index += len;
  return true;
}

// True when the buffer is a one-letter Polish word, or punctuation plus that letter
// ("i", "„i", "(w"). A letter with anything after it ("w.", "„i”") is not a match.
// *letterAt is the byte offset of the letter. *prefixCodepoints counts the punctuation.
inline bool polishSingleLetterWord(const char* word, const size_t bytes, size_t* letterAt, size_t* prefixCodepoints) {
  if (word == nullptr || bytes == 0 || letterAt == nullptr || prefixCodepoints == nullptr) return false;
  size_t index = 0;
  size_t lastStart = 0;
  uint32_t last = 0;
  while (index < bytes) {
    lastStart = index;
    if (!polishGlueNextCp(word, bytes, &index, &last)) return false;
  }
  if (!isPolishSingleLetterCp(last)) return false;
  index = 0;
  size_t prefix = 0;
  while (index < lastStart) {
    uint32_t cp = 0;
    if (!polishGlueNextCp(word, bytes, &index, &cp) || !polishGlueIsPunctuation(cp)) return false;
    ++prefix;
  }
  *letterAt = lastStart;
  *prefixCodepoints = prefix;
  return true;
}
