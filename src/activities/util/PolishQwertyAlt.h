#pragma once

#include <cstdint>

// Long-press letter for Polish QWERTY. x is ź, the same slot as AltGr+x on a
// Polish programmer keyboard. z is ż. Letters with no diacritic return null so
// the keyboard's usual hold-for-capital still applies.
constexpr const char* polishQwertyAlt(const int16_t value) {
  switch (value) {
    case 'a':
      return "\xC4\x85";  // ą
    case 'A':
      return "\xC4\x84";  // Ą
    case 'c':
      return "\xC4\x87";  // ć
    case 'C':
      return "\xC4\x86";  // Ć
    case 'e':
      return "\xC4\x99";  // ę
    case 'E':
      return "\xC4\x98";  // Ę
    case 'l':
      return "\xC5\x82";  // ł
    case 'L':
      return "\xC5\x81";  // Ł
    case 'n':
      return "\xC5\x84";  // ń
    case 'N':
      return "\xC5\x83";  // Ń
    case 'o':
      return "\xC3\xB3";  // ó
    case 'O':
      return "\xC3\x93";  // Ó
    case 's':
      return "\xC5\x9B";  // ś
    case 'S':
      return "\xC5\x9A";  // Ś
    case 'x':
      return "\xC5\xBA";  // ź
    case 'X':
      return "\xC5\xB9";  // Ź
    case 'z':
      return "\xC5\xBC";  // ż
    case 'Z':
      return "\xC5\xBB";  // Ż
    default:
      return nullptr;
  }
}
