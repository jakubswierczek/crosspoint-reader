#pragma once

#include <cstring>
#include <string>

// Cursor motion and edits on a UTF-8 text field. The cursor is always a byte
// offset on a code-point boundary. maxLength is a byte cap; 0 means unlimited.
// A character that does not fit is left untyped.

inline size_t utf8FieldPrev(const std::string& s, size_t pos) {
  if (pos == 0) return 0;
  pos--;
  while (pos > 0 && (static_cast<unsigned char>(s[pos]) & 0xC0) == 0x80) pos--;
  return pos;
}

inline size_t utf8FieldNext(const std::string& s, size_t pos) {
  if (pos >= s.length()) return s.length();
  pos++;
  while (pos < s.length() && (static_cast<unsigned char>(s[pos]) & 0xC0) == 0x80) pos++;
  return pos;
}

inline void utf8FieldInsert(std::string& text, size_t& cursorPos, const size_t maxLength, const char* out) {
  if (!out || !*out) return;
  const size_t n = strlen(out);
  if (maxLength != 0 && text.length() + n > maxLength) return;
  if (cursorPos > text.length()) cursorPos = text.length();
  text.insert(cursorPos, out, n);
  cursorPos += n;
}

inline bool utf8FieldBackspace(std::string& text, size_t& cursorPos) {
  if (text.empty() || cursorPos == 0) return false;
  const size_t prev = utf8FieldPrev(text, cursorPos);
  text.erase(prev, cursorPos - prev);
  cursorPos = prev;
  return true;
}
