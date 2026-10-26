#include <gtest/gtest.h>

#include <string>

#include "PolishQwertyAlt.h"
#include "Utf8FieldEdit.h"

TEST(PolishQwertyAlt, LongPressLetters) {
  EXPECT_STREQ(polishQwertyAlt('a'), "\xC4\x85");
  EXPECT_STREQ(polishQwertyAlt('c'), "\xC4\x87");
  EXPECT_STREQ(polishQwertyAlt('e'), "\xC4\x99");
  EXPECT_STREQ(polishQwertyAlt('l'), "\xC5\x82");
  EXPECT_STREQ(polishQwertyAlt('n'), "\xC5\x84");
  EXPECT_STREQ(polishQwertyAlt('o'), "\xC3\xB3");
  EXPECT_STREQ(polishQwertyAlt('s'), "\xC5\x9B");
  EXPECT_STREQ(polishQwertyAlt('z'), "\xC5\xBC");
  EXPECT_STREQ(polishQwertyAlt('x'), "\xC5\xBA");
  EXPECT_STREQ(polishQwertyAlt('A'), "\xC4\x84");
  EXPECT_STREQ(polishQwertyAlt('Z'), "\xC5\xBB");
  EXPECT_STREQ(polishQwertyAlt('X'), "\xC5\xB9");
  EXPECT_EQ(polishQwertyAlt('q'), nullptr);
  EXPECT_EQ(polishQwertyAlt('1'), nullptr);
}

TEST(Utf8FieldEdit, InsertAndBackspaceStayOnCodepointBoundaries) {
  std::string text = "ab";
  size_t cursor = 1;
  utf8FieldInsert(text, cursor, 0, polishQwertyAlt('l'));
  EXPECT_EQ(text, "a\xC5\x82"
                  "b");
  EXPECT_EQ(cursor, 3u);
  EXPECT_TRUE(utf8FieldBackspace(text, cursor));
  EXPECT_EQ(text, "ab");
  EXPECT_EQ(cursor, 1u);
  EXPECT_EQ(utf8FieldPrev(text, 0), 0u);
  EXPECT_FALSE(utf8FieldBackspace(text, cursor = 0));
}

TEST(Utf8FieldEdit, MaxLengthCountsBytes) {
  std::string text;
  size_t cursor = 0;
  utf8FieldInsert(text, cursor, 1, polishQwertyAlt('a'));
  EXPECT_TRUE(text.empty());
  EXPECT_EQ(cursor, 0u);
  utf8FieldInsert(text, cursor, 2, polishQwertyAlt('a'));
  EXPECT_EQ(text, "\xC4\x85");
  utf8FieldInsert(text, cursor, 2, "b");
  EXPECT_EQ(text, "\xC4\x85");
  EXPECT_EQ(cursor, 2u);
}
