#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "Epub/hyphenation/Hyphenator.h"

namespace {

std::vector<size_t> breaksFor(const std::string& tag, const std::string& word) {
  Hyphenator::setPreferredLanguage(tag);
  const auto infos = Hyphenator::breakOffsets(word, false);
  std::vector<size_t> offsets;
  offsets.reserve(infos.size());
  for (const auto& info : infos) offsets.push_back(info.byteOffset);
  return offsets;
}

}  // namespace

TEST(HyphenationLanguageTag, PolishThreeLetterTagSelectsPolishPatterns) {
  const auto polish = breaksFor("pl", "jeszcze");
  ASSERT_FALSE(polish.empty());
  EXPECT_EQ(breaksFor("PL", "jeszcze"), polish);
  EXPECT_EQ(breaksFor("pl-PL", "jeszcze"), polish);
  EXPECT_EQ(breaksFor("pol", "jeszcze"), polish);
  EXPECT_EQ(breaksFor("POL", "jeszcze"), polish);
  EXPECT_EQ(breaksFor("pol-PL", "jeszcze"), polish);
  EXPECT_NE(breaksFor("en", "jeszcze"), polish);
  EXPECT_TRUE(breaksFor("", "jeszcze").empty());
}

TEST(HyphenationLanguageTag, PortugueseThreeLetterTagSelectsPortuguesePatterns) {
  const auto portuguese = breaksFor("pt", "depois");
  ASSERT_FALSE(portuguese.empty());
  EXPECT_EQ(breaksFor("pt-BR", "depois"), portuguese);
  EXPECT_EQ(breaksFor("por", "depois"), portuguese);
  EXPECT_EQ(breaksFor("POR", "depois"), portuguese);
  EXPECT_NE(breaksFor("en", "depois"), portuguese);
}

TEST(HyphenationLanguageTag, ExistingThreeLetterTagsStayMapped) {
  EXPECT_EQ(breaksFor("fre", "madame"), breaksFor("fr", "madame"));
  EXPECT_EQ(breaksFor("fra", "madame"), breaksFor("fr", "madame"));
  EXPECT_EQ(breaksFor("ger", "selber"), breaksFor("de", "selber"));
  EXPECT_EQ(breaksFor("deu", "selber"), breaksFor("de", "selber"));
  EXPECT_EQ(breaksFor("eng", "something"), breaksFor("en", "something"));
}
