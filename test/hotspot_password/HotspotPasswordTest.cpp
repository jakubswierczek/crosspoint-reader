#include <gtest/gtest.h>

#include <string>

#include "network/HotspotPassword.h"

namespace {

uint32_t sequential(uint32_t& n) { return n++; }

}  // namespace

TEST(HotspotPasswordTest, AlphabetFitsAnUnbiasedMaskAndOmitsQrSeparators) {
  EXPECT_EQ(hotspot::PASSWORD_ALPHABET_LEN, 32u);
  EXPECT_EQ(strlen(hotspot::PASSWORD_ALPHABET), 32u);
  EXPECT_EQ(strpbrk(hotspot::PASSWORD_ALPHABET, ";:\\,\""), nullptr);
}

TEST(HotspotPasswordTest, GeneratedPasswordIsTenAlphabetCharacters) {
  uint32_t n = 0;
  char password[hotspot::PASSWORD_LEN + 1];
  hotspot::generatePassword(password, [&n] { return sequential(n); });
  EXPECT_TRUE(hotspot::passwordCharsOk(password));
  EXPECT_STREQ(password, "23456789AB");
}

TEST(HotspotPasswordTest, WifiQrUsesWpaAndTheGeneratedPassword) {
  char qr[80];
  ASSERT_TRUE(hotspot::formatWifiQr(qr, sizeof(qr), "CrossPoint-Reader", "H7K2M9PQAB"));
  EXPECT_STREQ(qr, "WIFI:T:WPA;S:CrossPoint-Reader;P:H7K2M9PQAB;;");
}

TEST(HotspotPasswordTest, RejectsShortSecretsAndSeparatorBearingSsids) {
  EXPECT_FALSE(hotspot::passwordCharsOk("SHORT"));
  EXPECT_FALSE(hotspot::passwordCharsOk("H7K2M9PQ;A"));
  EXPECT_FALSE(hotspot::passwordCharsOk(nullptr));
  char qr[80];
  EXPECT_FALSE(hotspot::formatWifiQr(qr, sizeof(qr), "Cross;Point", "H7K2M9PQAB"));
  EXPECT_FALSE(hotspot::formatWifiQr(qr, 8, "CrossPoint-Reader", "H7K2M9PQAB"));
}
