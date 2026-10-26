#include <gtest/gtest.h>

#include "Serialization/ObfuscationCodec.h"

TEST(ObfuscationCodecTest, V2PrefixIsNotPlainBase64) {
  EXPECT_EQ(std::strlen(obfuscation::V2_PREFIX), obfuscation::V2_PREFIX_LEN);
  EXPECT_NE(std::strchr(obfuscation::V2_PREFIX, '.'), nullptr);
  EXPECT_TRUE(obfuscation::isV2Blob("v2.YQ=="));
  EXPECT_FALSE(obfuscation::isV2Blob("YQ=="));
  EXPECT_FALSE(obfuscation::isV2Blob(""));
  EXPECT_FALSE(obfuscation::isV2Blob(nullptr));
}

TEST(ObfuscationCodecTest, UpgradeOnlyLegacyBlobsWhenTheKeyExists) {
  EXPECT_TRUE(obfuscation::shouldUpgradeStoredForm("YQ==", true));
  EXPECT_FALSE(obfuscation::shouldUpgradeStoredForm("v2.YQ==", true));
  EXPECT_FALSE(obfuscation::shouldUpgradeStoredForm("YQ==", false));
  EXPECT_FALSE(obfuscation::shouldUpgradeStoredForm("", true));
  EXPECT_FALSE(obfuscation::shouldUpgradeStoredForm(nullptr, true));
}
