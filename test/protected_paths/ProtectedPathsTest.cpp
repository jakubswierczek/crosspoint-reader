#include <gtest/gtest.h>

#include "network/ProtectedPaths.h"

using protectedpaths::isCredentialFileName;
using protectedpaths::isCredentialStoreDir;
using protectedpaths::isNetworkDeniedPath;
using protectedpaths::isNetworkSecretName;
using protectedpaths::isNetworkSecretPath;
using protectedpaths::isPluginPath;
using protectedpaths::isSensitivePath;
using protectedpaths::isWebDavBlocked;

TEST(ProtectedPaths, CredentialStoresAreSensitive) {
  EXPECT_TRUE(isSensitivePath("/.crosspoint/wifi.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint/opds.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint/koreader.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint/wifi.json.tmp"));
  EXPECT_TRUE(isSensitivePath("/.CrossPoint/WIFI.json"));
}

TEST(ProtectedPaths, SpellingVariantsCannotDodgeTheMatch) {
  EXPECT_TRUE(isSensitivePath("/.crosspoint/./wifi.json"));
  EXPECT_TRUE(isSensitivePath("//.crosspoint//wifi.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint/plugins/../wifi.json"));
  EXPECT_TRUE(isSensitivePath(".crosspoint/opds.json"));
}

TEST(ProtectedPaths, NamesSdFatWouldTrimOrAliasStillMatch) {
  EXPECT_TRUE(isSensitivePath("/.crosspoint/wifi.json."));
  EXPECT_TRUE(isSensitivePath("/.crosspoint./wifi.json"));
  EXPECT_TRUE(isSensitivePath("/ .crosspoint/ wifi.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint ./opds.json"));
  EXPECT_TRUE(isSensitivePath("/CROSSP~1/wifi.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint/WIFI~1.JSO"));
  EXPECT_FALSE(isSensitivePath("/Books/Photos/IMG~1.JPG"));  // too deep to reach a store
  EXPECT_FALSE(isSensitivePath("/Books/a~b.epub"));
}

TEST(ProtectedPaths, EverythingElseStaysReachable) {
  EXPECT_FALSE(isSensitivePath("/.crosspoint/settings.json"));
  EXPECT_FALSE(isSensitivePath("/.crosspoint/library.idx"));
  EXPECT_FALSE(isSensitivePath("/.crosspoint/month-wallpaper.json"));
  EXPECT_FALSE(isSensitivePath("/.fonts/Noto/Noto_14.cpfont"));
  EXPECT_FALSE(isSensitivePath("/Books/wifi.json"));
}

TEST(ProtectedPaths, PluginPathRules) {
  EXPECT_FALSE(isPluginPath("/.crosspoint/plugins/../wifi.json"));
  EXPECT_FALSE(isPluginPath("/.crosspoint/./koreader.json"));
  EXPECT_FALSE(isPluginPath("relative/path"));
  EXPECT_FALSE(isPluginPath("/"));
  EXPECT_TRUE(isPluginPath("/.crosspoint/month-wallpaper.json"));
  EXPECT_TRUE(isPluginPath("/Books/new.epub"));
}

TEST(ProtectedPaths, MoreCredentialStoresAreSensitive) {
  EXPECT_TRUE(isSensitivePath("/.crosspoint/opds_tokens.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint/lcp_passphrases.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint/lcp_device.json"));
  EXPECT_TRUE(isSensitivePath("/.crosspoint/opds_tokens.json.bak"));
  EXPECT_TRUE(isSensitivePath("/.CrossPoint/LCP_DEVICE.JSON"));
  EXPECT_FALSE(isPluginPath("/.crosspoint/opds_tokens.json"));
  EXPECT_FALSE(isPluginPath("/.crosspoint/lcp_passphrases.json.tmp"));
  EXPECT_FALSE(isPluginPath("/.crosspoint/lcp_device.json"));
}

TEST(ProtectedPaths, PluginSecretsAreDeniedOnReadButWritableByPlugins) {
  EXPECT_FALSE(isSensitivePath("/.crosspoint/plugins/readwise/token.json"));
  EXPECT_TRUE(isNetworkSecretPath("/.crosspoint/plugins/readwise/token.json"));
  EXPECT_TRUE(isNetworkDeniedPath("/.crosspoint/plugins/readwise/token.json"));
  EXPECT_TRUE(isPluginPath("/.crosspoint/plugins/readwise/token.json"));
  EXPECT_TRUE(isNetworkSecretName("token.json"));
  EXPECT_TRUE(isNetworkSecretName(" token.json"));
  EXPECT_TRUE(isNetworkSecretName("Secret.JSON.bak"));
  EXPECT_TRUE(isNetworkSecretName("credentials.json.tmp"));
  EXPECT_TRUE(isNetworkSecretPath("/Books/../secret.json"));
  EXPECT_TRUE(isNetworkSecretName("book.epub.key"));
  EXPECT_TRUE(isNetworkSecretName("book.epub.key.bak"));
  EXPECT_TRUE(isNetworkSecretName("TOKEN~1.JSO"));
  EXPECT_TRUE(isNetworkSecretName("CREDEN~1.BAK"));
  EXPECT_TRUE(isNetworkSecretName("VERYLO~1.KEY"));
  EXPECT_FALSE(isNetworkSecretName("keyboard.json"));
  EXPECT_FALSE(isNetworkSecretName("chapter.xhtml"));
  EXPECT_FALSE(isNetworkSecretName("CHAP~1.JSO"));
  EXPECT_FALSE(isNetworkSecretPath("/Books/Photos/IMG~1.JPG"));
  EXPECT_FALSE(isWebDavBlocked("/Books/Photos/IMG~1.JPG"));
  EXPECT_FALSE(isNetworkDeniedPath("/Books/My Book.epub"));
  EXPECT_FALSE(isNetworkDeniedPath("/Books/my.key.epub"));
  EXPECT_FALSE(isWebDavBlocked("/Books/my.key.epub"));
  EXPECT_TRUE(isNetworkSecretName("book.epub.key.tmp"));
  EXPECT_TRUE(isNetworkSecretName("VERYLO~1.TMP"));
  EXPECT_TRUE(isNetworkDeniedPath("/Books/Novels/VERYLO~1.TMP"));
  EXPECT_TRUE(isNetworkSecretName("AEPUBKEY.TMP"));
  EXPECT_FALSE(isNetworkSecretName("notes.bak"));
}

TEST(ProtectedPaths, SpacedParentStillReachesTheCredentialStore) {
  EXPECT_TRUE(isNetworkDeniedPath("/Books/ .. /CROSSP~1/opds_tokens.json"));
  EXPECT_TRUE(isNetworkDeniedPath("/Books/.. /CROSSP~1/wifi.json"));
  EXPECT_TRUE(isNetworkDeniedPath("/Books/ .. /CROSSP~1/lcp_passphrases.json"));
  EXPECT_TRUE(isNetworkDeniedPath("/Books/ ../.crosspoint/lcp_device.json"));
  EXPECT_TRUE(isCredentialStoreDir("/Books/ .. /CROSSP~1"));
}

TEST(ProtectedPaths, StoreDirectoryAndWebDavUseTheSameCanonicalPath) {
  EXPECT_TRUE(isCredentialStoreDir("/.crosspoint"));
  EXPECT_TRUE(isCredentialStoreDir("/ .crosspoint"));
  EXPECT_TRUE(isCredentialStoreDir("/CROSSP~1"));
  EXPECT_FALSE(isCredentialStoreDir("/Books"));
  EXPECT_FALSE(isCredentialStoreDir("/.crosspoint/plugins"));
  EXPECT_TRUE(isCredentialFileName("wifi.json"));
  EXPECT_TRUE(isCredentialFileName("WIFI.JSON.tmp"));
  EXPECT_FALSE(isCredentialFileName("settings.json"));

  EXPECT_TRUE(isWebDavBlocked("/ .crosspoint/wifi.json"));
  EXPECT_TRUE(isWebDavBlocked("/CROSSP~1/wifi.json"));
  EXPECT_TRUE(isWebDavBlocked("/.crosspoint/settings.json"));
  EXPECT_TRUE(isWebDavBlocked("/Books/token.json"));
  EXPECT_TRUE(isWebDavBlocked("/xtcache/file"));
  EXPECT_TRUE(isWebDavBlocked("/System Volume Information/foo"));
  EXPECT_TRUE(isWebDavBlocked("/system volume information"));
  EXPECT_FALSE(isWebDavBlocked("/Books/My Book.epub"));
  EXPECT_FALSE(isWebDavBlocked("/"));
}
