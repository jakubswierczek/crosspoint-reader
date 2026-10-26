#include <gtest/gtest.h>

#include "network/PluginRelayPolicy.h"

TEST(PluginRelayPolicyTest, AllowsPublicHttpsAndPrivateLan) {
  EXPECT_TRUE(pluginrelay::urlAllowed("https://readwise.io/api/v2/books/"));
  EXPECT_TRUE(pluginrelay::urlAllowed("https://API.Example.com:443/a?b=1#c"));
  EXPECT_TRUE(pluginrelay::urlAllowed("http://192.168.1.20:8080/book.epub"));
  EXPECT_TRUE(pluginrelay::urlAllowed("http://10.0.0.1/"));
  EXPECT_TRUE(pluginrelay::urlAllowed("http://172.16.5.5/"));
  EXPECT_TRUE(pluginrelay::urlAllowed("http://[2001:db8::1]/"));
  EXPECT_TRUE(pluginrelay::urlAllowed("http://[::ffff:192.168.0.8]/x"));
}

TEST(PluginRelayPolicyTest, RejectsLoopbackLinkLocalAndUserinfo) {
  EXPECT_EQ(pluginrelay::checkUrl(""), pluginrelay::UrlReject::Empty);
  EXPECT_EQ(pluginrelay::checkUrl("ftp://example.com/"), pluginrelay::UrlReject::Scheme);
  EXPECT_EQ(pluginrelay::checkUrl("http://user:secret@example.com/"), pluginrelay::UrlReject::Userinfo);
  EXPECT_EQ(pluginrelay::checkUrl("http://127.0.0.1/"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://127.0.0.2:9/x"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://0.0.0.0/"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://localhost/"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://LOCALHOST:8080/"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://api.localhost/"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://[::1]/"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://[0:0:0:0:0:0:0:1]/"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://[::ffff:127.0.0.1]/"), pluginrelay::UrlReject::Loopback);
  EXPECT_EQ(pluginrelay::checkUrl("http://169.254.169.254/"), pluginrelay::UrlReject::LinkLocal);
  EXPECT_EQ(pluginrelay::checkUrl("http://[fe80::1]/"), pluginrelay::UrlReject::LinkLocal);
  EXPECT_EQ(pluginrelay::checkUrl("http://[::ffff:169.254.1.1]/"), pluginrelay::UrlReject::LinkLocal);
}

TEST(PluginRelayPolicyTest, RejectsObscuredHostsAndBadPorts) {
  EXPECT_EQ(pluginrelay::checkUrl("http://2130706433/"), pluginrelay::UrlReject::Host);
  EXPECT_EQ(pluginrelay::checkUrl("http://127.1/"), pluginrelay::UrlReject::Host);
  EXPECT_EQ(pluginrelay::checkUrl("http://0177.0.0.1/"), pluginrelay::UrlReject::Host);
  EXPECT_EQ(pluginrelay::checkUrl("http://127.0.0.1%2e/"), pluginrelay::UrlReject::Host);
  EXPECT_EQ(pluginrelay::checkUrl("http://example.com:/"), pluginrelay::UrlReject::Port);
  EXPECT_EQ(pluginrelay::checkUrl("http://example.com:0/"), pluginrelay::UrlReject::Port);
  EXPECT_EQ(pluginrelay::checkUrl("http://example.com:080/"), pluginrelay::UrlReject::Port);
  EXPECT_EQ(pluginrelay::checkUrl("http://example.com:65536/"), pluginrelay::UrlReject::Port);
  EXPECT_FALSE(pluginrelay::urlAllowed(nullptr));
}
