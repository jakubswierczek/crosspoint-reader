#include <gtest/gtest.h>

#include "network/WebAccess.h"

using webaccess::codeEquals;
using webaccess::copyBasicPassword;
using webaccess::copyBearer;
using webaccess::copyCookieCode;
using webaccess::copyQueryCode;
using webaccess::Credentials;
using webaccess::decide;
using webaccess::Decision;
using webaccess::Request;
using webaccess::State;

namespace {

constexpr const char* CODE = "H7K2M9PQ";

Request baseReq(Credentials& creds) {
  static const char* hosts[] = {"192.168.4.1", "crosspoint.local"};
  Request req;
  req.method = "GET";
  req.path = "/api/files";
  req.host = "192.168.4.1";
  req.credentials = &creds;
  req.nowMs = 1000;
  req.allowedHosts = hosts;
  req.allowedHostCount = 2;
  return req;
}

}  // namespace

TEST(WebAccess, PublicReadsSkipTheCode) {
  Credentials creds;
  State state;
  Request req = baseReq(creds);
  req.path = "/api/status";
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);

  req.path = "/assets/web.css";
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);
  req.path = "/js/jszip.min.js";
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);
  req.method = "OPTIONS";
  req.path = "/api/files";
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);
  EXPECT_EQ(state.failures, 0);
}

TEST(WebAccess, ProtectedRoutesRequireACode) {
  Credentials creds;
  State state;
  Request req = baseReq(creds);
  EXPECT_EQ(decide(req, CODE, state), Decision::Unauthorized);
  EXPECT_EQ(state.failures, 0);

  req.path = "/download";
  EXPECT_EQ(decide(req, CODE, state), Decision::Unauthorized);
  req.method = "PROPFIND";
  req.path = "/Books/Title.epub";
  EXPECT_EQ(decide(req, CODE, state), Decision::Unauthorized);
}

TEST(WebAccess, BearerBasicCookieAndQuery) {
  Credentials creds;
  State state;
  Request req = baseReq(creds);

  bool present = false;
  copyBearer("Bearer H7K2M9PQ", creds.bearer, &present);
  creds.hasBearer = present;
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);

  creds = {};
  copyBearer("bearer h7k2m9pq-extra", creds.bearer, &present);
  creds.hasBearer = present;
  EXPECT_EQ(decide(req, CODE, state), Decision::Unauthorized);
  EXPECT_EQ(state.failures, 1);

  creds = {};
  // "reader:H7K2M9PQ"
  copyBasicPassword("Basic cmVhZGVyOkg3SzJNOVBR", creds.basicPassword, &present);
  creds.hasBasic = present;
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);
  EXPECT_EQ(state.failures, 0);

  creds = {};
  copyCookieCode("other=1; cp=H7K2M9PQ", creds.cookie, &present);
  creds.hasCookie = present;
  req.method = "POST";
  req.path = "/api/settings";
  req.origin = "http://192.168.4.1";
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);

  req.origin = nullptr;
  EXPECT_EQ(decide(req, CODE, state), Decision::Forbidden);

  req.origin = "http://evil.example";
  EXPECT_EQ(decide(req, CODE, state), Decision::Forbidden);
  EXPECT_EQ(state.failures, 0);
}

TEST(WebAccess, QueryLogsInAndStripsGet) {
  Credentials creds;
  State state;
  bool present = false;
  copyQueryCode("k=H7K2M9PQ", creds.queryKey, &present);
  creds.hasQuery = present;
  Request req = baseReq(creds);
  req.path = "/";
  EXPECT_EQ(decide(req, CODE, state), Decision::RedirectStripQuery);

  req.method = "POST";
  req.path = "/upload";
  EXPECT_EQ(decide(req, CODE, state), Decision::AllowSetCookie);
}

TEST(WebAccess, HostAndCaptivePortal) {
  Credentials creds;
  State state;
  bool present = false;
  copyBearer("Bearer H7K2M9PQ", creds.bearer, &present);
  creds.hasBearer = present;
  Request req = baseReq(creds);
  req.host = "evil.example";
  EXPECT_EQ(decide(req, CODE, state), Decision::Forbidden);
  EXPECT_EQ(state.failures, 0);

  req.path = "/";
  req.method = "GET";
  req.apMode = true;
  req.host = "captive.apple.com";
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);

  req.apMode = false;
  EXPECT_EQ(decide(req, CODE, state), Decision::Forbidden);

  req.path = "/api/files";
  req.apMode = true;
  EXPECT_EQ(decide(req, CODE, state), Decision::Forbidden);
}

TEST(WebAccess, LockoutThenUnlockAcrossMillisWrap) {
  Credentials creds;
  State state;
  bool present = false;
  copyBearer("Bearer --------", creds.bearer, &present);
  creds.hasBearer = present;
  Request req = baseReq(creds);
  req.nowMs = 0xFFFFF000u;
  for (int i = 0; i < 7; ++i) EXPECT_EQ(decide(req, CODE, state), Decision::Unauthorized);
  EXPECT_EQ(decide(req, CODE, state), Decision::Locked);
  EXPECT_EQ(state.failures, 8);

  creds = {};
  copyBearer("Bearer H7K2M9PQ", creds.bearer, &present);
  creds.hasBearer = present;
  req.credentials = &creds;
  req.nowMs = 0xFFFFF000u + 1000u;
  EXPECT_EQ(decide(req, CODE, state), Decision::Locked);

  req.nowMs = state.lockoutUntilMs;
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);
  EXPECT_EQ(state.failures, 0);
}

TEST(WebAccess, CodeCompareRejectsShortAndLongInputs) {
  EXPECT_TRUE(codeEquals("H7K2M9PQ", "H7K2M9PQ"));
  EXPECT_FALSE(codeEquals("H7K2M9P", "H7K2M9PQ"));
  EXPECT_FALSE(codeEquals("H7K2M9PQQ", "H7K2M9PQ"));
  EXPECT_FALSE(codeEquals("H7K2M9PR", "H7K2M9PQ"));
}

TEST(WebAccess, AssetPrefixIsNotAPublicBypass) {
  Credentials creds;
  State state;
  Request req = baseReq(creds);
  req.path = "/js/../Books/Title.epub";
  EXPECT_EQ(decide(req, CODE, state), Decision::Unauthorized);
  req.path = "/js/%2e%2e/Books/Title.epub";
  EXPECT_EQ(decide(req, CODE, state), Decision::Unauthorized);
  req.path = "/assets/../Books/Title.epub";
  EXPECT_EQ(decide(req, CODE, state), Decision::Unauthorized);
  req.path = "/js/jszip.min.js";
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);
}

TEST(WebAccess, ShellQueryCountsTowardLockout) {
  Credentials creds;
  State state;
  bool present = false;
  copyQueryCode("k=BADCODE1", creds.queryKey, &present);
  creds.hasQuery = present;
  Request req = baseReq(creds);
  req.method = "GET";
  req.path = "/";
  for (int i = 0; i < 7; ++i) EXPECT_EQ(decide(req, CODE, state), Decision::Allow);
  EXPECT_EQ(decide(req, CODE, state), Decision::Locked);
  EXPECT_EQ(state.failures, 8);

  creds = {};
  copyQueryCode("k=H7K2M9PQ", creds.queryKey, &present);
  creds.hasQuery = present;
  req.credentials = &creds;
  EXPECT_EQ(decide(req, CODE, state), Decision::Locked);

  creds = {};
  req.credentials = &creds;
  EXPECT_EQ(decide(req, CODE, state), Decision::Allow);
}

TEST(WebAccess, QueryPercentAndCookieParse) {
  char out[9];
  bool present = false;
  copyQueryCode("/?k=H7K2M9PQ", out, &present);
  EXPECT_TRUE(present);
  EXPECT_STREQ(out, "H7K2M9PQ");
  copyQueryCode("a=1&k=%48%37K2M9PQ", out, &present);
  EXPECT_TRUE(present);
  EXPECT_STREQ(out, "H7K2M9PQ");
  copyQueryCode("k=SHORT", out, &present);
  EXPECT_TRUE(present);
  EXPECT_STREQ(out, "");
  copyCookieCode("cp=H7K2M9PQ; theme=1", out, &present);
  EXPECT_TRUE(present);
  EXPECT_STREQ(out, "H7K2M9PQ");
}
