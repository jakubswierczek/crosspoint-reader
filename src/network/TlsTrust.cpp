#include <CrossPointSettings.h>
#include <SecureHttpClient.h>
#include <TlsTrust.h>

namespace {
const char BUNDLE[] =
#include "tls_ca_bundle.inc"
    ;
}  // namespace

extern "C" const char* crosspoint_tls_ca_pem() {
  if (!SETTINGS.tlsVerify) return nullptr;
  return BUNDLE;
}

void applyTlsTrust(freeink::SecureHttpClient& http) {
  if (const char* pem = crosspoint_tls_ca_pem()) {
    http.setCACert(pem);
  } else {
    http.setInsecure();
  }
}
