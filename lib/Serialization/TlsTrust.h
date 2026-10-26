#pragma once

namespace freeink {
class SecureHttpClient;
}

// Built-in CA bundle when Settings → System → Verify HTTPS certificates is on.
// Null when that toggle is off; callers then skip verification.
extern "C" const char* crosspoint_tls_ca_pem();

void applyTlsTrust(freeink::SecureHttpClient& http);
