#pragma once

// The code shown on File Transfer and Calibre screens. Stable across boots when
// NVS can store it; otherwise one code for this boot. Never logged.
const char* webAccessCode();

class WebServer;
// True when this request may create or replace a file. Uses a copy of the
// lockout counter so the later middleware response is what records a failure.
bool webRequestMayWrite(WebServer& server);
