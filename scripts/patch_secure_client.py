"""
PlatformIO pre-script: turn on TLS peer verification in the FreeInk SDK copy
this build compiles.

SecureClient only verifies a peer when VERIFY_PEER is set. setCACert() alone
leaves wolfSSL's default VERIFY_NONE. The script also points the OPDS implicit
login client at crosspoint_tls_ca_pem().

Both files are symlink:// dependencies, so the patch edits the submodule
working tree. It is idempotent and refuses any other content. Restore the
submodule with `git -C freeink-sdk checkout -- .` before committing; the
pinned SHA must not change.
"""

import hashlib
from pathlib import Path

Import("env")

PROJECT_DIR = Path(env.subst("$PROJECT_DIR"))
MARKER = "/* CrossPoint TLS peer verification */"

SECURE_UPSTREAM = "544d404e40b81e254a418118623c01a207897b72f7297fd2275b1fe44160dfd5"
OPDS_UPSTREAM = "8cb8db2777f4a804c00e11d4a17f7969fc6c9d93899bfa765b5681d3549502be"

SECURE_OLD_INCLUDES = """#if defined(FREEINK_NET_WOLFSSL)
#include <wolfssl/ssl.h>
#endif
"""
SECURE_NEW_INCLUDES = """#if defined(FREEINK_NET_WOLFSSL)
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <cstring>
#include <ctime>
#endif
"""

SECURE_OLD_CALLBACK_ANCHOR = "bool isWantIo(const int err) {"
SECURE_NEW_CALLBACK = """// A cold boot has no wall clock. Signature and hostname are still checked;
// notBefore/notAfter are ignored only until the clock is in 2025 or later.
int verifyPeer(int preverify, WOLFSSL_X509_STORE_CTX* store) {
  if (preverify == 1) return 1;
  const int err = wolfSSL_X509_STORE_CTX_get_error(store);
  if (time(nullptr) < 1735689600 && (err == ASN_BEFORE_DATE_E || err == ASN_AFTER_DATE_E)) return 1;
  return 0;
}

bool isWantIo(const int err) {"""

SECURE_OLD_LOAD = """  if (_insecure) {
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, nullptr);
  } else if (_rootCA) {
    wolfSSL_CTX_load_verify_buffer(ctx, reinterpret_cast<const unsigned char*>(_rootCA),
                                   strlen(_rootCA), WOLFSSL_FILETYPE_PEM);
  }
"""
SECURE_NEW_LOAD = f"""  {MARKER}
  if (_insecure) {{
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, nullptr);
  }} else if (_rootCA != nullptr && _rootCA[0] != '\\0') {{
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verifyPeer);
    int loaded = 0;
    const char* cursor = _rootCA;
    while (const char* begin = strstr(cursor, "-----BEGIN CERTIFICATE-----")) {{
      const char* end = strstr(begin, "-----END CERTIFICATE-----");
      if (end == nullptr) break;
      end += sizeof("-----END CERTIFICATE-----") - 1;
      while (*end == '\\r' || *end == '\\n') ++end;
      const long pemLen = static_cast<long>(end - begin);
      if (wolfSSL_CTX_load_verify_buffer(ctx, reinterpret_cast<const unsigned char*>(begin), pemLen,
                                         WOLFSSL_FILETYPE_PEM) == WOLFSSL_SUCCESS) {{
        ++loaded;
      }}
      cursor = end;
    }}
    if (loaded == 0) {{
      if (Serial) Serial.printf("[SecureClient] no CA loaded (%s)\\n", label);
      stop();
      return 0;
    }}
  }} else {{
    if (Serial) Serial.printf("[SecureClient] verification required, no CA (%s)\\n", label);
    stop();
    return 0;
  }}
"""

SECURE_OLD_SNI = "  wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, strlen(host));\n"
SECURE_NEW_SNI = """  wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host, strlen(host));
  if (!_insecure && wolfSSL_check_domain_name(ssl, host) != WOLFSSL_SUCCESS) {
    if (Serial) Serial.printf("[SecureClient] domain check failed (%s)\\n", label);
    stop();
    return 0;
  }
"""

OPDS_OLD = """    http.setTimeout(AUTH_TIMEOUT_MS);
    http.setInsecure();
"""
OPDS_NEW = """    http.setTimeout(AUTH_TIMEOUT_MS);
    extern "C" const char* crosspoint_tls_ca_pem();
    if (const char* pem = crosspoint_tls_ca_pem()) http.setCACert(pem);
    else http.setInsecure();
"""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch_secure(text: str) -> str:
    if MARKER in text:
        return text
    for old, new in (
        (SECURE_OLD_INCLUDES, SECURE_NEW_INCLUDES),
        (SECURE_OLD_CALLBACK_ANCHOR, SECURE_NEW_CALLBACK),
        (SECURE_OLD_LOAD, SECURE_NEW_LOAD),
        (SECURE_OLD_SNI, SECURE_NEW_SNI),
    ):
        if old not in text:
            raise RuntimeError("SecureClient.cpp no longer matches the reviewed patch")
        text = text.replace(old, new, 1)
    return text


def patch_opds(text: str) -> str:
    if "crosspoint_tls_ca_pem" in text:
        return text
    if OPDS_OLD not in text:
        raise RuntimeError("OpdsImplicitAuth.cpp no longer matches the reviewed patch")
    return text.replace(OPDS_OLD, OPDS_NEW, 1)


def apply_one(path: Path, upstream: str, transform) -> None:
    current = digest(path)
    text = path.read_text()
    if MARKER in text or "crosspoint_tls_ca_pem" in text:
        # Already patched. A content drift means the SDK moved under us.
        transformed = transform(text)
        if transformed != text:
            raise RuntimeError(f"{path.name} is partially patched")
        return
    if current != upstream:
        raise RuntimeError(
            f"{path.name} hash {current} is not the reviewed SDK copy {upstream}. "
            "Update the patch before building."
        )
    path.write_text(transform(text))
    print(f"Patched TLS verification: {path.relative_to(PROJECT_DIR)}")


def main() -> None:
    # Library install can land after this script on a cold tree. wolfSSL's
    # pre-script does the same: a missing libdeps directory is the SDK pass.
    libdeps = PROJECT_DIR / ".pio" / "libdeps"
    if not libdeps.is_dir():
        return
    secure_files = list(libdeps.glob("*/SecureNet/src/SecureClient.cpp"))
    opds_files = list(libdeps.glob("*/Opds/src/OpdsImplicitAuth.cpp"))
    if not secure_files or not opds_files:
        return
    for path in secure_files:
        apply_one(path, SECURE_UPSTREAM, patch_secure)
    for path in opds_files:
        apply_one(path, OPDS_UPSTREAM, patch_opds)


main()
