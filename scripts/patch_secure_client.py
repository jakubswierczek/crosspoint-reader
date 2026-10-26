"""
PlatformIO post-script: turn on TLS peer verification in the FreeInk SDK copy
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

SECURE_OLD_FILE_SCOPE = """#endif

namespace freeink {
"""
SECURE_NEW_FILE_SCOPE = """#endif

#if defined(FREEINK_NET_WOLFSSL)
// C linkage: wolfSSL's verify callback is an extern "C" function pointer.
// A cold boot has no wall clock. Signature and hostname are still checked.
// notBefore/notAfter are ignored only until the clock is in 2025 or later.
extern "C" int crosspointVerifyPeer(int preverify, WOLFSSL_X509_STORE_CTX* store) {
  if (preverify == 1) return 1;
  if (store != nullptr && time(nullptr) < 1735689600 &&
      (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E)) {
    return 1;
  }
  return 0;
}
#endif

namespace freeink {
"""

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
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, crosspointVerifyPeer);
    // Loading the roots also checks their dates. Skip that only while the
    // clock is still before 2025; a set clock still rejects an expired root.
    const word32 loadFlags = time(nullptr) < 1735689600 ? WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY : 0;
    const int loaded = wolfSSL_CTX_load_verify_buffer_ex(
        ctx, reinterpret_cast<const unsigned char*>(_rootCA), static_cast<long>(strlen(_rootCA)),
        WOLFSSL_FILETYPE_PEM, 0, loadFlags);
    if (loaded != WOLFSSL_SUCCESS) {{
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

OPDS_OLD_DECL = """bool opdsImplicitAuthenticate(const std::string& authenticateUrl, const std::string& username,
                              const std::string& password, std::string& outToken) {
"""
OPDS_NEW_DECL = """extern "C" const char* crosspoint_tls_ca_pem();

bool opdsImplicitAuthenticate(const std::string& authenticateUrl, const std::string& username,
                              const std::string& password, std::string& outToken) {
"""
OPDS_OLD = """    http.setTimeout(AUTH_TIMEOUT_MS);
    http.setInsecure();
"""
OPDS_NEW = """    http.setTimeout(AUTH_TIMEOUT_MS);
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
        (SECURE_OLD_FILE_SCOPE, SECURE_NEW_FILE_SCOPE),
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
    for old, new in ((OPDS_OLD_DECL, OPDS_NEW_DECL), (OPDS_OLD, OPDS_NEW)):
        if old not in text:
            raise RuntimeError("OpdsImplicitAuth.cpp no longer matches the reviewed patch")
        text = text.replace(old, new, 1)
    return text


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
    print(f"Patched TLS verification: {path.name}")


def patch_selected(env) -> None:
    # The SDK-only pass has no application libraries yet.
    if env.get("ARDUINO_LIB_COMPILE_FLAG") == "Build":
        return
    selected = {}
    for builder in env.GetLibBuilders():
        if getattr(builder, "is_dependent", False):
            selected[builder.name] = builder
    secure = selected.get("SecureNet")
    opds = selected.get("Opds")
    if secure is None or opds is None:
        raise RuntimeError("TLS verification patch requires SecureNet and Opds")
    apply_one(Path(secure.path) / "src" / "SecureClient.cpp", SECURE_UPSTREAM, patch_secure)
    apply_one(Path(opds.path) / "src" / "OpdsImplicitAuth.cpp", OPDS_UPSTREAM, patch_opds)


if "Import" in globals():
    Import("env")  # noqa: F821 -- supplied by SCons
    patch_selected(env)  # noqa: F821
