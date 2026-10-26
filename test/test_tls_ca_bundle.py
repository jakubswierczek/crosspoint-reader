#!/usr/bin/env python3
"""Check the built-in CA bundle is the six reviewed public roots."""

import subprocess
import sys
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1] / "src" / "network" / "tls_ca_bundle.inc"

# Subject CN and SHA-256 fingerprint, in bundle order.
EXPECTED = (
    ("ISRG Root X1", "96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6"),
    ("ISRG Root X2", "69:72:9B:8E:15:A8:6E:FC:17:7A:57:AF:B7:17:1D:FC:64:AD:D2:8C:2F:CA:8C:F1:50:7E:34:45:3C:CB:14:70"),
    ("DigiCert Global Root G2", "CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F"),
    ("Amazon Root CA 1", "8E:CD:E6:88:4F:3D:87:B1:12:5B:A3:1A:C3:FC:B1:3D:70:16:DE:7F:57:CC:90:4F:E1:CB:97:C6:AE:98:19:6E"),
    ("GTS Root R4", "34:9D:FA:40:58:C5:E2:63:12:3B:39:8A:E7:95:57:3C:4E:13:13:C8:3F:E6:8F:93:55:6C:D5:E8:03:1B:3C:7D"),
    (
        "USERTrust RSA Certification Authority",
        "E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2",
    ),
)


def pem_text() -> str:
    raw = BUNDLE.read_text()
    start = raw.index('R"bundle(') + len('R"bundle(')
    end = raw.rindex(')bundle"')
    return raw[start:end]


def blocks(text):
    found = []
    cursor = 0
    begin = "-----BEGIN CERTIFICATE-----"
    ending = "-----END CERTIFICATE-----"
    while True:
        at = text.find(begin, cursor)
        if at < 0:
            break
        stop = text.find(ending, at)
        if stop < 0:
            raise SystemExit("certificate block is not closed")
        stop += len(ending)
        found.append(text[at:stop] + "\n")
        cursor = stop
    return found


def main() -> int:
    certs = blocks(pem_text())
    if len(certs) != len(EXPECTED):
        print(f"expected {len(EXPECTED)} certificates, found {len(certs)}", file=sys.stderr)
        return 1
    for pem, (name, fingerprint) in zip(certs, EXPECTED):
        info = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-fingerprint", "-sha256"],
            input=pem,
            text=True,
            capture_output=True,
            check=True,
        )
        lines = info.stdout.splitlines()
        subject = next(line for line in lines if line.startswith("subject=")).split("=", 1)[1]
        issuer = next(line for line in lines if line.startswith("issuer=")).split("=", 1)[1]
        digest = next(line for line in lines if "Fingerprint=" in line).split("=", 1)[1]
        if name not in subject or subject != issuer:
            print(f"{name} is not a self-signed root:\n{info.stdout}", file=sys.stderr)
            return 1
        if digest != fingerprint:
            print(f"{name} fingerprint {digest} != {fingerprint}", file=sys.stderr)
            return 1
    print(f"{len(certs)} CA certificates match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
