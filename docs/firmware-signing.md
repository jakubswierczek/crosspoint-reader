# Firmware image signing (design, not implemented)

CrossPoint checks an OTA download is an ESP image for this chip, and that an
embedded board tag (when present) names this board. `esp_ota_end()` then checks
the image checksum. Nothing checks that the image was produced by the project.
A file that passes those checks can be installed from a redirected download.

This document is a proposal. The firmware in this branch still accepts the
same unsigned images as upstream. Rejecting them here would brick updates for
every reader that does not already hold a matching key.

## Why this fork does not enforce a signature

Secure Boot on the ESP32-S3 stores a hash of the signing key in eFuses. Those
bits are one-time programmable, and the Xteink bootloader is not the project's
to replace. Burning a key the project does not control, or that a fork cannot
rotate, would make official and fork images uninstallable. There is no shared
public key in the repository today.

Signing therefore has to live in the application, before `esp_ota_begin()`
commits to an image, and the first build that enforces it has to be flashed
over USB. An OTA update cannot install the first trusted verifier: the running
image is the one that decides what to trust.

## Proposed check

Use a detached Ed25519 signature over the raw application image (the bytes
written to the OTA partition, not the esptool wrapper).

- One public key is compiled into the firmware. It is not secret. A fork that
  publishes its own builds uses its own key and does not accept upstream
  signatures, and upstream does not accept the fork's.
- The release process signs the image on an offline machine. The private key
  is not on a CI runner and is not in the repository. A second person can
  confirm the digest out of band before the signature is published.
- The OTA client downloads the image and the signature (a 64-byte file next to
  the bin is enough). It verifies before `esp_ota_begin()`. A bad signature
  aborts with no partition write.
- The same check applies to a file copied onto the SD card and installed from
  the device. USB flashing with esptool stays the recovery path and does not
  consult this verifier.
- Images without a signature keep installing until a release explicitly turns
  enforcement on. That release is published with a signature, flashed once
  over USB to devices that will enforce it, and only then refuses unsigned
  downloads. Older firmware keeps accepting unsigned images, so a reader that
  never takes the USB step is not stranded.

## What this does not do

It does not prove the device is running the image the user thinks it is after
someone with USB access rewrites flash. It does not encrypt the image. It does
not replace TLS for the download: a signature still has to be checked when the
bytes arrive, including from a mirror. Certificate verification of the
download connection is a separate change.

Ed25519 verify is a small, fixed-size operation (a 32-byte key and a 64-byte
signature) and does not need the multi-kilobyte bignum temporaries that RSA
verification allocates. That fits the ESP32-C3 internal RAM budget. The public
key and the verify code are flash-resident.

## Rollout

1. Publish signed images without enforcing, so the signature file exists and
   clients can be tested against it.
2. Ship a USB-flashed build that enforces the compiled-in key.
3. Keep the private key offline. Rotating it means a new USB-flashed build;
   OTA cannot introduce a key the running image does not already trust.
