# Flashing this fork on an Xteink X4 Pro

These steps are for a Mac flashing the `x4pro` build of branch `cursor/x4pro-pl-secure`. That image is the security integration (access code, WPA2 hotspot, path denylist, plugin URL limits, `v2.` password obfuscation, HTTPS verification, and the ZIP size check) plus the Polish UI: the Polish translation, the `pol` hyphenation tag, Polish keyboard letters, and keeping a short Polish word with the next word. Firmware signing is described in `docs/firmware-signing.md` and is not enforced.

The environment name in `platformio.ini` is `x4pro` (ESP32-S3, 16 MB flash, 8 MB PSRAM). Do not use `pio run --target upload` with no `-e`: the default environment is the ESP32-C3 X3/X4 image. The file-transfer screen shows two secrets: the hotspot password and the web access code. The UI language can be set to Polski.

Build the image from this branch:

```bash
pio run -e x4pro
```

The app image is `.pio/build/x4pro/firmware.bin`. The same build also writes:

| File | Offset in the combined image |
| --- | --- |
| `bootloader.bin` | `0x0000` |
| `partitions.bin` | `0x8000` |
| `boot_app0.bin` | `0xe000` |
| `firmware.bin` | `0x10000` |
| `firmware.factory.bin` | combined image of the four rows above |

`firmware.factory.bin` is produced by the X4 Pro build ("Successfully created combined binary image"). The README's esptool command writes `firmware.bin` at `0x10000`. The web flasher's "Custom .bin" step says to upload "the firmware file" and does not say whether that file is `firmware.bin` or `firmware.factory.bin`. Use `firmware.bin` with the esptool command below. For the web flasher, start with `firmware.bin`; this session did not click through the site to see which file it accepts.

## Before you flash

1. Wake the reader and connect a USB-C cable that carries data.
2. Devices bought from xteink.com are not USB-locked. Some third-party units are. If the browser's serial device picker does not list the reader, try another port or browser before using the unlocker at https://crosspointreader.com/#unlock-tool.
3. The unlocker warning in the README applies here: the only officially supported firmwares in that tool are CrossPoint and CrossInk. Flashing other firmware on a USB-locked device can leave it stuck, with USB flashing locked again and no way back if that firmware cannot OTA.

This repository does not document a download-mode or BOOT-button sequence for the X4 Pro. `freeink-sdk/docs/xteink-x4pro-support.md` says the Left button is GPIO0, a boot-strap pin, and that it works as a button as long as it is not held during reset. The README's flash steps are: wake/unlock the device and connect USB-C. USB is the ESP32-S3 native USB (GPIO19 D−, GPIO20 D+). `platformio.ini` says USB Serial/JTAG is the normal USB personality so PlatformIO can monitor and flash the reader.

## Back up the current firmware

The only full-chip read in this repo is in `docs/fix-bricked-xteink.md`. It uses `--chip esp32c3` and length `0x1000000`. That guide, and `docs/images/spiflash/crosspoint_spiflash_backup.tar.xz`, are for the Xteink X3/X4 (ESP32-C3) only. Do not write that image, and do not run that `--chip esp32c3` command, on an X4 Pro.

The X4 Pro board in `platformio.ini` is `esp32-s3-devkitc1-n16r8` with `board_upload.flash_size = 16MB`. A 16 MB read with the chip set to `esp32s3` is the same length as the C3 example, with the chip changed. It is not a command this repo writes for the X4 Pro. Find the Mac port first (next section), then:

```bash
esptool.py --chip esp32s3 --port /dev/cu.usbmodemXXXX --baud 921600 read_flash 0x0 0x1000000 x4pro-backup.bin
```

Keep that file. Restoring it would be `write_flash 0x0 x4pro-backup.bin` with the same chip and port. This session did not run either command on hardware.

The documented way to return to official CrossPoint is the web flasher, below, not this backup.

## Web flasher

The README recommends https://crosspointreader.com/#flash-tools and lists Xteink X4Pro as a device choice. Custom binaries are supported.

1. Wake the reader and connect USB-C.
2. Open https://crosspointreader.com/#flash-tools.
3. Select **Xteink X4Pro**.
4. Click **Custom .bin** and upload `firmware.bin` from `.pio/build/x4pro/`.
5. Choose the serial device the browser shows.

To roll back, use the same page, select **Xteink X4Pro**, and flash an official CrossPoint release instead of the custom file. The README states that revert path directly.

## esptool on a Mac

Install esptool the way the README shows:

```bash
pip install esptool
```

Find the port. The README's macOS step is:

```bash
log stream --predicate 'subsystem == "com.apple.iokit"' --info
```

Connect the reader while that is running and note the new device. The README's flash example uses `/dev/ttyACM0`, which is a Linux name. On a Mac the node is usually `/dev/cu.usbmodem…`. This session did not have an X4 Pro attached, so the exact node was not observed. Put that node in `--port`.

Flash the app image at the offset in `platformio.ini` (`board_upload.offset_address = 0x10000`) and the X4 Pro line in the README:

```bash
esptool.py --chip esp32s3 --port /dev/cu.usbmodemXXXX --baud 921600 write_flash 0x10000 .pio/build/x4pro/firmware.bin
```

The command name may be `esptool` instead of `esptool.py` depending on how pip installed it. The README uses `esptool.py`.

Flash mode: `docs/contributing/touch-and-ui.md` says the X4-family standalone environments need `dio`. The X4 Pro env sets `board_build.arduino.memory_type = dio_opi`. A wrong flash-mode header boots into `partition 0 invalid magic number 0xffff` even when esptool reports a verified write. M5Paper is `qio`; do not reuse a qio image or flash-mode flag on this reader.

## PlatformIO

From a checkout of this branch, with the reader connected:

```bash
pio run -e x4pro -t upload
```

That is the comment on `[env:x4pro]` in `platformio.ini`. The development quick start's `pio run --target upload` builds and flashes the default ESP32-C3 environment. Do not use it for an X4 Pro.

The `x4pro` env enables serial logging and `CROSSPOINT_WAIT_FOR_USB_SERIAL`. In `src/main.cpp` that flag is a 250 ms delay so early logs are reliable. It does not wait for a host to open the port. `pio device monitor -e x4pro` shows those logs.

## SD card

`USER_GUIDE.md` says firmware can also be updated by placing `firmware.bin` on the SD card, and that this path is not available on the BOOX Picco. It does not mention the X4 Pro separately. This session did not confirm that SD-card update on an X4 Pro.

## What this session could not verify

- No X4 Pro was connected. None of these commands were run on hardware.
- No download-mode button sequence is documented for the X4 Pro. Do not hold the Left button (GPIO0) during reset.
- The web flasher page was not exercised, so which of `firmware.bin` and `firmware.factory.bin` it accepts was not confirmed.
- The Mac serial-port node was not observed. The `/dev/cu.usbmodemXXXX` placeholder is not from the README.
- The 16 MB `read_flash` backup above is the C3 guide's length with `--chip esp32s3`. It is not a documented X4 Pro procedure.
- The SPI-clip recovery guide and the bundled `crosspoint_spiflash_backup.tar.xz` are for the ESP32-C3 X3/X4 only.
