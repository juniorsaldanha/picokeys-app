ESP32-S3 flasher stub (text and data segments) used to start the stub on keys with secure boot
on, where the ROM can't jump to it (see `firmware::start_stub_secure_s3`). Byte-identical to
espflash 4.7.0's `resources/stubs/esp32s3.toml` and esptool 4.13's
`targets/stub_flasher/2/esp32s3.json` (entry 0x403795a8, text at 0x40378000, data at 0x3fcb2dc4).

From esp-flasher-stub (https://github.com/espressif/esp-flasher-stub), MIT OR Apache-2.0.
