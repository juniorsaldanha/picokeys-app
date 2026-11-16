# Pico Key Manager

A free, GPL-3.0 desktop manager for [pico-keys](https://www.picokeys.com/) devices
(Pico FIDO first; Pico HSM and Pico OpenPGP planned. Pico-specific features talk to the pico-keys-sdk rescue applet and YKOATH over CCID (PC/SC)). Runs on macOS, Linux, and Windows.

Stack: **Tauri 2** (native shell, Rust backend) + **Dioxus 0.7** (Rust → WASM UI) +
**[rust-ui](https://rust-ui.com)** components + **Tailwind v4**. The webview renders on the GPU.

## Features (FIDO)

- Hot-plug device detection
- Device overview: firmware, FIDO versions, algorithms, options, extensions, AAGUID
- PIN: set, change, retries left
- Passkeys: list, search, delete (unlocked with PIN)
- Identify key (wink)

## Features (Pico)

- Device: chip, firmware, serial, flash usage, secure boot status
- Configuration: USB VID/PID and name, interfaces, LED driver/order/GPIO/brightness, button timeout
- FIDO factory reset
- Authenticator (OATH): TOTP/HOTP codes, add via otpauth:// link or setup key, touch-required accounts
- OTP slots (short/long touch): HMAC-SHA1 challenge-response, Yubico OTP, static password; erase, swap
- Firmware: install official Pico FIDO / HSM / OpenPGP releases from GitHub; ESP32-S2/S3 via the ROM bootloader (espflash), RP2040/RP2350 via the UF2 drive
- SSH & Git: create ecdsa-sk/ed25519-sk keys (resident, verify-required, labels), set up git SSH commit/tag signing with allowed_signers, add ~/.ssh/config hosts, test logins

## Layout

```
types/      shared serde types (backend <-> UI)
src-tauri/  Tauri app; src/fido.rs = CTAP2/HID via ctap-hid-fido2
ui/         Dioxus web UI; src/components/ui = rust-ui components
```

## Develop

```sh
rustup target add wasm32-unknown-unknown
cargo install --locked tauri-cli dioxus-cli ui-cli
cargo tauri dev        # runs `dx serve` for the UI + the native app
cargo tauri build      # release bundles (.dmg/.app, .msi/.exe, .deb/.AppImage)
```

Tests (`--include-ignored` also probes a connected key):

```sh
cargo test -p picokeys-app -- --include-ignored --nocapture
```

### Linux

HID access needs a udev rule, e.g. `/etc/udev/rules.d/70-pico-key.rules`:

```
KERNEL=="hidraw*", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="10fe", TAG+="uaccess"
```

Build deps: `libwebkit2gtk-4.1-dev libudev-dev` (see Tauri prerequisites).

## License

GPL-3.0-or-later. Not affiliated with the official PicoKey App.
