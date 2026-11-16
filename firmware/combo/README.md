# Pico FIDO + Pico OpenPGP in one firmware

Upstream ships FIDO (with OATH/OTP) and OpenPGP (with PIV) as separate firmwares, so a key
has either passkeys or an OpenPGP card. `make-combo.sh` builds one source tree with both, so the
same key can hold passkeys and an `ssh-rsa` key on the OpenPGP card.

```sh
./make-combo.sh <pico-fido checkout> <pico-openpgp checkout> <out dir>   # Linux (GNU sed)
cd <out dir> && idf.py -B build-esp -DENABLE_EDDSA=1 build                # ESP32-S3
```

What it changes:

- base: the pico-fido tree (and its pico-keys-sdk); the OpenPGP and PIV sources are added
- one file table: FIDO's entries spliced into OpenPGP's (`merge_files.py`; fails on a duplicate
  file id). Flash data is keyed by file id, so an existing FIDO key keeps its passkeys and PIN.
  `EF_VAULT_KEY` is shared on purpose (the vault root has per-app slots).
- one management applet (FIDO's); PIV's `cmd_version` renamed; product id stays Pico FIDO
- CCID and libcvc on; the build number pinned to the pico-fido checkout's

Checked against pico-fido 99337e1 + pico-openpgp 9b23276:

- emulator: the app's OpenPGP/SSH live tests (`ci/emulator/run.sh`), including ssh logins
  through the built-in agent with RSA, P-256 and Ed25519
- emulator: pico-fido's upstream pytest suite: 318 passed, 3 skipped, same as plain pico-fido
- emulator: upgrade (`test-upgrade.sh`): a passkey and PIN made on plain pico-fido still work
  after booting the combined firmware on the same flash, and a fresh OpenPGP card appears
- ESP32-S3: 752 KB app (1 MB slot), +3.6 KB static RAM over FIDO alone

pico-fido 8.2 on ESP32-S3 also needs `CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384` in `sdkconfig`;
without it, it boot-loops with a stack overflow in the main task.
