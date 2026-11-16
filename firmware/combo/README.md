# Pico FIDO + Pico OpenPGP in one firmware

> **History:** the first combined build broke passkey listing on a real key. Both applets create
> files at runtime as `prefix << 8 | slot`, and OpenPGP's key containers (0xD0–0xD5) landed in
> FIDO's resident-credential range, so FIDO read PIV records as relying parties. The script now
> moves OpenPGP's prefixes to 0xF0–0xF5, and `merge_files.py` refuses any overlap.

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
  static file id, or on a runtime prefix both use). Flash data is keyed by file id.
  `EF_VAULT_KEY` is shared on purpose (the vault root has per-app slots).
- OpenPGP's runtime key-container prefixes moved from 0xD0–0xD5 to 0xF0–0xF5
- one management applet (FIDO's, which also lists OpenPGP/PIV); PIV's `cmd_version` renamed;
  product id stays Pico FIDO
- `sdk-fixes.patch` on pico-keys-sdk (found on a real ESP32-S3 key; the emulator doesn't run these
  paths):
  - flash journal recovery read the redo copy at a raw partition offset, which faults on ESP32
    (`LoadProhibited` at boot, so any damaged record became a boot loop); it now reads through
    `flash_read()`, and never runs while a commit is in flight
  - the journal sector goes below every pending page, not only below `last_base`, and a rescan
    publishes `last_base` once at the end instead of resetting it to the top first. OpenPGP and
    PIV rescan the whole flash on select; a commit landing mid-rescan put its journal in (erased)
    the lowest live data sector, which lost a sector of OpenPGP and FIDO records on a real key
  - a CTAPHID request that arrives while a CCID command runs (an RSA-4096 keygen takes minutes)
    is answered `CHANNEL_BUSY` instead of blocking the USB task in `card_exit()`, which also
    stopped the CCID time extensions so the host gave up
  - a CCID command sent while one is still running is answered slot-busy instead of being queued
    behind it (every later answer came one command late), and a late answer carries its own
    command's sequence number
- CCID and libcvc on; admin-less PIN mode on for non-ESP builds only (as upstream); the build
  number pinned to the pico-fido checkout's

Checked against pico-fido 99337e1 + pico-openpgp 9b23276 (emulator unless noted):

- `test-upgrade.sh`: a passkey + PIN made on plain pico-fido; boot the combined firmware on the
  same flash; select OpenPGP first (that's when its containers get written), list passkeys
  (exact RP list), make all three OpenPGP keys, make a second passkey, list again, re-read the
  OpenPGP keys. The first combined build fails it with the real key's error (invalid UTF-8 RP).
- pico-fido's suite: 318 passed, 3 skipped (same as plain pico-fido)
- pico-openpgp's suites: PIV 279 passed (same); OpenPGP 1121 passed, the same 9 vault failures
  as plain pico-openpgp, plus `test_management_applet_config`, which expects an OpenPGP-only
  capability list
- the app's OpenPGP/SSH live tests (`ci/emulator/run.sh`), with ssh logins through the agent
- ESP32-S3: 752 KB app (1 MB slot), +3.6 KB static RAM over FIDO alone

pico-fido 8.2 on ESP32-S3 also needs `CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384` in `sdkconfig`;
without it, it boot-loops with a stack overflow in the main task.
