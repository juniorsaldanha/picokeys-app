#!/bin/bash -eu
# Builds the source tree of one firmware with Pico FIDO (+OATH/OTP) and Pico OpenPGP (+PIV),
# from upstream checkouts: make-combo.sh <pico-fido> <pico-openpgp> <out dir>
# The FIDO tree (and its newer pico-keys-sdk) is the base; the OpenPGP/PIV applets are added.
# Clashes resolved: one management applet (FIDO's), PIV's cmd_version renamed, one product id
# (FIDO's, so the app and tools still see "Pico FIDO"), one merged file table (merge_files.py),
# and OpenPGP's runtime file ids moved out of FIDO's range.
FIDO=$(cd "$1" && pwd) PGP=$(cd "$2" && pwd) OUT=$3 HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
rsync -a --delete --exclude '/build*' --exclude '.git' "$FIDO"/ "$OUT"/
rsync -a "$PGP/src/openpgp" "$PGP/src/piv" "$OUT/src/"
rm "$OUT/src/openpgp/management.c" "$OUT/src/openpgp/management.h"
sed -i.bak 's/\bcmd_version\b/piv_cmd_version/' "$OUT/src/piv/cmd_version.c" "$OUT/src/piv/piv.h" "$OUT/src/openpgp/piv.c"
sed -i.bak '/^uint8_t PICO_\(PRODUCT\|VERSION_MAJOR\|VERSION_MINOR\) =/d' "$OUT/src/openpgp/defs.c"
# OpenPGP's key containers live at (0xD0..0xD5 << 8 | key), on top of FIDO's resident containers
# (0xD0..0xDD, 0xE0..0xE3): move them to 0xF0..0xF5, which nothing else in the tree generates
sed -i.bak -E 's/^(#define OPENPGP_KEY_[A-Z0-9_]+_PREFIX) 0xd([0-5])u/\1 0xf\2u/' "$OUT/src/openpgp/key_container.c"
[ "$(grep -c '_PREFIX 0xf[0-5]u' "$OUT/src/openpgp/key_container.c")" = 6 ] || { echo "OpenPGP prefixes not relocated" >&2; exit 1; }
python3 "$HERE/merge_files.py" "$OUT/src/fido" "$OUT/src/openpgp/files.c" > "$OUT/src/openpgp/files.c.new"
mv "$OUT/src/openpgp/files.c.new" "$OUT/src/openpgp/files.c"
rm "$OUT/src/fido/files.c"
# ESP-IDF builds the firmware as the src/fido component: export the OpenPGP/PIV headers too
sed -i.bak 's#INCLUDE_DIRS \.#INCLUDE_DIRS ../openpgp ../piv .#' "$OUT/src/fido/CMakeLists.txt"
find "$OUT/src" -name '*.bak' -delete
# OpenPGP headers that share a name with FIDO's are only found from their own directory,
# so put fido last in the include path and add the OpenPGP sources.
BUILD=$(git -c safe.directory='*' -C "$FIDO" rev-list --count HEAD)
python3 - "$OUT/CMakeLists.txt" "$PGP/CMakeLists.txt" "$BUILD" <<'PY'
import re, sys
p, pgp, build = sys.argv[1], open(sys.argv[2]).read(), sys.argv[3]
s = open(p).read()
# the tree has no .git, so pin the build number to the FIDO checkout's
s = s.replace('SET_BUILD_NUMBER("${CMAKE_CURRENT_LIST_DIR}")', f"add_compile_definitions(PICO_BUILD_NUMBER={build})", 1)
srcs = [l.strip() for l in re.search(r"list\(APPEND SOURCES\n(.*?)\n\)", pgp, re.S).group(1).splitlines()]
srcs = [x for x in srcs if not x.endswith(("/management.c",))]
s = s.replace("    ${CMAKE_CURRENT_LIST_DIR}/src/fido/files.c\n", "", 1)
s = s.replace("    ${CMAKE_CURRENT_LIST_DIR}/src/fido/defs.c\n)", "    ${CMAKE_CURRENT_LIST_DIR}/src/fido/defs.c\n    " + "\n    ".join(srcs) + "\n)", 1)
old = "set(INCLUDES ${INCLUDES}\n    ${CMAKE_CURRENT_LIST_DIR}/src/fido\n)"
assert old in s, "include block"
s = s.replace(old, "set(INCLUDES ${INCLUDES}\n    ${CMAKE_CURRENT_LIST_DIR}/src/openpgp\n    ${CMAKE_CURRENT_LIST_DIR}/src/piv\n    ${CMAKE_CURRENT_LIST_DIR}/src/fido\n)", 1)
# OpenPGP needs CCID (FIDO only turns it on with OATH/OTP) and libcvc (PIV attestation)
s = s.replace("include(pico-keys-sdk/picokeys_sdk_import.cmake)", "set(USB_ITF_CCID 1)\nset(USB_ITF_WCID 1)\nset(ENABLE_LIBCVC 1)\ninclude(pico-keys-sdk/picokeys_sdk_import.cmake)", 1)
# as upstream pico-openpgp: the Gnuk-style admin-less PIN mode is on for non-ESP builds only
s = s.replace("include(pico-keys-sdk/picokeys_sdk_import.cmake)", "include(pico-keys-sdk/picokeys_sdk_import.cmake)\nif(NOT ESP_PLATFORM)\n    add_compile_definitions(ENABLE_ADMINLESS_MODE=1)\nendif()", 1)
open(p, "w").write(s)
PY
echo "combo tree in $OUT"
