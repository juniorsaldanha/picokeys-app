#!/bin/bash -u
# Upgrade check on the emulator: plain Pico FIDO makes a passkey with a PIN, then the combined
# firmware boots on the same flash; the passkey, PIN and a fresh OpenPGP card must all be there.
#   docker run --rm -v <pico-fido>/build-emu:/fido:ro -v <combo>/build-emu:/combo:ro \
#     -v <pico-fido>/tests:/tests:ro -v $PWD:/s:ro pkm-emulator /s/test-upgrade.sh
apt-get -qq update >/dev/null; apt-get -qq install -y python3-pip >/dev/null 2>&1
pip3 install -q --break-system-packages fido2==2.2.1 >/dev/null 2>&1
D=$(python3 -c 'import fido2,os;print(os.path.dirname(fido2.__file__))'); cp -R /tests/docker/fido2/* $D/hid/
mkdir -p /tmp/tpm; swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --tpmstate dir=/tmp/tpm --flags not-need-init,startup-clear -d
/usr/sbin/pcscd --disable-polkit; sleep 1; mkdir -p /w && cd /w
PICO_NOVUS_TPM_PIN=123456 /fido/pico_fido > fido.log 2>&1 & E=$!; sleep 3
python3 /s/test-upgrade.py before; opensc-tool -s 00a4040006d27600012401 2>&1 | tail -1
kill $E; wait $E 2>/dev/null; ls -la memory.flash; sleep 1
echo "--- combined firmware on the same flash"
PICO_NOVUS_TPM_PIN=123456 /combo/pico_fido > combo.log 2>&1 & sleep 3
python3 /s/test-upgrade.py after
opensc-tool -s 00a4040006d27600012401 2>&1 | grep -i received
mkdir -p ~/.gnupg; chmod 700 ~/.gnupg; echo disable-ccid > ~/.gnupg/scdaemon.conf; gpg --card-status 2>&1 | grep -E 'Version|Serial|PIN retry|Signature key|Authentication key'
