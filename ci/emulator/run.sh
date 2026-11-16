#!/bin/bash -eu
# Runs a command next to an emulated pico-keys firmware (Linux, inside ci/emulator/Dockerfile).
#   ci/emulator/run.sh <emulator binary> <command...>
# Brings up swtpm (the emulator keeps its OTP secrets in a TPM), pcscd with the vsmartcard
# virtual reader, the emulator with a fresh flash, and sshd on 127.0.0.1:2222 for agent tests.
EMU=$1; shift
mkdir -p /tmp/tpm
swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --tpmstate dir=/tmp/tpm --flags not-need-init,startup-clear -d
/usr/sbin/pcscd --disable-polkit
sleep 1
cd /tmp && rm -f memory.flash
PICO_NOVUS_TPM_PIN=123456 "$EMU" > /tmp/emulator.log 2>&1 &
for _ in $(seq 1 20); do opensc-tool -an >/dev/null 2>&1 && break; sleep 0.5; done
opensc-tool -an
mkdir -p ~/.gnupg && echo disable-ccid > ~/.gnupg/scdaemon.conf && chmod 700 ~/.gnupg
mkdir -p /run/sshd ~/.ssh && chmod 700 ~/.ssh
ssh-keygen -q -A
/usr/sbin/sshd -p 2222 -o ListenAddress=127.0.0.1 -o PasswordAuthentication=no -o PermitRootLogin=prohibit-password
cd /src
"$@"
