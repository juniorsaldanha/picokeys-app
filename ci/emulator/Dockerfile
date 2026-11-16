# Linux test bench: the app's backend tests against emulated pico-keys firmware
# (vsmartcard vpcd + pcscd), plus gpg/opensc/sshd to cross-check results.
FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake git pkg-config curl ca-certificates python3 \
      pcscd libpcsclite-dev libccid vsmartcard-vpcd opensc gnupg scdaemon \
      openssh-server openssh-client \
      libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libudev-dev libssl-dev \
      libpipewire-0.3-dev libclang-dev libgbm-dev libdrm-dev libegl-dev libwayland-dev libxcb1-dev libxcb-randr0-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
# pico-keys emulation on Linux keeps its OTP secrets in a (software) TPM
RUN apt-get update && apt-get install -y --no-install-recommends libtss2-dev tpm2-tools swtpm && rm -rf /var/lib/apt/lists/*
ENV PATH=/root/.cargo/bin:$PATH CARGO_TARGET_DIR=/target
WORKDIR /src
