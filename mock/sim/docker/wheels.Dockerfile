# syntax=docker/dockerfile:1
#
# Builds the zfsim wheels for Windows, Linux and macOS, each for x86_64 and
# arm64 (aarch64), on one Linux machine, so a wheel build needs nothing but
# Docker. Used by `just sim-wheels` and by CI on every GitHub release
# (.github/workflows/zfsim-wheels.yml):
#
#   docker build -f mock/sim/docker/wheels.Dockerfile --build-arg VERSION=2.0.2 \
#       --target wheels --output type=local,dest=mock/sim/dist .
#
# The context is the repository root (see wheels.Dockerfile.dockerignore).
# Each wheel is an abi3 build (any CPython >= 3.9) of the same sources:
#   * Linux:   maturin + zig, against glibc 2.17 (manylinux2014)
#   * Windows: maturin + cargo-xwin, which fetches the MSVC CRT and Windows SDK
#              (by doing so you accept Microsoft's license for them)
#   * macOS:   maturin + zig, which links against its own macOS SDK stubs
#              (arm64: macOS 11+, the first release on Apple silicon)
# `--interpreter python3.9` keeps each build to the one abi3 wheel: without it a
# cross build also tries version-specific wheels for every interpreter maturin
# knows that has no abi3 (PyPy, free-threaded 3.13t), and those fail.

FROM rust:1-bookworm AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv clang lld llvm \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/tools \
 && /opt/tools/bin/pip install --no-cache-dir "maturin==1.8.3" "ziglang==0.13.0" "cargo-xwin==0.18.4"
ENV PATH=/opt/tools/bin:$PATH
RUN rustup target add \
        x86_64-unknown-linux-gnu x86_64-pc-windows-msvc x86_64-apple-darwin \
        aarch64-unknown-linux-gnu aarch64-pc-windows-msvc aarch64-apple-darwin

# The MSVC CRT and Windows SDK, fetched once into a layer of their own (before
# any sources, so a code change keeps it; CI keeps it in the GitHub Actions
# cache). The download from Microsoft is slow (minutes) and its connection
# sometimes drops, so it is retried; a retry skips the files already fetched.
# The pip cargo-xwin is the version maturin 1.8.3 bundles (0.18.4), so maturin
# finds the DONE mark in XWIN_CACHE_DIR and downloads nothing. Both
# architectures, for the x86_64 and arm64 wheels.
ENV XWIN_CACHE_DIR=/opt/xwin XWIN_ARCH=x86_64,aarch64
RUN set -eux; \
    cargo new --lib --vcs none /tmp/xwin-fetch; \
    cd /tmp/xwin-fetch; \
    for attempt in 1 2 3 4 5; do \
        cargo xwin check --target x86_64-pc-windows-msvc \
            && cargo xwin check --target aarch64-pc-windows-msvc \
            && break; \
        [ "$attempt" -lt 5 ]; \
        sleep 30; \
    done; \
    cd /; \
    rm -rf /tmp/xwin-fetch; \
    cat /opt/xwin/xwin/DONE

WORKDIR /src
COPY driver/src driver/src
COPY kext_interface/version.txt kext_interface/version.txt
COPY protocol protocol
COPY mock mock

# The wheel version (PEP 440), e.g. 2.0.2 from the release tag v2.0.2.
ARG VERSION=0.0.0
RUN sed -i "0,/^version = \".*\"/s//version = \"${VERSION}\"/" mock/sim/pyproject.toml \
 && grep -q "^version = \"${VERSION}\"" mock/sim/pyproject.toml

# Cache mounts keep crates and build outputs between local builds; CI starts
# them cold.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/mock/target \
    --mount=type=cache,target=/root/.cache \
    set -eux; \
    cd mock/sim; \
    build="maturin build --release --out /dist --interpreter python3.9"; \
    for arch in x86_64 aarch64; do \
        $build --target $arch-unknown-linux-gnu --zig --compatibility manylinux2014; \
        $build --target $arch-pc-windows-msvc; \
        $build --target $arch-apple-darwin --zig; \
    done; \
    ls -l /dist

# `--target wheels --output type=local,dest=...` exports just the wheel files.
FROM scratch AS wheels
COPY --from=build /dist/ /
