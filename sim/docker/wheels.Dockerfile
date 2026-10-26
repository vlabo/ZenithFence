# syntax=docker/dockerfile:1
#
# Builds the zfsim wheels for Windows, Linux and macOS (x86_64) on one Linux
# machine, so a wheel build needs nothing but Docker. Used by `just sim-wheels`
# and by CI on every GitHub release (.github/workflows/zfsim-wheels.yml):
#
#   docker build -f sim/docker/wheels.Dockerfile --build-arg VERSION=2.0.2 \
#       --target wheels --output type=local,dest=sim/dist .
#
# The context is the repository root (see wheels.Dockerfile.dockerignore).
# Each wheel is an abi3 build (any CPython >= 3.9) of the same sources:
#   * Linux:   maturin + zig, against glibc 2.17 (manylinux2014)
#   * Windows: maturin + cargo-xwin, which fetches the MSVC CRT and Windows SDK
#              (by doing so you accept Microsoft's license for them)
#   * macOS:   maturin + zig, which links against its own macOS SDK stubs
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
RUN rustup target add x86_64-unknown-linux-gnu x86_64-pc-windows-msvc x86_64-apple-darwin

WORKDIR /src
COPY driver/src driver/src
COPY kext_interface/version.txt kext_interface/version.txt
COPY protocol protocol
COPY mock mock
COPY sim sim

# The wheel version (PEP 440), e.g. 2.0.2 from the release tag v2.0.2.
ARG VERSION=0.0.0
RUN sed -i "0,/^version = \".*\"/s//version = \"${VERSION}\"/" sim/pyproject.toml \
 && grep -q "^version = \"${VERSION}\"" sim/pyproject.toml

# Cache mounts keep crates, build outputs and the downloaded Windows SDK
# between local builds; CI starts cold.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/sim/target \
    --mount=type=cache,target=/root/.cache \
    set -eux; \
    cd sim; \
    build="maturin build --release --out /dist --interpreter python3.9"; \
    $build --target x86_64-unknown-linux-gnu --zig --compatibility manylinux2014; \
    $build --target x86_64-pc-windows-msvc; \
    $build --target x86_64-apple-darwin --zig; \
    ls -l /dist

# `--target wheels --output type=local,dest=...` exports just the wheel files.
FROM scratch AS wheels
COPY --from=build /dist/ /
