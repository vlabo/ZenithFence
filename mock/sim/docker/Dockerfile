# The real Linux agent (nexufend, built with -tags mockkext) attached to the
# mock driver served by mock/sim/scripts/serve.py, in one container so the agent can
# resolve serve.py's PID. Debugging only. Built by `just mock-docker`; the
# context is the ZenithFence repo root (see Dockerfile.dockerignore).

FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY driver/src driver/src
COPY kext_interface/version.txt kext_interface/version.txt
COPY protocol protocol
COPY mock mock
RUN cargo build --release --manifest-path mock/sim/Cargo.toml \
 && cp mock/target/release/lib_native.so /_native.so

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates procps iproute2 && rm -rf /var/lib/apt/lists/*
COPY mock/sim/python /opt/zfsim/python
COPY mock/sim/scripts /opt/zfsim/scripts
COPY --from=build /_native.so /opt/zfsim/python/zfsim/_native.so
COPY mock/sim/docker/agent/nexufend-agent-mock-kext /opt/nexufend/nexufend-agent
COPY mock/sim/docker/entrypoint.sh /entrypoint.sh
# The entrypoint may have Windows line endings from the checkout.
RUN tr -d '\015' < /entrypoint.sh > /e && mv /e /entrypoint.sh \
 && chmod +x /opt/nexufend/nexufend-agent /entrypoint.sh
ENV PYTHONPATH=/opt/zfsim/python PYTHONUNBUFFERED=1
VOLUME /data
ENTRYPOINT ["/entrypoint.sh"]
