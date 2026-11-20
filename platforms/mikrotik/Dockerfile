# syntax=docker/dockerfile:1
# aivpn-mikrotik: runs aivpn-client inside a MikroTik RouterOS container
# Build: docker build --build-arg MUSL_IMAGE_TAG=aarch64-musl --build-arg TARGET_TRIPLE=aarch64-unknown-linux-musl -t aivpn-mikrotik .
# See build-mikrotik.sh for multi-arch manifest push

ARG MUSL_IMAGE_TAG=aarch64-musl
ARG TARGET_TRIPLE=aarch64-unknown-linux-musl

# Stage 1: cross-compile aivpn-client as a static musl binary
FROM --platform=linux/amd64 messense/rust-musl-cross:${MUSL_IMAGE_TAG} AS builder

ARG TARGET_TRIPLE

WORKDIR /app
# Cargo.lock is copied and --locked is passed so the router image is built from
# the same pinned dependency graph as the server image. The whole crates/ tree
# is copied rather than an explicit per-crate list: cargo needs every member
# listed in Cargo.toml to be present to resolve the workspace at all.
COPY Cargo.toml Cargo.lock ./
COPY crates crates/
COPY vendor vendor/
COPY deploy/install-client-image.sh deploy/install-client-image.sh
COPY deploy/install-app-routing.sh deploy/install-app-routing.sh
COPY deploy/systemd/aivpn-app-routing.service deploy/systemd/aivpn-app-routing.service
COPY deploy/systemd/aivpn-app-routing.socket deploy/systemd/aivpn-app-routing.socket
COPY platforms/linux/polkit/com.aivpn.client.policy platforms/linux/polkit/com.aivpn.client.policy
COPY assets/masks assets/masks/

RUN cargo build --locked --release --target "${TARGET_TRIPLE}" -p aivpn-client --bin aivpn-client \
    && cp "target/${TARGET_TRIPLE}/release/aivpn-client" /aivpn-client

# Stage 2: minimal runtime image with iproute2 for ip commands
FROM alpine:3.24
RUN apk add --no-cache iproute2 iptables ca-certificates \
    && rm -rf /var/cache/apk/*

COPY --from=builder /aivpn-client /usr/local/bin/aivpn-client
COPY platforms/mikrotik/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/aivpn-client

# Required at runtime: /dev/net/tun must be mounted from RouterOS host
# Required capability: NET_ADMIN (set by RouterOS container runtime)
ENTRYPOINT ["/entrypoint.sh"]
