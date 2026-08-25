# AIVPN Server Production Dockerfile
# Multi-stage build for minimal image size

# Stage 1: Build
# rust:1.97-slim-trixie — current stable Rust on Debian 13 (trixie), matching
# the runtime stage below so the dynamically linked binary finds the same
# glibc. Keep both stages on the same Debian release when bumping either.
FROM rust:1.97-slim-trixie AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace (Cargo.lock pinned for reproducible release builds).
# The whole crates/ tree is copied rather than an explicit per-crate list:
# every workspace member in Cargo.toml must be present for cargo to resolve
# the workspace at all, so an enumerated list silently breaks the image the
# moment a member is added.
COPY Cargo.toml Cargo.lock ./
COPY crates crates/
COPY assets/masks assets/masks/

# Build in release mode with the committed Cargo.lock (--locked → reproducible).
# Full feature set so the image works with the web panel (management-api →
# /run/aivpn/api.sock), the metrics dashboard, and neural mask rotation —
# matching `make server`. Use a custom build for a minimal gateway.
RUN cargo build --locked --release --bin aivpn-server --features "management-api,metrics,neural"

# Stage 2: Runtime
# debian:trixie-slim — Debian 13, the current stable release (bookworm is now
# oldstable). Must stay on the same release as the builder stage above.
# TODO(security): pin with @sha256:<digest> once a digest is chosen to track
# (trixie-slim is a floating tag; a digest pin trades that for a manual
# bump on every base-image security update).
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    nftables \
    iptables \
    iproute2 \
    netcat-openbsd \
    bc \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 aivpn

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/aivpn-server /usr/local/bin/aivpn-server
COPY deploy/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Create config directory and TUN device node
RUN mkdir -p /etc/aivpn /dev/net /var/lib/aivpn/bootstrap /var/lib/aivpn/masks && \
    { mknod /dev/net/tun c 10 200 2>/dev/null || true; } && \
    { [ ! -e /dev/net/tun ] || chmod 600 /dev/net/tun; } && \
    chmod +x /usr/local/bin/docker-entrypoint.sh && \
    mkdir -p /usr/share/aivpn

# Copy example config
COPY deploy/config/server.json.example /usr/share/aivpn/server.json.example

# Seed preset masks so server has masks on first run
COPY assets/masks/*.json /usr/share/aivpn/preset-masks/

# Expose port
EXPOSE 443/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD test "$(basename "$(readlink /proc/1/exe 2>/dev/null)")" = "aivpn-server" || exit 1

# Run as root (required for TUN device and NAT)
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--config", "/etc/aivpn/server.json", "--listen", "0.0.0.0:443", "--key-file", "/etc/aivpn/server.key"]
