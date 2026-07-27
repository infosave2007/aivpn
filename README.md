🌐 [Русский](README_RU.md) | [中文](README_CN.md)

# AIVPN

[![CI](https://github.com/infosave2007/aivpn/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/infosave2007/aivpn/actions/workflows/ci.yml)
[![Crates.io Server](https://img.shields.io/crates/v/aivpn-server.svg?label=aivpn-server)](https://crates.io/crates/aivpn-server)
[![Crates.io Client](https://img.shields.io/crates/v/aivpn-client.svg?label=aivpn-client)](https://crates.io/crates/aivpn-client)
![Rust](https://img.shields.io/badge/rust-1.75%2B-blue.svg)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20%7C%20iOS%20%7C%20MikroTik-informational)

---

## Overview

AIVPN is a UDP-based VPN system that combines standard tunnel encryption with **traffic mimicry**: outbound packets are reshaped to resemble known application protocols (WebRTC, QUIC, DNS-over-UDP), making the connection statistically indistinguishable from regular application traffic to passive observers.

Key technical properties:

- **Zero-RTT data start** — encrypted payload can flow in the first packet; no mandatory handshake round-trip.
- **O(1) session lookup** — no session ID is transmitted in the clear. Every packet carries an 8-byte *resonance tag* derived from a timestamp and a per-session secret. The server resolves the session in constant time via a `DashMap`.
- **Perfect Forward Secrecy** — in-flight session key rotation via X25519 ratchet. Compromising the server key does not expose past traffic.
- **Neural Resonance module** — per-mask micro-MLP (~66 KB) monitors live traffic statistics; high reconstruction error triggers automatic mask rotation without disconnecting clients.
- **Generative mask distributions** — masks auto-recorded from real traffic model multimodal packet-size / inter-arrival behaviour with a BIC-selected Gaussian mixture (design-doc §4 "neural-generated masks"), reproducing real DNS/QUIC/WebRTC distributions far more faithfully than a single Gaussian. It is an internal representation sampled transparently by every client, not a separate mask type.
- **Written in Rust** — memory-safe, no GC pauses. Client binary ≈ 2.5 MB. Runs on a $5 VPS.

---

## Architecture

### Workspace layout

```
crates/aivpn-common/     — shared crypto, protocol, mask profiles (no I/O)
crates/aivpn-server/     — Linux-only VPN gateway and management CLI
crates/aivpn-client/     — cross-platform VPN client (Linux / macOS / Windows)
crates/aivpn-android-core/ — JNI bridge for Android (Rust → Kotlin via C FFI)
crates/aivpn-ios-core/   — iOS Rust staticlib (C FFI), linked by PacketTunnelProvider
crates/aivpn-windows/    — Windows GUI (egui/eframe 0.31, manages aivpn-client.exe subprocess)
crates/aivpn-linux/      — Linux GUI (iced 0.13, wraps aivpn-client subprocess)
platforms/android/       — Android Kotlin app (MVVM: MainViewModel + RecyclerView)
platforms/ios/           — iOS SwiftUI app + NetworkExtension PacketTunnelProvider
platforms/macos/         — macOS SwiftUI menu bar app + privileged helper daemon
platforms/aivpn-web/     — Web management panel (Hono 4 + SvelteKit 2, SQLite/PostgreSQL)
mask-assets/             — bundled traffic mimicry JSON profiles
```

### Key modules

| Module | Location | Purpose |
|--------|----------|---------|
| `crypto.rs` | `aivpn-common` | X25519 key exchange, ChaCha20-Poly1305 AEAD, BLAKE3/HMAC, resonance tag generation |
| `protocol.rs` | `aivpn-common` | Wire format: `[8-byte tag][pad_len][inner_header][encrypted payload][poly1305 tag]` |
| `mask.rs` | `aivpn-common` | `MaskProfile` — traffic shaping: header templates, FSM states, IAT distributions |
| `gateway.rs` | `aivpn-server` | Central event loop: UDP receive, session dispatch, NAT forwarding, neural checks |
| `session.rs` | `aivpn-server` | `SessionManager` — `DashMap`-based O(1) tag lookup, 256-entry replay window, 500-session cap |
| `neural.rs` | `aivpn-server` | Neural Resonance: per-mask MLP 64→128→64, MSE threshold 0.35, auto mask rotation |
| `client.rs` | `aivpn-client` | State machine: Unprovisioned → Connecting → Connected, key exchange, reconnection |
| `tunnel.rs` | `aivpn-client` | Cross-platform TUN: `/dev/net/tun` (Linux), `utun` (macOS), Wintun (Windows) |
| `mimicry.rs` | `aivpn-client` | `MimicryEngine` — applies `MaskProfile` to outbound packets |

### Pool sync

Server-to-server client database synchronization uses `ControlPayload::PoolSync` carried inside ordinary VPN UDP packets — indistinguishable from client traffic. No separate TCP port or firewall rule required.

---

## Platform Support

| Platform | Server | Client | GUI | TUN driver |
|----------|:------:|:------:|:---:|------------|
| Linux CLI | ✅ | ✅ | — | `/dev/net/tun` |
| Linux GUI | — | ✅ | ✅ iced AppImage + tray | `/dev/net/tun` |
| macOS | — | ✅ | ✅ menu bar | `utun` |
| Windows | — | ✅ | ✅ egui GUI | [Wintun](https://www.wintun.net/) |
| Android | — | ✅ | ✅ native Kotlin | `VpnService` API |
| iOS | — | ✅ | ✅ SwiftUI | `NetworkExtension` |
| MikroTik RouterOS 7.6+ | — | ✅ | — | container veth + TUN |
| Entware routers (ARMv7 / MIPSel) | — | ✅ | — | musl static binary |

### Feature Capability Matrix

| Feature | Linux CLI | Linux GUI | Win | Mac | Android | iOS |
|---------|:---------:|:---------:|:---:|:---:|:-------:|:---:|
| Traffic Mimicry | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Adaptive Mode (4 levels) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Live Quality Score | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Split Tunnel | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DNS Proxy | ✅ | ✅ | ✅ | ✅ | N/A* | ❌ |
| Kill Switch | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| mTLS Certificate | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| FEC (forward error correction) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Traffic Recording | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Device Key / JIT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SOCKS5 Proxy | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Full Tunnel | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Diagnostics / Benchmark | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Bootstrap Descriptor Discovery | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Polymorphic Masks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Crowdsourced Mask Feedback (opt-in) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| In-App Admin (roles, client mgmt, revoke, audit)‡ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Pool Topology View + Per-Client Exit Node | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SSH Server Install Wizard§ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Live Metrics Graphs† | — | — | — | — | — | — |

\* Android's `VpnService` API routes all device traffic (including DNS) through the encrypted tunnel by design — there's no separate local DNS-proxy listener because none is needed; DNS leaks aren't possible on this platform.

† Live Metrics Graphs is a server + [Web Management Panel](#web-management-panel) feature, not a client capability — it requires building the server with `--features metrics` and is viewed from the web dashboard, not from any of the clients above.

‡ See [In-App Client Administration & Roles](#in-app-client-administration--roles). On desktop, the CLI exposes the same surface via `aivpn-client mgmt`/`aivpn-client role` (bridged over the local admin socket); Linux CLI's checkmark reflects that CLI bridge rather than a graphical admin screen.

§ See [SSH Server Installer](#ssh-server-installer). Requires the client to be built with the `ssh-install` Cargo feature (bundled by default in the released GUI/mobile builds); on Linux CLI it is the `aivpn-client ssh-install {script,probe,run}` subcommand rather than a graphical wizard.

---

## Web Management Panel

`platforms/aivpn-web/` provides a full-stack web UI for managing the aivpn server.

**Stack:** Hono 4 + Bun (backend) · SvelteKit 2 + Svelte 5 + TailwindCSS 4 (frontend) · Layerchart charts · SQLite (default) or PostgreSQL

**Features:**
- JWT auth (15 min access token + 7-day refresh httpOnly cookie), argon2id passwords
- TOTP 2FA (AES-256-GCM encrypted secrets) and WebAuthn passkeys
- Roles: `admin` (full access) and `viewer` (read-only) — these are the **web panel's own** login roles, independent of a VPN client's [`ClientRole`](#in-app-client-administration--roles). `viewer` is enforced through a fail-closed allowlist of GET-only proxied endpoints (clients, pool nodes/links/health, masks, status, kernel, events); config, backup, bootstrap export, and mask upload/delete stay admin-only.
- Pages: Dashboard (live charts), Clients (add/edit/QR/revoke, role assignment), Pool (topology graph, per-client exit node, audit hash-chain verify badge), Config, Masks, Backup, Logs, Settings
- All `/api/v1/*` proxied to the aivpn Unix socket (`/run/aivpn/api.sock`)
- Realtime SSE event stream at `/web/events`
- **Live metrics graphs** — the Dashboard renders live time-series charts (active sessions, bandwidth in/out, packet rate, p50/p95 packet-processing latency) plus pulsing badges for mask/key rotations and DPI-attacks-detected, all fed over the same `/web/events` SSE stream from an in-memory ~10-minute ring buffer (no new persistent storage). Requires the server to be built with `--features metrics` (see [Optional features (Cargo)](#optional-features-cargo)); the dashboard shows a hint instead of the charts if the server lacks that feature.

**Quick Start:**

```bash
# 1. Generate secrets
JWT_SECRET=$(openssl rand -base64 48)
TOTP_KEY=$(openssl rand -base64 32)

# 2. Run with Docker (simplest)
docker run -d --name aivpn-web \
  -v /run/aivpn:/run/aivpn \
  -e JWT_SECRET="$JWT_SECRET" \
  -e TOTP_ENCRYPTION_KEY="$TOTP_KEY" \
  -e ORIGIN=https://vpn.example.com \
  -p 8080:8080 \
  ghcr.io/infosave2007/aivpn-web:latest

# 3. Get the one-time admin password from the startup log
docker logs aivpn-web 2>&1 | grep -A4 "FIRST-TIME SETUP"

# 4. Open https://vpn.example.com and log in with username "admin"
```

Or via `docker compose up -d aivpn-web` (secrets go in `platforms/aivpn-web/.env`).

**Run (Bun, from source):**
```bash
cd platforms/aivpn-web
cp .env.example .env          # fill JWT_SECRET, TOTP_ENCRYPTION_KEY, ORIGIN
bun install && bun run build
bun run start                 # listens on PORT (default 8080)
```

**Key environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `file:./data/aivpn-web.db` | SQLite path or `postgres://...` |
| `JWT_SECRET` | — | Long random string for token signing |
| `TOTP_ENCRYPTION_KEY` | — | 32-byte base64 key (`openssl rand -base64 32`) |
| `ORIGIN` | — | Public HTTPS URL (required for WebAuthn / CSRF) |
| `UNIX_SOCK` | `/run/aivpn/api.sock` | Path to aivpn management socket |
| `PORT` | `8080` | HTTP listen port |

**Makefile targets:**
```bash
make web           # install deps + build frontend
make web-docker    # build Docker image aivpn-web:latest
make web-dev       # start dev servers (hot reload)
```

An nginx reverse-proxy example is in `deploy/nginx/aivpn-web.conf`.

**Default credentials (first run):**

On first startup with an empty database, a random admin password is generated and printed once to the server console:

```
╔══════════════════════════════════════════════════╗
║         FIRST-TIME SETUP — SAVE THESE NOW        ║
╠══════════════════════════════════════════════════╣
║  Username : admin                                 ║
║  Password : <random 22-char base64url string>     ║
╚══════════════════════════════════════════════════╝
```

Save this password immediately — it is shown **once** only. After logging in, change it in **Settings → Security** or register a passkey.

**OIDC / SSO (optional):**

| Variable | Description |
|----------|-------------|
| `OIDC_ISSUER` | IdP base URL (e.g. `https://accounts.google.com`) |
| `OIDC_CLIENT_ID` | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | Client secret (omit for public PKCE clients) |
| `OIDC_MODE` | `disabled` (default) · `enabled` (adds SSO button) · `exclusive` (SSO only) |
| `OIDC_ROLE_CLAIM` | ID token claim containing the user's role (e.g. `role`) |
| `OIDC_ADMIN_VALUE` | Claim value that grants `admin` role (default: `admin`) |

The role from OIDC is applied only on **first** SSO login; admins can override it afterwards in the web panel.

---

## Quick Start

### Server (Linux)

#### Docker (recommended)

```bash
mkdir -p config
docker compose up -d aivpn-server
```

The container auto-generates `server.key` and `server.json` on first start. It runs with `network_mode: host` and mounts `./config` → `/etc/aivpn`.

Open UDP port 443 in your firewall:

```bash
# UFW
sudo ufw allow 443/udp
# firewalld
sudo firewall-cmd --add-port=443/udp --permanent && sudo firewall-cmd --reload
```

#### Bare metal

```bash
sudo mkdir -p /etc/aivpn
openssl rand 32 | sudo tee /etc/aivpn/server.key > /dev/null
sudo chmod 600 /etc/aivpn/server.key
sudo ./aivpn-server --listen 0.0.0.0:443 --key-file /etc/aivpn/server.key
```

The server automatically enables IPv4 forwarding and installs NAT masquerade rules (nftables preferred, iptables fallback). No manual firewall configuration is required for the tunnel itself.

#### Add a client

```bash
# Docker
docker compose exec aivpn-server aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip YOUR_PUBLIC_IP:443

# Bare metal
aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip YOUR_PUBLIC_IP:443
```

Output includes the connection key (`aivpn://…`) — distribute it to the client.

Add `--role viewer|admin` to grant that client [in-app management access](#in-app-client-administration--roles) (requires the client to already be device-bound — combine with `--device-pubkey <BASE64>` to create a device-bound admin in one shot, no separate enrollment step):

```bash
aivpn-server --add-client "Admin Phone" --role admin --device-pubkey <BASE64_DEVICE_PUBKEY> \
    --key-file /etc/aivpn/server.key --clients-db /etc/aivpn/clients.json --server-ip YOUR_PUBLIC_IP:443
```

Other management commands: `--list-clients`, `--show-client`, `--remove-client`, `--enable-client`/`--disable-client`, `--reset-device`.

---

### Client — Linux

```bash
sudo ./aivpn-client -k "aivpn://..."
# Full tunnel (route all traffic through VPN)
sudo ./aivpn-client -k "aivpn://..." --full-tunnel
```

### Client — macOS

Download `aivpn-macos.dmg` from [Releases](https://github.com/infosave2007/aivpn/releases), drag **Aivpn.app** to Applications, launch — appears in the menu bar. Paste the connection key and click **Connect**.

CLI:
```bash
sudo ./aivpn-client -k "aivpn://..."
```

> The app prompts for a password via `sudo` to create the `utun` interface.

### Client — Windows

**Installer (recommended):** download `aivpn-windows-installer.exe`, run as Administrator, launch **AIVPN** from the Start Menu.

**Portable:** extract `aivpn-windows-package.zip` (contains `aivpn.exe`, `aivpn-client.exe`, `wintun.dll`). Run `aivpn.exe` as Administrator.

CLI (PowerShell, elevated):
```powershell
.\aivpn-client.exe -k "aivpn://..."
```

> Administrator privileges are required to create the Wintun network adapter.

### Client — Android

1. Install `aivpn-client.apk`
2. Paste the connection key (`aivpn://…`)
3. Tap **Connect**

### Client — iOS

Build on macOS (Xcode 15+ required):

```bash
make ios TEAM_ID=YOUR_TEAM_ID
```

Install `releases/aivpn-ios.ipa`:
```bash
xcrun devicectl device install app --device <UDID> releases/aivpn-ios.ipa
```

> A free Apple Developer account is sufficient. Sideloaded builds expire after 7 days.

### Client — Entware routers (ARMv7 / MIPSel)

```bash
# Copy the static musl binary to the router
scp aivpn-client-linux-armv7-musleabihf root@router:/opt/bin/aivpn-client
ssh root@router 'chmod +x /opt/bin/aivpn-client && /opt/bin/aivpn-client -k "aivpn://..."'
```

### Client — MikroTik RouterOS 7.6+

```routeros
/system/device-mode/update container=yes   # then reboot
/interface/veth/add name=veth-aivpn address=172.31.0.2/30 gateway=172.31.0.1
/ip/address/add address=172.31.0.1/30 interface=veth-aivpn
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
/container/envs/add list=aivpn-env name=AIVPN_KEY value="aivpn://..."
/container/add remote-image=infosave2007/aivpn-mikrotik:latest \
    interface=veth-aivpn start-on-boot=yes envlist=aivpn-env mounts=aivpn-tun
/container/start [find remote-image~"aivpn-mikrotik"]
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2
```

See [platforms/mikrotik/README.md](platforms/mikrotik/README.md) for policy routing and troubleshooting.

### SOCKS5 proxy mode (no root)

```bash
aivpn-client -k "aivpn://..." --proxy-listen 127.0.0.1:1080
```

Configure Firefox / Chrome / curl to use `SOCKS5 127.0.0.1:1080`. No TUN device or administrator privileges required.

---

## Connection Key Format

Connection keys encode all server and client parameters in a single portable string:

```
aivpn://<base64url(JSON)>
```

JSON fields:

| Field | Type | Description |
|-------|------|-------------|
| `s` | `string` | Server address, e.g. `"1.2.3.4:443"` |
| `k` | `string` | Server X25519 public key (base64) |
| `p` | `string` | Client pre-shared key / PSK (base64) |
| `i` | `string` | Client static VPN IP, e.g. `"10.0.0.2"` |
| `n` | `object` | *(optional)* Bootstrap `network_config` (see below) |

`network_config` object (`n`):

| Field | Description |
|-------|-------------|
| `client_ip` | Client TUN IP |
| `server_vpn_ip` | Server TUN IP |
| `prefix_len` | Subnet prefix length |
| `mtu` | Inner MTU |

Priority order when connecting:

1. Settings confirmed by `ServerHello` (authoritative)
2. Bootstrap `network_config` from the key
3. Legacy fallback `10.0.0.0/24`

Keys without `network_config` remain fully supported.

Generate a key:
```bash
aivpn-server --add-client "Name" --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

Reprint an existing key:
```bash
aivpn-server --show-client "Name" --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

---

## Server Configuration Reference

Default config path: `config/server.json` (local) or `/etc/aivpn/server.json`. CLI flags override file values.

```json
{
  "listen_addr": "0.0.0.0:443",
  "tun_name": "aivpn0",
  "tun_mtu": "auto",
  "mask_dir": "/var/lib/aivpn/masks",
  "bootstrap_mask_files": [],
  "session_timeout_secs": 0,
  "idle_timeout_secs": 300,
  "allow_peer_routing": false,
  "network_config": {
    "server_vpn_ip": "10.0.0.1",
    "prefix_len": 24,
    "mtu": 1346,
    "keepalive_secs": 8,
    "ipv6_enabled": false,
    "ipv6_prefix": "fd10:cafe::/48"
  },
  "pool": {
    "peers": [],
    "sync_key": ""
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `listen_addr` | `0.0.0.0:443` | UDP bind address. Port is embedded in connection keys automatically |
| `tun_name` | random | TUN interface name |
| `tun_mtu` | _(unset)_ | `"auto"` = physical MTU minus 64-byte overhead (fallback 1346); or a fixed integer |
| `mask_dir` | `/var/lib/aivpn/masks` | Directory scanned for `.json` mask profiles |
| `bootstrap_mask_files` | `[]` | Mask files pre-loaded at startup to reduce first-connection latency |
| `session_timeout_secs` | `0` | Hard session cap; `0` = unlimited |
| `idle_timeout_secs` | `300` | Disconnect sessions silent for this many seconds |
| `allow_peer_routing` | `false` | Route packets between VPN clients inside the subnet |
| `network_config.server_vpn_ip` | `10.0.0.1` | Server TUN IP |
| `network_config.prefix_len` | `24` | VPN subnet prefix |
| `network_config.mtu` | `1346` | Inner MTU sent to clients in `ServerHello` |
| `network_config.keepalive_secs` | `8` | Keepalive interval negotiated with clients |
| `network_config.ipv6_enabled` | `false` | Enable IPv6 NAT66 |
| `network_config.ipv6_prefix` | `fd10:cafe::/48` | ULA /48 prefix for client IPv6 addresses |
| `pool.peers` | `[]` | Peer server addresses for database sync |
| `pool.sync_key` | `""` | Shared 32-byte BLAKE3 key (base64). Generate: `openssl rand -base64 32` |
| `pool.node_id` | _(unset)_ | This node's own identifier within the pool (recommended: its `host:port`); pool sync is disabled while unset |
| `pool.node_ip_partition` | hash-derived | Pin this node's hard VPN-IP partition index explicitly instead of deriving it from `hash(node_id)` — rules out a hash collision, or hand-balances a large pool. See [Pool Topology and Per-Client Exit Routing](#pool-topology-and-per-client-exit-routing) |
| `pool.transport` | `"legacy"` | `"masked"` switches pool sync to dial peers as a fully masked pool-client with bidirectional anti-entropy, instead of the mask-independent push-only legacy transport |
| `pool.exit_node` / `pool.exit_node_enabled` | unset / `false` | Global-default multi-hop exit (see [Multi-hop Chain Forwarding](#multi-hop-chain-forwarding)); overridable per client |

### Optional features (Cargo)

| Feature | What it enables |
|---------|----------------|
| `neural` | Neural Resonance module (MSE-based mask rotation) |
| `management-api` | Unix socket HTTP API at `/run/aivpn/api.sock` |
| `metrics` | Prometheus exporter, and live runtime metrics (active sessions, bandwidth, mask/key rotations, DPI-attacks-detected, packet-processing latency) over `/web/events` SSE for the [web panel's live graphs](#web-management-panel) |
| `passive-distribution` | Bootstrap descriptor distribution channels |
| `bootstrap-publish` | Auto-publish rotated bootstrap descriptors to S3/GitHub/Telegram (see [Bootstrap Descriptor Distribution](#bootstrap-descriptor-distribution)) |

---

## Build from Source

Requires: Rust 1.75+, `cargo`, `make`.

```bash
git clone https://github.com/infosave2007/aivpn
cd aivpn
make help          # show all available targets
```

### Server builds (Linux)

```bash
make server        # x86_64 → releases/aivpn-server-linux-x86_64
make server-arm64  # ARM64  → releases/aivpn-server-linux-arm64
make server-docker # via Docker (minimal host dependencies)
```

### Client builds

```bash
make client        # Linux x86_64
```

### musl static cross-builds (for routers)

```bash
make server-musl-armv7        # ARMv7
make server-musl-mipsel       # MIPSel
make server-musl-aarch64      # AArch64 (default features)
make server-musl-aarch64-full # AArch64, full feature set (management-api,metrics,neural) — what CI publishes as aivpn-server-linux-aarch64
```

### Platform builds

```bash
make windows              # Windows GUI + zip (cross-compile from Linux)
make windows-docker       # Windows GUI via Docker (no mingw-w64 required)
make ios [TEAM_ID=XX]     # iOS IPA (macOS + Xcode 15+ only)
make macos                # macOS .app + .pkg + .dmg (macOS only)
make linux                 # Linux GUI binary (no extra tools)
make linux-appimage        # Linux GUI as AppImage (requires appimagetool)
```

### Deploy

```bash
make deploy               # VPS: download binary + start docker compose
make server-deploy HOST=vps.example.com  # SSH upload local binary to VPS
```

### Tests and development

```bash
make test           # cargo test --workspace
make clippy         # cargo clippy
make check          # cargo check (fast)
make test-docker    # integration test: server + client in Docker
```

### Android

```bash
export ANDROID_SDK_ROOT=/opt/android-sdk
export ANDROID_NDK_ROOT=/opt/android-ndk
echo "sdk.dir=$ANDROID_SDK_ROOT" > platforms/android/local.properties

make android
```

Signed build: create `platforms/android/keystore.properties` before running the script.

### Optional Cargo features (server)

```bash
cargo build --release --bin aivpn-server --features "management-api,metrics,neural"
```

### Install from crates.io

```bash
cargo install aivpn-client
cargo install aivpn-server
```

---

## Advanced Features

### Device Binding (JIT enrollment)

A connection key can be designated as *one-time*: the first device to connect binds its X25519 static key, and subsequent connections from a different device are rejected.

```bash
# Create enrollment slot
aivpn-server --add-client-one-time "Alice-Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip IP:PORT

# Reset binding (re-enable enrollment)
aivpn-server --reset-device "Alice-Phone" \
    --clients-db /etc/aivpn/clients.json
```

Device key storage per platform:

| Platform | Location |
|----------|----------|
| Linux / macOS | `~/.config/aivpn/device.key` (mode 600, auto-generated) |
| Windows | `%APPDATA%\aivpn\device.key` |
| Android | Android Keystore via `EncryptedSharedPreferences` |
| iOS | Keychain, `kSecAttrAccessibleAfterFirstUnlock` |

### In-App Client Administration & Roles

Any client can be granted a management **role** that gates what it may do — both against the Unix-socket REST API and via an in-tunnel management channel carried inside ordinary VPN traffic, so administration works even when no other path to the server is reachable:

| Role (`ClientRole`) | Rank | Grants (curated tunnel/API surface: clients, pool topology, audit log, status, heavy-config apply/confirm) |
|---|---|---|
| `user` (default) | 0 | connect only — no management access |
| `viewer` | 1 | read-only: GET on every curated route (list/inspect clients, connection key, pool nodes/health/links, status, audit log) |
| `admin` | 2 | the full curated allowlist, reads and mutations: add/edit/remove/revoke clients, role assignment, per-client `exit_node`, reset-device, apply/confirm heavy config (active mask, global exit node) |

Elevating a client above `user` requires it to already be **device-bound** (see [Device Binding](#device-binding-jit-enrollment)) — a role is a privilege grant, so it is always tied to a proven device key, never a bare PSK:

```bash
# Fresh client, device-bound and elevated to admin in one step
aivpn-server --add-client "Admin Phone" --role admin --device-pubkey <BASE64_DEVICE_PUBKEY> \
    --key-file /etc/aivpn/server.key --clients-db /etc/aivpn/clients.json --server-ip IP:PORT

# Elevate an already device-bound client afterwards (role-only re-add)
aivpn-server --add-client "Alice" --role viewer --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

`--role` and `--device-pubkey` also apply to `--add-client-one-time`, so a fresh one-time-enrollment slot can be pre-granted a role that takes effect once the device actually binds.

**Managing the server from inside the tunnel** — an admin/viewer-role client can issue `MgmtRequest`/`MgmtResponse` control messages against a curated subset of the REST surface (`/api/v1/status`, `/api/v1/clients*`, `/api/v1/audit-log`, `/api/v1/config/apply`+`/confirm`, `/api/v1/pool/*`), rate-limited per session. Full config `PUT`, `/api/v1/backup/import`, and mask-signing-key management are deliberately **never** reachable this way, even for `admin` — those stay Unix-socket-only (local CLI, or the web panel's own separately-gated `admin` login). Desktop clients bridge the curated surface to a local admin socket via the CLI:

```bash
aivpn-client mgmt --method GET --path /api/v1/clients
aivpn-client role   # prints the role (0=user/1=viewer/2=admin) the server granted this client
```

Android and iOS expose the equivalent calls through JNI/FFI (`mgmtRequest`/`getRole`/`qrPng`), and all 5 platform GUIs (Linux, Windows, macOS, Android, iOS) plus the web panel's Clients page ship an admin screen: list clients, add a new one with its QR code, edit, and revoke — role-gated so a `viewer`-role session only sees the read side.

**Revoke** — `POST /api/v1/clients/:id/revoke` (or the tunnel equivalent) force-disconnects the client's live session immediately and disables it from reconnecting, and pushes a priority pool beacon so other pool nodes learn about the revoke without waiting for the next sync interval.

**Tamper-evident audit log** — every admin action, whether via the REST API or the in-tunnel path, is appended to a hash-chain log (`--audit-log`, default `/var/log/aivpn/audit.log`, JSONL). `GET /api/v1/audit-log?verify=1` walks the chain and returns `{ entries, verified, broken_at }` instead of the plain entry array; the web panel surfaces this as a verify badge.

**Apply-with-rollback for heavy settings** — changes that could lock the operator out if misapplied (the server's active mask, the global-default exit node) go through a commit-confirm flow instead of applying immediately: `POST /api/v1/config/apply` stages the change and starts a rollback timer; `POST /api/v1/config/confirm` commits it before the timer expires. An unconfirmed change reverts automatically.

**Web panel role gating** — the web panel has its own separate `admin`/`viewer` login roles that gate its proxy in front of the server API; see [Web Management Panel](#web-management-panel) for the allowlist. They are independent of the `ClientRole` table above.

### Connection Quality Score and Adaptive Mode

AIVPN continuously computes a **0–100 quality score** from RTT (40 pts), jitter (20 pts), packet loss (30 pts), and Neural MSE (10 pts). Adaptive Mode adjusts keepalive interval and FEC group size automatically:

| Score | Adaptive Level | Keepalive | FEC group |
|-------|---------------|-----------|-----------|
| 80–100 | Off | 8 s | disabled |
| 50–79 | Light | 6 s | 1/16 |
| 20–49 | Aggressive | 4 s | 1/8 |
| 0–19 | Satellite | 15 s | 1/4 |

Enable Adaptive Mode:
```bash
aivpn-client -k "aivpn://..." --adaptive
```

### Forward Error Correction (FEC)

Every N uplink data packets, one XOR repair packet is emitted. If exactly one packet from a group is lost, the server reconstructs it immediately — no retransmit round-trip. N is controlled by Adaptive Mode. FEC is disabled on clean links.

### Multi-server Pool Sync

Nodes in a pool share their client databases in real time over the standard VPN port:

```json
{
  "pool": {
    "peers": ["node2.example.com:443"],
    "sync_key": "<base64-32-byte-key>"
  }
}
```

### Pool Topology and Per-Client Exit Routing

**Read-only topology endpoints** — `GET /api/v1/pool/nodes`, `/api/v1/pool/health`, `/api/v1/pool/links` expose the pool's current node list, per-node health, and inter-node link status, reachable by `viewer`-role sessions too. The web panel's **Pool** page renders this as a live topology graph.

**Hard per-node VPN-IP partitioning** — each pool node claims a disjoint slice of the VPN subnet (`hash(node_id) % partitions` by default, or pinned explicitly via `pool.node_ip_partition`), so independent client adds performed on two different nodes at the same time can never collide on the same VPN IP. Nodes exchange their claimed partitions (`ControlPayload::PartitionAnnounce`) and flag an operator-caused overlap (e.g. a hash collision, or a misconfigured `node_ip_partition`) instead of silently corrupting the pool. The pre-existing deterministic re-home logic remains as a backstop for any IP that still ends up contended.

**Per-client exit routing** — independent of the pool-wide default below, any individual client can be routed through a specific pool exit node, live, without a server restart: `PATCH /api/v1/clients/:id` with `{"exit_node": "host:port"}` (or `null` to fall back to the global default), also reachable over the tunnel mgmt path. Unlike `role`, setting a client's own `exit_node` is not a privilege grant and needs no device binding. The server dials the target exit peer on demand if it isn't already an active pool connection. All 5 client GUIs and the web panel's Pool/Clients pages expose an exit-node picker per client.

### Multi-hop Chain Forwarding

Route client traffic through two AIVPN nodes. The client connects only to the entry node; the internet sees the exit node's IP. This sets the **global default** exit node for every client that has no per-client `exit_node` override (see [Pool Topology and Per-Client Exit Routing](#pool-topology-and-per-client-exit-routing) above); changing it live goes through the [apply-with-rollback](#in-app-client-administration--roles) flow since a bad global exit can black-hole all pool traffic.

**Entry node:**
```json
{ "pool": { "sync_key": "<key>", "exit_node": "exit.example.com:443" } }
```
**Exit node:**
```json
{ "pool": { "sync_key": "<same-key>", "exit_node_enabled": true } }
```

### SSH Server Installer

`deploy/install-server.sh` is an idempotent, systemd-first installer for a fresh Linux VPS: it detects the distro/architecture, checks the target port is free, fetches (or accepts a locally-supplied) `aivpn-server` release binary and verifies its SHA256, generates `server.key`/`server.json`, seeds mask profiles, installs and starts a systemd unit (or deploys via `docker compose` with `--mode docker`), opens the firewall, optionally provisions a device-bound admin client in the same run, and health-checks that `aivpn-server` actually owns the listening port afterwards. Re-running it is an upgrade: `server.key`/`clients.json` are never overwritten, the binary/unit are always replaced, and the service restarts at the end. Every step prints one machine-readable line on stdout:

```
##AIVPN {"step":"...","status":"ok|error|info","code":"...","msg":"..."}
```

so a caller (a script, or the in-app installer UI below) can track progress without scraping text.

```bash
sudo bash deploy/install-server.sh --device-pubkey <BASE64_DEVICE_PUBKEY> --server-ip vpn.example.com:443
deploy/install-server.sh --help          # full flag / env-var reference
deploy/install-server.sh --show-script   # print the script's own source before running it as root
deploy/install-server.sh --print-sha256  # print the script's own sha256sum
```

Key flags: `--mode systemd|docker`, `--port`/`--listen`, `--binary-url`/`--binary-file`, `--masks-url`/`--masks-dir`, `--device-pubkey`/`--server-ip`/`--admin-name`, `--config`/`--key-file`/`--clients-db`/`--mask-dir`/`--management-socket`/`--audit-log`, `--skip-firewall`, `--skip-deps`. Must be run from this repo's `deploy/` directory (or a full checkout) so it can find `deploy/config/server.json.example` and `deploy/systemd/aivpn-server.service` alongside it — only the server *binary* is fetched over the network by default.

**In-app install wizard** — every native client (Linux, Windows, macOS, Android, iOS) embeds a `russh`-based SSH client (`aivpn_common::ssh_install`, behind the `ssh-install` Cargo feature) together with the installer script, systemd unit, bundled masks, and config template as an embedded asset, and drives a setup wizard entirely from the app: enter the target host, confirm the TOFU SSH host-key fingerprint, optionally review the install script and its SHA256 before running it, watch live progress parsed from the `##AIVPN` markers, then import the resulting `aivpn://` connection key. The wizard's entry point is on the main screen, not gated behind an existing connection or an admin session — bootstrapping a brand-new server from scratch needs neither. On the CLI the same flow is `aivpn-client ssh-install {script,probe,run}`:

```bash
aivpn-client ssh-install probe --host vpn.example.com --user root
aivpn-client ssh-install run --host vpn.example.com --fingerprint "SHA256:..." \
    --key-file ~/.ssh/id_ed25519 --device-pubkey <BASE64_DEVICE_PUBKEY> --server-ip vpn.example.com:443
```

`ssh-install run` authenticates with exactly one of `--password-env`/`--password-stdin`/`--key-file` (never a raw `--password` argument — argv is visible via `/proc/<pid>/cmdline`), and accepts `--binary-file`/`--binary-url` to control which `aivpn-server` build gets installed, plus `--mode systemd|docker` and pass-through `--extra-arg` tokens forwarded to `install-server.sh`.

Native clients originally also shipped a dedicated **migration wizard** (export the current server via `/api/v1/backup/export`, install a fresh server, import via `/api/v1/backup/import`) alongside the install wizard, but it was intentionally dropped from all 5 (Linux, Windows, macOS, Android, iOS) to avoid five near-duplicate implementations of the same export/import flow. Server migration is now a **web-panel-only** capability, driven from the existing Backup page (which already talks to the same `/api/v1/backup/export`/`/api/v1/backup/import` routes) — native clients keep only the install wizard above.

CI publishes full-feature (`management-api,metrics,neural`) `aivpn-server` release binaries for both `x86_64` and `aarch64`, each with a `SHA256SUMS` file — matching what `install-server.sh`'s default `--binary-url` (GitHub Releases) fetches and verifies against.

### Bootstrap Descriptor Distribution

Signed (ed25519) bootstrap descriptors let a brand-new client — one without a working `aivpn://` key yet — discover a usable mask configuration via the same redundant fallback channels (CDN/GitHub/Telegram) the client's `bootstrap_loader.rs` already knows how to fetch from. The server builds, signs, and rotates these every 24h automatically, pushing fresh copies to already-connected clients over the live session.

**CLI export** — print or save the current previous/current/next-epoch signed descriptors as JSON, for manual upload to any hosting:
```bash
aivpn-server --export-bootstrap-descriptor --key-file /etc/aivpn/server.key
aivpn-server --export-bootstrap-descriptor --key-file /etc/aivpn/server.key --bootstrap-output /path/to/bootstrap.json
```
Requires a real `--key-file` — an ephemeral/random server key is rejected, since no client would trust a descriptor signed by a throwaway key.

**Management API export** — the same JSON array is available at `GET /api/v1/bootstrap/export` (feature `management-api`, same Unix-socket auth model as the rest of the API). Treat it as admin-only in any web-panel proxy layer, same as `/config` and `/backup/*`.

**Auto-publish on rotation** — build with `--features bootstrap-publish` and add a `bootstrap_publish` section to `server.json` to push freshly-rotated descriptors automatically whenever the 24h epoch actually advances:
```json
{
  "bootstrap_publish": {
    "enabled": true,
    "channels": [
      { "type": "s3", "endpoint": "https://s3.us-east-1.amazonaws.com", "region": "us-east-1", "bucket": "my-aivpn-bootstrap", "key": "bootstrap.json", "access_key": "...", "secret_key": "..." },
      { "type": "github", "repo": "owner/repo", "asset_name": "bootstrap-descriptors.json", "tag_name": "bootstrap", "token": "..." },
      { "type": "telegram", "bot_token": "...", "chat_id": "..." }
    ]
  }
}
```

- **S3** — any S3-compatible provider (AWS S3, Cloudflare R2, MinIO), path-style addressing (`{endpoint}/{bucket}/{key}`), signed with AWS SigV4.
- **GitHub** — published as a release asset under a fixed `tag_name` (kept up to date across rotations, since clients always fetch `/releases/latest`). Use a fine-grained personal access token scoped to just that one repo.
- **Telegram** — sent as a document via a bot (`sendDocument`). Scope the bot to a single chat/channel.

Each channel is independent (one failing doesn't block the others) and retries 3× with backoff (5s / 30s / 120s) before logging a failure. Without the `bootstrap-publish` feature, `enabled: true` just logs a warning and does nothing — the config section itself is always valid JSON, so config files stay portable across builds.

**Security note:** if the server's private key is compromised, an attacker can already forge valid bootstrap descriptors (the signing key is derived deterministically from it). Auto-publish credentials don't add that forgery capability, but they do let a compromised server push a forged descriptor through the operator's real, trusted distribution channels to reach brand-new users, not just already-connected ones — treat these credentials in `server.json` with the same care as any other secret (file mode `0600`, readable only by the user running `aivpn-server`).

### Local DNS Proxy

Forward all DNS queries through the VPN tunnel (Linux):

```bash
aivpn-client -k "aivpn://..." --dns-proxy 127.0.0.1:5300 --dns-upstream 1.1.1.1:53
```

### Traffic Recording — Custom Mask Creation

Record real application traffic to generate new mimicry profiles:

```bash
# Connect with an admin key, then:
aivpn-client record start --service myapp
# ... use the application for 60+ seconds ...
aivpn-client record stop
```

The server analyzes packet size histograms and inter-arrival times, generates a `MaskProfile`, validates it via self-test, and distributes it to active sessions.

### Polymorphic Masks

Each session can use a per-session, uniquely-perturbed variant of a base mask, so a single static mask profile can't be fingerprinted across users or sessions by an observer comparing traffic from many connections. The server derives the variant deterministically from the session's own key material and pushes it to the client over the existing `MaskUpdate` channel — the client only applies it, with no new client-side cryptography. Perturbation is bounded per-mask (IAT jitter scale, padding shift, header-gap bytes, FSM dwell-time scale) so the traffic still plausibly matches the mimicked protocol; the FSM state graph, spoofed protocol, and ephemeral-key length are never altered. The opening handshake always uses the bootstrap fallback mask (not the named preset), so it isn't fingerprintable before the session's variant is pushed.

```bash
aivpn-client -k "aivpn://..." --polymorphic-base webrtc_yandex_telemost_v1
```

A matching "Polymorphic" checkbox is available in the Linux, Windows, macOS, iOS, and Android GUIs next to the mask picker.

Mask profiles can declare optional `perturbation_bounds` to control how far a polymorphic variant may drift from the base profile:

```json
{
  "mask_id": "webrtc_yandex_telemost_v1",
  "perturbation_bounds": {
    "iat_jitter_scale": 0.15,
    "padding_shift_bytes": 8,
    "header_gap_bytes": 4,
    "fsm_dwell_scale": 0.2
  }
}
```

### Crowdsourced Mask Feedback (opt-in)

Clients can opt in (off by default) to share which masks worked for them and to receive server hints about masks that are working well in their region. Reports are aggregated by a coarse, user-set 2-letter ISO-3166 country code — no finer location ever leaves the client. The server only aggregates a report once at least K=20 distinct reporters have contributed for a given mask/region (tracked with a HyperLogLog sketch that stores no reporter identities), rolling sparse countries up to their continent once same-continent neighbors clear the k-anonymity gate; aggregate memory is bounded by a hard cap with eviction and a periodic sweep. A per-reporter vote cap also bounds how much a single reporter can skew a region's ranking.

Desktop clients record both mask *successes and failures*: pre-handshake connection failures are batched and attributed to the mask that was in use, persisted across restarts at `~/.config/aivpn/mask_feedback.json`, and reported in aggregate the next time a connection succeeds. When `--receive-mask-hints` is on, the client softly biases its initial mask choice toward the highest-scored preset reported for its region — it never overrides an explicit `--preferred-mask`/`--polymorphic-base`, and it never applies when the opening mask must stay a signed bootstrap descriptor (e.g. `--no-fallback`/production-secure builds), so bootstrap security is never weakened. `--share-mask-feedback` and `--receive-mask-hints` are fully independent toggles — a client can receive regional hints without ever sharing its own feedback.

The server pushes reporting cadence to opted-in clients via a `FeedbackConfig` control message, tunable through an optional `"feedback"` block in `server.json`:

```json
{
  "feedback": {
    "report_failure_threshold": 3,
    "report_interval_secs": 3600
  }
}
```

`report_failure_threshold` is the minimum number of consecutive failures on a mask before it is marked failed; `report_interval_secs` is the minimum spacing between a client's feedback sends. Both are optional and default to `3` and `3600` respectively when the block (or a key) is omitted.

```bash
aivpn-client -k "aivpn://..." --share-mask-feedback --receive-mask-hints --country-code DE
```

Both toggles and the country-code field are also available in the Linux, Windows, macOS, iOS, and Android GUIs' settings screens.

### Benchmarking

```bash
aivpn-client bench -k "aivpn://..."
# P50: 12ms  P95: 28ms  Up: 47 Mbps  Down: 52 Mbps  Score: 94/100
aivpn-client bench -k "aivpn://..." --json
```

---

### Mask Signing & Verification (provenance)

A mask defines how traffic is shaped and, critically, *how packets are parsed*
(`tag_offset`, header layout, `spoof_protocol`). A malicious or corrupted mask
reaching a server or client is therefore a real attack surface. aivpn masks carry
an ed25519 signature over the **whole** profile; the server can sign the masks it
distributes with an operator key, and both server and client can verify that
signature on load.

Verification has three modes (`mask_verify_mode`, or `--mask-verify-mode`, env
`AIVPN_MASK_VERIFY_MODE`):

| Mode | Behaviour |
|------|-----------|
| `off` | No signature check. |
| `warn` | **Default.** Verify and log a warning on failure, but still load the mask — nothing breaks if the corpus isn't signed yet. |
| `enforce` | Reject any mask whose signature doesn't verify against the operator public key. Requires the entire mask corpus to be signed first. |

Operator workflow to turn on `enforce`:

```bash
# 1. Generate an operator signing key (prints the public key to distribute).
aivpn-server --gen-mask-signing-key /etc/aivpn/mask-signing.key

# 2. Sign your whole mask corpus in place (run once; also re-run after adding masks).
aivpn-server --sign-mask-dir /var/lib/aivpn/masks --mask-signing-key /etc/aivpn/mask-signing.key

# 3. Server: point at the signing key (auto-signs newly generated masks) and enforce.
#    server.json:  "mask_signing_key": "/etc/aivpn/mask-signing.key", "mask_verify_mode": "enforce"

# 4. Clients: ship them the operator PUBLIC key and enforce.
#    client:  --mask-operator-pubkey <BASE64_PUBKEY> --mask-verify-mode enforce
```

The public key is verified independently for the downlink `reverse_profile` too.
Because `enforce` rejects unsigned masks, roll it out phased — stay on `warn`
until every server's mask directory is signed and clients carry the public key.
The signing key is a secret: store it `0600`, readable only by the operator.

## Security Model

| Property | Mechanism |
|----------|-----------|
| Encryption | ChaCha20-Poly1305 AEAD |
| Key exchange | X25519 ECDH |
| Session authentication | Per-client PSK (optional device binding) |
| Forward secrecy | In-flight X25519 key ratchet |
| Replay protection | 256-entry sliding window per session |
| Session anonymity | 8-byte BLAKE3-derived resonance tag; no session ID in the clear |
| Traffic mimicry | `MaskProfile` FSM: header injection, IAT shaping |
| Mask integrity | Neural Resonance MSE threshold (0.35); automatic rotation |
| NAT traversal | Server-side nftables/iptables, client-side `SO_REUSEPORT` |

Detailed adversary model and threat analysis: [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Project Structure

```
aivpn/
├── crates/aivpn-common/src/
│   ├── crypto.rs          # X25519, ChaCha20-Poly1305, BLAKE3
│   ├── mask.rs            # Mimicry profiles (WebRTC, QUIC, DNS)
│   ├── protocol.rs        # Packet format and control plane
│   └── fec.rs             # XOR Forward Error Correction
├── crates/aivpn-client/src/
│   ├── client.rs          # Core state machine
│   ├── tunnel.rs          # Cross-platform TUN interface
│   ├── kill_switch.rs     # Kill-switch (nftables / pfctl / netsh)
│   └── mimicry.rs         # Traffic shaping engine
├── crates/aivpn-server/src/
│   ├── gateway.rs         # UDP gateway, session dispatch
│   ├── neural.rs          # Neural Resonance module
│   ├── nat.rs             # NAT forwarder (IPv4 + IPv6 NAT66)
│   ├── client_db.rs       # Client database (roles, device binding, exit_node)
│   ├── mgmt_service.rs    # Shared REST + in-tunnel management dispatch
│   ├── audit_log.rs       # Tamper-evident hash-chain admin audit log
│   ├── pending_config.rs  # Apply-with-rollback (commit-confirm) for heavy config
│   ├── pool_sync.rs       # In-protocol pool synchronization
│   ├── pool_dialer.rs     # Masked pool-client transport (dial peers, exit routing)
│   └── pool_partition.rs  # Hard per-node VPN-IP partitioning
├── crates/aivpn-common/src/ssh_install.rs  # russh SSH-install client + embedded installer bundle
├── deploy/install-server.sh   # systemd-first server installer (##AIVPN progress markers)
├── platforms/android/         # Android Kotlin app
├── platforms/ios/             # iOS SwiftUI app + NEPacketTunnelProvider
├── crates/aivpn-windows/      # Windows egui GUI
├── platforms/macos/           # macOS SwiftUI menu bar app
├── mask-assets/           # Bundled traffic mimicry profiles (JSON)
├── deploy/docker/             # Dockerfiles and entrypoint
├── Dockerfile
├── docker-compose.yml
└── THREAT_MODEL.md
```

---

## License

MIT — see [LICENSE](LICENSE).
