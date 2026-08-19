#!/usr/bin/env bash
# aivpn-server installer — Wave C1b (Phase C, in-app SSH installer)
#
# Sets up aivpn-server on a fresh Linux VPS: detects the environment,
# checks the target port is free, fetches + verifies the release binary,
# generates keys/config, seeds mask profiles, installs a systemd unit,
# opens the firewall, optionally provisions a device-bound admin client,
# starts the service, and health-checks it.
#
# Every step prints one machine-readable line on stdout:
#
#   ##AIVPN {"step":"...","status":"ok|error|info","code":"...","msg":"..."}
#
# so a calling application (the in-app installer UI) can parse progress
# without scraping human-readable text. Extra fields (e.g. "raw" on
# errors, "connection_key" on success) are appended as additional
# "key":"value" pairs on the same line.
#
# This script is meant to be readable top-to-bottom before you run it —
# review it (or run --show-script / --print-sha256 first), then run as
# root:
#
#   sudo bash deploy/install-server.sh --device-pubkey <base64> \
#       --server-ip vpn.example.com:443
#
# Full flag/env-var reference: run with --help.
#
# Design notes:
#  - Idempotent: re-running is an upgrade. server.key and clients.json are
#    NEVER overwritten; the binary and systemd unit are always replaced;
#    the service is restarted at the end.
#  - The config template (deploy/config/server.json.example) and the
#    systemd unit template (deploy/systemd/aivpn-server.service) are read
#    from this script's own directory — run it from a full repo checkout
#    (or ship the whole deploy/ directory alongside it). Only the SERVER
#    BINARY itself is fetched over HTTP/HTTPS, from a URL you control via
#    --binary-url / $AIVPN_BINARY_BASE_URL.
#  - Masks are NOT optional: aivpn-server refuses client connections with
#    an empty mask directory. This script treats "no masks available" as
#    a hard failure, unless the mask directory was already populated by a
#    previous run (upgrade path).

set -euo pipefail

# ─── Constants / defaults ───────────────────────────────────────────────────

SCRIPT_VERSION="1.0.0"
DEFAULT_REPO_SLUG="infosave2007/aivpn"
DEFAULT_BINARY_BASE_URL="https://github.com/${DEFAULT_REPO_SLUG}/releases/latest/download"

BIN_PATH="/usr/local/bin/aivpn-server"
UNIT_DST="/etc/systemd/system/aivpn-server.service"

INSTALL_MODE="${AIVPN_INSTALL_MODE:-systemd}"
PORT="${AIVPN_PORT:-443}"
LISTEN_ADDR="${AIVPN_LISTEN:-}"

BINARY_BASE_URL="${AIVPN_BINARY_BASE_URL:-$DEFAULT_BINARY_BASE_URL}"
BINARY_FILE=""
MASKS_URL="${AIVPN_MASKS_URL:-}"
MASKS_DIR_OVERRIDE=""

DEVICE_PUBKEY="${AIVPN_DEVICE_PUBKEY:-}"
PUBLIC_SERVER_IP="${AIVPN_PUBLIC_SERVER_IP:-}"
ADMIN_NAME="${AIVPN_ADMIN_NAME:-admin}"

CONFIG_PATH="/etc/aivpn/server.json"
KEY_FILE="/etc/aivpn/server.key"
CLIENTS_DB="/etc/aivpn/clients.json"
MASK_DIR="/var/lib/aivpn/masks"
MGMT_SOCKET="/run/aivpn/api.sock"
AUDIT_LOG="/var/log/aivpn/audit.log"

SKIP_FIREWALL=0
SKIP_DEPS=0

CURRENT_STEP="init"
ADMIN_CONNECTION_KEY=""
SERVER_CMD=("$BIN_PATH")

# ─── stdout markers ─────────────────────────────────────────────────────────

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Escape a string for use as the REPLACEMENT of a sed s#...#...# command
# (delimiter '#'): '\', '&' (expands to the whole match) and '#' (would end
# the expression early) are special there and must be backslash-escaped.
sed_escape_replacement() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//&/\\&}"
    s="${s//#/\\#}"
    printf '%s' "$s"
}

# emit_marker STEP STATUS CODE MSG [KEY VALUE]...
# STATUS is one of: ok | error | info
emit_marker() {
    local step="$1" status="$2" code="$3" msg="$4"
    shift 4
    local json
    json="{\"step\":\"$(json_escape "$step")\",\"status\":\"$(json_escape "$status")\",\"code\":\"$(json_escape "$code")\",\"msg\":\"$(json_escape "$msg")\""
    while [ "$#" -ge 2 ]; do
        json="${json},\"$(json_escape "$1")\":\"$(json_escape "$2")\""
        shift 2
    done
    json="${json}}"
    printf '##AIVPN %s\n' "$json"
}

on_error() {
    local ec=$?
    emit_marker "$CURRENT_STEP" "error" "unexpected_failure" \
        "installer failed at step '${CURRENT_STEP}' (exit code ${ec})"
    exit "$ec"
}
trap on_error ERR

# ─── self-inspection (--show-script / --print-sha256) ──────────────────────

self_source_path() {
    local self="${BASH_SOURCE[0]:-$0}"
    if [ -f "$self" ]; then
        printf '%s' "$self"
        return 0
    fi
    return 1
}

show_script() {
    local self
    if self="$(self_source_path)"; then
        cat "$self"
    else
        echo "error: cannot show script source — it was executed via stdin/pipe (e.g. curl | bash)." >&2
        echo "Download it to a file first: curl -fsSL <url> -o install-server.sh && bash install-server.sh --show-script" >&2
        exit 1
    fi
}

print_sha256() {
    local self
    if self="$(self_source_path)"; then
        sha256sum "$self" | awk '{print $1}'
    else
        echo "error: cannot self-hash — it was executed via stdin/pipe (e.g. curl | bash)." >&2
        echo "Download it to a file first: curl -fsSL <url> -o install-server.sh && bash install-server.sh --print-sha256" >&2
        exit 1
    fi
}

print_help() {
    cat <<EOF
aivpn-server installer v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

Installs and starts aivpn-server natively under systemd (default) or via
Docker Compose (--mode docker). Idempotent — safe to re-run to upgrade.

  --mode systemd|docker      Install mode (default: systemd; env AIVPN_INSTALL_MODE)
  --port PORT                UDP listen port (default: 443; env AIVPN_PORT)
  --listen HOST:PORT         Full listen address, overrides --port (env AIVPN_LISTEN)

  --binary-url URL           Base URL to fetch aivpn-server-linux-<arch> (+.SHA256SUMS) from.
                              Default: ${DEFAULT_BINARY_BASE_URL}
                              (env AIVPN_BINARY_BASE_URL)
  --binary-file PATH         Use a local binary instead of downloading (e.g. scp'd ahead of
                              time). If PATH.SHA256SUMS exists next to it, it is verified too.
  --masks-url URL            URL to a masks.tar.gz to seed /var/lib/aivpn/masks from, used
                              only when no local mask source is found. Default:
                              <binary-url>/masks.tar.gz (env AIVPN_MASKS_URL)
  --masks-dir PATH           Local directory of *.json mask files to seed from (overrides
                              auto-detection of the repo's bundled assets/masks/).

  --device-pubkey BASE64     Base64 X25519 device public key. When set, an admin client is
                              created (or, on re-run, its existing connection key is re-read)
                              and printed in the final "done" marker as "connection_key".
                              (env AIVPN_DEVICE_PUBKEY)
  --server-ip HOST[:PORT]    Public host[:port] embedded into the generated connection key.
                              Required together with --device-pubkey. (env AIVPN_PUBLIC_SERVER_IP)
  --admin-name NAME          Name for the auto-provisioned admin client (default: admin;
                              env AIVPN_ADMIN_NAME)

  --config PATH               (default: ${CONFIG_PATH})
  --key-file PATH              (default: ${KEY_FILE})
  --clients-db PATH            (default: ${CLIENTS_DB})
  --mask-dir PATH               (default: ${MASK_DIR})
  --management-socket PATH        (default: ${MGMT_SOCKET})
  --audit-log PATH                (default: ${AUDIT_LOG})

  --skip-firewall             Do not touch any firewall.
  --skip-deps                 Do not install OS packages (assume they're already present).

  --show-script                Print this script's own source and exit (no root needed).
  --print-sha256               Print this script's own sha256sum and exit (no root needed).
  -h, --help                   Show this help and exit.

Notes:
  - Must be run as root (except --help / --show-script / --print-sha256).
  - Expects to run from this repo's deploy/ directory (or a full checkout) so it can find
    deploy/config/server.json.example and deploy/systemd/aivpn-server.service alongside it.
  - Masks are mandatory: aivpn-server will not accept any connection with an empty mask
    directory. This script fetches/copies mask profiles and hard-fails if none end up
    present (unless a previous run already populated the mask directory).
EOF
}

# ─── environment detection ──────────────────────────────────────────────────

SCRIPT_DIR=""
BUNDLED_MASKS_DIR=""

detect_script_dir() {
    local self
    if self="$(self_source_path)"; then
        SCRIPT_DIR="$(cd "$(dirname "$self")" && pwd)"
        if [ -d "$SCRIPT_DIR/../assets/masks" ]; then
            BUNDLED_MASKS_DIR="$(cd "$SCRIPT_DIR/../assets/masks" && pwd)"
        fi
    fi
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        emit_marker "preflight" "error" "root_required" \
            "this installer must be run as root (e.g. sudo bash $0 ...)"
        exit 1
    fi
}

is_systemd() {
    [ -d /run/systemd/system ]
}

detect_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then echo apt
    elif command -v dnf >/dev/null 2>&1; then echo dnf
    elif command -v yum >/dev/null 2>&1; then echo yum
    elif command -v pacman >/dev/null 2>&1; then echo pacman
    elif command -v apk >/dev/null 2>&1; then echo apk
    elif command -v zypper >/dev/null 2>&1; then echo zypper
    else echo none
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        *) echo unsupported ;;
    esac
}

detect_environment() {
    CURRENT_STEP="detect_env"
    local pkg_mgr arch systemd_str already="no"
    pkg_mgr="$(detect_pkg_mgr)"
    arch="$(detect_arch)"
    if is_systemd; then systemd_str="yes"; else systemd_str="no"; fi
    if [ -x "$BIN_PATH" ] || { command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^aivpn-server\.service'; }; then
        already="yes"
    fi
    emit_marker "detect_env" "info" "detected" \
        "pkg_mgr=${pkg_mgr} arch=${arch} systemd=${systemd_str} already_installed=${already}"
}

# ─── port pre-check ─────────────────────────────────────────────────────────

port_precheck() {
    CURRENT_STEP="port_check"
    local port="$1"
    local service_active=0

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet aivpn-server 2>/dev/null; then
        service_active=1
    fi

    if ! command -v ss >/dev/null 2>&1; then
        if [ "$service_active" -eq 1 ]; then
            emit_marker "port_check" "ok" "upgrade" \
                "an aivpn-server.service is already active on this host; ss (iproute2) is unavailable so the requested port ${port}/udp cannot be verified — proceeding as an upgrade"
        else
            emit_marker "port_check" "info" "ss_missing" \
                "ss (iproute2) not found; skipping pre-flight port check"
        fi
        return 0
    fi

    local hit
    hit="$(ss -H -lunp "sport = :${port}" 2>/dev/null || true)"
    if [ -z "$hit" ]; then
        if [ "$service_active" -eq 1 ]; then
            emit_marker "port_check" "ok" "upgrade" \
                "an aivpn-server.service is already active on this host; requested port ${port}/udp is free, proceeding as an upgrade"
        else
            emit_marker "port_check" "ok" "port_free" "port ${port}/udp is free"
        fi
        return 0
    fi

    local proc pid
    proc="$(printf '%s' "$hit" | grep -oP 'users:\(\("\K[^"]+' 2>/dev/null | head -1 || true)"
    pid="$(printf '%s' "$hit" | grep -oP 'pid=\K[0-9]+' 2>/dev/null | head -1 || true)"

    # The port may legitimately be held by aivpn-server itself (upgrade of
    # our own service on the same port) — check that before treating any
    # occupant as a conflict, even when a service is already active.
    local occupant_is_us=0
    if [ "$proc" = "aivpn-server" ]; then
        occupant_is_us=1
    elif [ "$service_active" -eq 1 ] && [ -n "$pid" ]; then
        local main_pid
        main_pid="$(systemctl show -p MainPID --value aivpn-server 2>/dev/null || true)"
        if [ -n "$main_pid" ] && [ "$main_pid" != "0" ] && [ "$main_pid" = "$pid" ]; then
            occupant_is_us=1
        fi
    fi

    if [ "$occupant_is_us" -eq 1 ]; then
        emit_marker "port_check" "ok" "upgrade" \
            "port ${port}/udp is held by aivpn-server's own running instance (pid ${pid:-?}); proceeding as an upgrade"
        return 0
    fi

    emit_marker "port_check" "error" "port_busy" \
        "port ${port}/udp busy (pid ${pid:-?}/proc ${proc:-unknown})" \
        "raw" "$hit"
    exit 1
}

# ─── dependency install ─────────────────────────────────────────────────────

install_deps() {
    CURRENT_STEP="install_deps"
    if [ "$SKIP_DEPS" -eq 1 ]; then
        emit_marker "install_deps" "info" "skipped" "dependency installation skipped (--skip-deps)"
        return 0
    fi

    local mgr
    mgr="$(detect_pkg_mgr)"
    case "$mgr" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y >/dev/null 2>&1 || true
            apt-get install -y iproute2 iptables nftables ca-certificates openssl curl >/dev/null 2>&1 \
                || apt-get install -y iproute2 iptables ca-certificates openssl curl >/dev/null 2>&1 \
                || true
            ;;
        dnf)
            dnf install -y iproute iptables nftables ca-certificates openssl curl >/dev/null 2>&1 || true
            ;;
        yum)
            yum install -y iproute iptables nftables ca-certificates openssl curl >/dev/null 2>&1 || true
            ;;
        pacman)
            pacman -Sy --noconfirm --needed iproute2 iptables nftables ca-certificates openssl curl >/dev/null 2>&1 || true
            ;;
        apk)
            apk add --no-cache iproute2 iptables nftables ca-certificates openssl curl >/dev/null 2>&1 || true
            ;;
        zypper)
            zypper --non-interactive install iproute2 iptables nftables ca-certificates openssl curl >/dev/null 2>&1 || true
            ;;
        none)
            emit_marker "install_deps" "info" "unknown_pkg_mgr" \
                "no supported package manager found; ensure iproute2, iptables/nftables, ca-certificates, openssl and curl are installed"
            return 0
            ;;
    esac
    emit_marker "install_deps" "ok" "$mgr" "runtime dependencies installed via $mgr"
}

ensure_tun_device() {
    CURRENT_STEP="tun_device"
    modprobe tun >/dev/null 2>&1 || true
    if [ ! -e /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200 2>/dev/null || true
        chmod 600 /dev/net/tun 2>/dev/null || true
    fi
    if [ -e /dev/net/tun ]; then
        emit_marker "tun_device" "ok" "present" "/dev/net/tun is present"
    else
        emit_marker "tun_device" "error" "missing" \
            "/dev/net/tun could not be created — the TUN kernel module may be missing/disabled (try: modprobe tun)"
        exit 1
    fi
}

# ─── binary fetch + verify + install ────────────────────────────────────────

fetch_and_install_binary() {
    CURRENT_STEP="fetch_binary"
    local arch asset tmpdir
    arch="$(detect_arch)"
    if [ "$arch" = "unsupported" ]; then
        emit_marker "fetch_binary" "error" "unsupported_arch" \
            "unsupported CPU architecture: $(uname -m) (aivpn-server ships x86_64 and aarch64 builds)"
        exit 1
    fi
    asset="aivpn-server-linux-${arch}"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "'"$tmpdir"'"' RETURN

    if [ -n "$BINARY_FILE" ]; then
        if [ ! -f "$BINARY_FILE" ]; then
            emit_marker "fetch_binary" "error" "file_not_found" "--binary-file $BINARY_FILE not found"
            exit 1
        fi
        cp "$BINARY_FILE" "$tmpdir/$asset"
        if [ -f "${BINARY_FILE}.SHA256SUMS" ]; then
            cp "${BINARY_FILE}.SHA256SUMS" "$tmpdir/${asset}.SHA256SUMS"
        fi
        emit_marker "fetch_binary" "ok" "local_file" "using local binary override $BINARY_FILE"
    else
        emit_marker "fetch_binary" "info" "downloading" \
            "downloading ${asset} from ${BINARY_BASE_URL}"
        if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tmpdir/$asset" "${BINARY_BASE_URL}/${asset}"; then
            emit_marker "fetch_binary" "error" "download_failed" \
                "failed to download ${BINARY_BASE_URL}/${asset}"
            exit 1
        fi
        if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tmpdir/${asset}.SHA256SUMS" "${BINARY_BASE_URL}/${asset}.SHA256SUMS"; then
            emit_marker "fetch_binary" "error" "checksum_download_failed" \
                "failed to download ${BINARY_BASE_URL}/${asset}.SHA256SUMS"
            exit 1
        fi
    fi

    CURRENT_STEP="verify_binary"
    if [ -f "$tmpdir/${asset}.SHA256SUMS" ]; then
        if (cd "$tmpdir" && sha256sum -c "${asset}.SHA256SUMS" >/dev/null 2>&1); then
            emit_marker "verify_binary" "ok" "checksum_match" "SHA256 checksum verified for ${asset}"
        else
            emit_marker "verify_binary" "error" "checksum_mismatch" \
                "SHA256 checksum verification FAILED for ${asset} — aborting; the binary may be corrupted or tampered with"
            exit 1
        fi
    else
        emit_marker "verify_binary" "info" "no_checksum" \
            "no .SHA256SUMS available for ${asset} — skipping verification (not recommended for production)"
    fi

    CURRENT_STEP="install_binary"
    install -m 0755 "$tmpdir/$asset" "$BIN_PATH"
    emit_marker "install_binary" "ok" "installed" "aivpn-server installed to ${BIN_PATH}"
}

# ─── config / key / masks ───────────────────────────────────────────────────

seed_config() {
    CURRENT_STEP="seed_config"
    mkdir -p "$(dirname "$CONFIG_PATH")"
    if [ -f "$CONFIG_PATH" ]; then
        emit_marker "seed_config" "ok" "exists" "$CONFIG_PATH already exists, left untouched"
        return 0
    fi

    local template=""
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/config/server.json.example" ]; then
        template="$SCRIPT_DIR/config/server.json.example"
    fi
    if [ -z "$template" ]; then
        emit_marker "seed_config" "error" "template_missing" \
            "deploy/config/server.json.example not found next to this script; run from a full repo checkout or pass --config for an already-existing file"
        exit 1
    fi

    cp "$template" "$CONFIG_PATH"
    local listen_esc
    listen_esc="$(sed_escape_replacement "$LISTEN_ADDR")"
    sed -i "s#\"listen_addr\": *\"[^\"]*\"#\"listen_addr\": \"${listen_esc}\"#" "$CONFIG_PATH"
    chmod 644 "$CONFIG_PATH"
    emit_marker "seed_config" "ok" "created" "$CONFIG_PATH created from template (listen_addr=${LISTEN_ADDR})"
}

gen_key() {
    CURRENT_STEP="gen_key"
    mkdir -p "$(dirname "$KEY_FILE")"
    if [ -f "$KEY_FILE" ]; then
        emit_marker "gen_key" "ok" "exists" "$KEY_FILE already exists, left untouched"
        return 0
    fi
    (umask 077; head -c 32 /dev/urandom > "$KEY_FILE")
    chmod 600 "$KEY_FILE"
    emit_marker "gen_key" "ok" "generated" "$KEY_FILE generated (32 random bytes)"
}

seed_masks() {
    CURRENT_STEP="seed_masks"
    mkdir -p "$MASK_DIR"

    local source_dir="" copied=0 f base
    if [ -n "$MASKS_DIR_OVERRIDE" ]; then
        source_dir="$MASKS_DIR_OVERRIDE"
    elif [ -n "$BUNDLED_MASKS_DIR" ]; then
        source_dir="$BUNDLED_MASKS_DIR"
    fi

    if [ -n "$source_dir" ] && [ -d "$source_dir" ]; then
        for f in "$source_dir"/*.json; do
            [ -f "$f" ] || continue
            base="$(basename "$f")"
            if [ ! -f "$MASK_DIR/$base" ]; then
                cp "$f" "$MASK_DIR/$base"
                copied=$((copied + 1))
            fi
        done
        emit_marker "seed_masks" "ok" "local_copy" \
            "seeded ${copied} mask file(s) into ${MASK_DIR} from ${source_dir}"
    else
        local url="${MASKS_URL:-${BINARY_BASE_URL}/masks.tar.gz}"
        local mtmp
        mtmp="$(mktemp -d)"
        if curl -fsSL --retry 2 --retry-delay 2 -o "$mtmp/masks.tar.gz" "$url" 2>/dev/null; then
            tar -xzf "$mtmp/masks.tar.gz" -C "$mtmp" 2>/dev/null || true
            while IFS= read -r -d '' f; do
                base="$(basename "$f")"
                if [ ! -f "$MASK_DIR/$base" ]; then
                    cp "$f" "$MASK_DIR/$base"
                    copied=$((copied + 1))
                fi
            done < <(find "$mtmp" -maxdepth 3 -name '*.json' -print0)
            emit_marker "seed_masks" "ok" "remote_fetch" \
                "seeded ${copied} mask file(s) into ${MASK_DIR} from ${url}"
        else
            emit_marker "seed_masks" "info" "remote_unavailable" \
                "no local mask source found and ${url} was unreachable"
        fi
        rm -rf "$mtmp"
    fi

    local final_count
    final_count="$(find "$MASK_DIR" -maxdepth 1 -name '*.json' | wc -l)"
    if [ "$final_count" -eq 0 ]; then
        emit_marker "seed_masks" "error" "no_masks" \
            "no mask profiles present in ${MASK_DIR} — aivpn-server refuses connections without at least one mask; pass --masks-dir <path> or ensure ${BINARY_BASE_URL}/masks.tar.gz is reachable"
        exit 1
    fi
    emit_marker "seed_masks" "ok" "present" "${final_count} mask profile(s) present in ${MASK_DIR}"
}

# ─── systemd unit ────────────────────────────────────────────────────────────

install_systemd_unit() {
    CURRENT_STEP="install_systemd_unit"
    local unit_src=""
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/systemd/aivpn-server.service" ]; then
        unit_src="$SCRIPT_DIR/systemd/aivpn-server.service"
    else
        emit_marker "install_systemd_unit" "error" "unit_template_missing" \
            "deploy/systemd/aivpn-server.service not found next to this script; run from a full repo checkout"
        exit 1
    fi

    local esc_listen esc_config esc_keyfile esc_clients esc_maskdir esc_mgmt esc_audit esc_binpath
    esc_listen="$(sed_escape_replacement "$LISTEN_ADDR")"
    esc_config="$(sed_escape_replacement "$CONFIG_PATH")"
    esc_keyfile="$(sed_escape_replacement "$KEY_FILE")"
    esc_clients="$(sed_escape_replacement "$CLIENTS_DB")"
    esc_maskdir="$(sed_escape_replacement "$MASK_DIR")"
    esc_mgmt="$(sed_escape_replacement "$MGMT_SOCKET")"
    esc_audit="$(sed_escape_replacement "$AUDIT_LOG")"
    esc_binpath="$(sed_escape_replacement "$BIN_PATH")"

    sed \
        -e "s#__AIVPN_LISTEN__#${esc_listen}#g" \
        -e "s#__AIVPN_CONFIG__#${esc_config}#g" \
        -e "s#__AIVPN_KEYFILE__#${esc_keyfile}#g" \
        -e "s#__AIVPN_CLIENTS_DB__#${esc_clients}#g" \
        -e "s#__AIVPN_MASKDIR__#${esc_maskdir}#g" \
        -e "s#__AIVPN_MGMT_SOCK__#${esc_mgmt}#g" \
        -e "s#__AIVPN_AUDITLOG__#${esc_audit}#g" \
        -e "s#__AIVPN_BINPATH__#${esc_binpath}#g" \
        "$unit_src" > "$UNIT_DST"

    chmod 644 "$UNIT_DST"
    systemctl daemon-reload
    systemctl enable aivpn-server >/dev/null 2>&1 || true
    emit_marker "install_systemd_unit" "ok" "installed" "${UNIT_DST} installed and enabled (listen=${LISTEN_ADDR})"
}

enable_ip_forward() {
    CURRENT_STEP="ip_forward"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    local conf="/etc/sysctl.d/99-aivpn-forward.conf"
    if [ ! -f "$conf" ] || ! grep -q "net.ipv4.ip_forward" "$conf" 2>/dev/null; then
        printf 'net.ipv4.ip_forward = 1\n' > "$conf"
        sysctl -p "$conf" >/dev/null 2>&1 || true
    fi
    emit_marker "ip_forward" "ok" "enabled" "net.ipv4.ip_forward=1 (persisted in ${conf})"
}

# ─── firewall ────────────────────────────────────────────────────────────────

firewall_open_port() {
    CURRENT_STEP="firewall"
    local port="$1"

    if [ "$SKIP_FIREWALL" -eq 1 ]; then
        emit_marker "firewall" "info" "skipped" "firewall step skipped (--skip-firewall)"
        return 0
    fi

    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${port}/udp" >/dev/null 2>&1 || true
        emit_marker "firewall" "ok" "ufw" "opened ${port}/udp via ufw"
        return 0
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        emit_marker "firewall" "ok" "firewalld" "opened ${port}/udp via firewalld"
        return 0
    fi

    if command -v nft >/dev/null 2>&1; then
        nft add table inet aivpn 2>/dev/null || true
        nft add chain inet aivpn input '{ type filter hook input priority 0 ; }' 2>/dev/null || true
        # Idempotency: only add the accept rule if it is not already present
        # (the iptables branch below does the same via -C). Match the rule as
        # nft renders it ("udp dport <port> accept"); the port is numeric, so
        # a fixed-string grep is safe.
        if ! nft list chain inet aivpn input 2>/dev/null | grep -qF "udp dport ${port} accept"; then
            nft add rule inet aivpn input udp dport "${port}" accept 2>/dev/null || true
        fi
        emit_marker "firewall" "ok" "nftables" "opened ${port}/udp via nftables"
        return 0
    fi

    if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p udp --dport "${port}" -j ACCEPT 2>/dev/null \
            || iptables -I INPUT -p udp --dport "${port}" -j ACCEPT
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        fi
        emit_marker "firewall" "ok" "iptables" "opened ${port}/udp via iptables"
        return 0
    fi

    emit_marker "firewall" "info" "none_found" \
        "no supported firewall manager found (ufw/firewalld/nftables/iptables); ensure ${port}/udp is reachable from the internet"
}

# ─── admin client provisioning ──────────────────────────────────────────────

create_admin_client() {
    CURRENT_STEP="create_admin_client"
    if [ -z "$DEVICE_PUBKEY" ]; then
        emit_marker "create_admin_client" "info" "skipped" \
            "no --device-pubkey supplied, skipping auto-admin client creation"
        return 0
    fi
    if [ -z "$PUBLIC_SERVER_IP" ]; then
        emit_marker "create_admin_client" "error" "missing_server_ip" \
            "--device-pubkey was given but --server-ip (public host[:port]) was not; cannot generate a connection key"
        exit 1
    fi

    local out rc=0 mode="created"
    out="$("${SERVER_CMD[@]}" --add-client "$ADMIN_NAME" --role admin \
        --device-pubkey "$DEVICE_PUBKEY" --server-ip "$PUBLIC_SERVER_IP" \
        --config "$CONFIG_PATH" --key-file "$KEY_FILE" --clients-db "$CLIENTS_DB" 2>&1)" || rc=$?

    if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi "already exists"; then
        # Idempotent re-run: the admin client was already provisioned by a
        # previous install. Re-derive its existing connection key instead
        # of treating this as a failure.
        mode="existing"
        rc=0
        out="$("${SERVER_CMD[@]}" --show-client "$ADMIN_NAME" --server-ip "$PUBLIC_SERVER_IP" \
            --config "$CONFIG_PATH" --key-file "$KEY_FILE" --clients-db "$CLIENTS_DB" 2>&1)" || rc=$?
    fi

    if [ "$rc" -ne 0 ]; then
        emit_marker "create_admin_client" "error" "add_client_failed" \
            "aivpn-server client provisioning failed" "raw" "$out"
        exit 1
    fi

    ADMIN_CONNECTION_KEY="$(printf '%s\n' "$out" | grep -o 'aivpn://[A-Za-z0-9_=-]*' | head -1 || true)"
    if [ -z "$ADMIN_CONNECTION_KEY" ]; then
        emit_marker "create_admin_client" "error" "key_not_found" \
            "admin client step completed but no aivpn:// connection key was found in the output" "raw" "$out"
        exit 1
    fi
    emit_marker "create_admin_client" "ok" "$mode" "admin client '${ADMIN_NAME}' connection key ready"
}

# ─── health check ───────────────────────────────────────────────────────────

health_check() {
    CURRENT_STEP="health_check"
    local tries=0 max=15 active=""
    while [ "$tries" -lt "$max" ]; do
        if systemctl is-active --quiet aivpn-server; then
            active=1
            break
        fi
        tries=$((tries + 1))
        sleep 1
    done
    if [ -z "$active" ]; then
        local logs
        logs="$(journalctl -u aivpn-server -n 30 --no-pager 2>/dev/null | tr '\n' '|')"
        emit_marker "health_check" "error" "service_not_active" \
            "aivpn-server.service did not become active within ${max}s" "raw" "$logs"
        exit 1
    fi

    tries=0
    local listening="" ss_hit=""
    while [ "$tries" -lt 10 ]; do
        if command -v ss >/dev/null 2>&1; then
            ss_hit="$(ss -H -lunp "sport = :${PORT}" 2>/dev/null || true)"
            if [ -n "$ss_hit" ]; then
                listening=1
                break
            fi
        fi
        tries=$((tries + 1))
        sleep 1
    done
    if [ -z "$listening" ]; then
        emit_marker "health_check" "error" "port_not_listening" \
            "aivpn-server.service is active but is not listening on ${PORT}/udp yet"
        exit 1
    fi

    # A listener on the port is not enough — confirm it is aivpn-server
    # itself, not some other process that happens to be squatting the port
    # (the ss(8) output includes process info because of -p).
    local owner_ok=0 main_pid
    main_pid="$(systemctl show -p MainPID --value aivpn-server 2>/dev/null || true)"
    if printf '%s' "$ss_hit" | grep -q '"aivpn-server"'; then
        owner_ok=1
    elif [ -n "$main_pid" ] && [ "$main_pid" != "0" ] && printf '%s' "$ss_hit" | grep -q "pid=${main_pid}"; then
        owner_ok=1
    fi
    if [ "$owner_ok" -eq 0 ]; then
        emit_marker "health_check" "error" "port_owned_by_other" \
            "${PORT}/udp is occupied but not by aivpn-server (expected pid ${main_pid:-?}); another process is squatting the port" \
            "raw" "$ss_hit"
        exit 1
    fi

    emit_marker "health_check" "ok" "healthy" "aivpn-server.service is active and listening on ${PORT}/udp"
}

final_marker() {
    CURRENT_STEP="done"
    if [ -n "$ADMIN_CONNECTION_KEY" ]; then
        emit_marker "done" "ok" "installed" "aivpn-server installed and running on ${LISTEN_ADDR}" \
            "connection_key" "$ADMIN_CONNECTION_KEY"
    else
        emit_marker "done" "ok" "installed" "aivpn-server installed and running on ${LISTEN_ADDR}"
    fi
}

# ─── docker mode (secondary path) ───────────────────────────────────────────
#
# Thinner path: the repo's docker-compose.yml + deploy/docker/docker-entrypoint.sh
# already seed config/key/masks into the mounted ./deploy/config and ./masks
# directories on first container start, so this mode does not duplicate that
# logic — it just brings the container up and (optionally) provisions the
# admin client inside it.

require_docker_compose() {
    if ! command -v docker >/dev/null 2>&1; then
        emit_marker "docker_mode" "error" "docker_missing" \
            "docker not found; install Docker Engine or re-run with --mode systemd"
        exit 1
    fi
    if docker compose version >/dev/null 2>&1; then
        DC=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        DC=(docker-compose)
    else
        emit_marker "docker_mode" "error" "compose_missing" \
            "neither 'docker compose' nor 'docker-compose' is available"
        exit 1
    fi
}

run_docker_mode() {
    CURRENT_STEP="docker_mode"
    local DC=()
    require_docker_compose

    local repo_root=""
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/../docker-compose.yml" ]; then
        repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"
    fi
    if [ -z "$repo_root" ]; then
        emit_marker "docker_mode" "error" "compose_file_missing" \
            "docker-compose.yml not found next to this script; --mode docker requires a full repo checkout (git clone https://github.com/${DEFAULT_REPO_SLUG})"
        exit 1
    fi

    emit_marker "docker_mode" "info" "starting" \
        "building and starting aivpn-server via docker compose in ${repo_root}"
    if ! (cd "$repo_root" && "${DC[@]}" up -d --build aivpn-server); then
        emit_marker "docker_mode" "error" "compose_up_failed" "docker compose up failed for aivpn-server"
        exit 1
    fi
    emit_marker "docker_mode" "ok" "started" \
        "aivpn-server container is up (config/key/masks auto-seeded by the container entrypoint into ${repo_root}/deploy/config and ${repo_root}/masks)"

    SERVER_CMD=("${DC[@]}" exec -T aivpn-server aivpn-server)
    create_admin_client

    CURRENT_STEP="health_check"
    sleep 2
    if (cd "$repo_root" && "${DC[@]}" ps aivpn-server 2>/dev/null | grep -qi "up\|running"); then
        emit_marker "health_check" "ok" "healthy" "aivpn-server container is running"
    else
        emit_marker "health_check" "error" "container_not_running" "aivpn-server container did not report as running"
        exit 1
    fi

    final_marker
}

# ─── arg parsing ─────────────────────────────────────────────────────────────

need_arg() {
    if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
        emit_marker "preflight" "error" "missing_value" "option $1 requires a value"
        exit 1
    fi
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --*=*)
                set -- "${1%%=*}" "${1#*=}" "${@:2}"
                continue
                ;;
        esac
        case "$1" in
            -h|--help) print_help; exit 0 ;;
            --show-script) show_script; exit 0 ;;
            --print-sha256) print_sha256; exit 0 ;;
            --mode) need_arg "$@"; INSTALL_MODE="$2"; shift 2 ;;
            --port) need_arg "$@"; PORT="$2"; shift 2 ;;
            --listen) need_arg "$@"; LISTEN_ADDR="$2"; shift 2 ;;
            --binary-url) need_arg "$@"; BINARY_BASE_URL="$2"; shift 2 ;;
            --binary-file) need_arg "$@"; BINARY_FILE="$2"; shift 2 ;;
            --masks-url) need_arg "$@"; MASKS_URL="$2"; shift 2 ;;
            --masks-dir) need_arg "$@"; MASKS_DIR_OVERRIDE="$2"; shift 2 ;;
            --device-pubkey) need_arg "$@"; DEVICE_PUBKEY="$2"; shift 2 ;;
            --server-ip) need_arg "$@"; PUBLIC_SERVER_IP="$2"; shift 2 ;;
            --admin-name) need_arg "$@"; ADMIN_NAME="$2"; shift 2 ;;
            --config) need_arg "$@"; CONFIG_PATH="$2"; shift 2 ;;
            --key-file) need_arg "$@"; KEY_FILE="$2"; shift 2 ;;
            --clients-db) need_arg "$@"; CLIENTS_DB="$2"; shift 2 ;;
            --mask-dir) need_arg "$@"; MASK_DIR="$2"; shift 2 ;;
            --management-socket) need_arg "$@"; MGMT_SOCKET="$2"; shift 2 ;;
            --audit-log) need_arg "$@"; AUDIT_LOG="$2"; shift 2 ;;
            --skip-firewall) SKIP_FIREWALL=1; shift ;;
            --skip-deps) SKIP_DEPS=1; shift ;;
            *)
                emit_marker "preflight" "error" "unknown_flag" "unknown option: $1 (see --help)"
                exit 1
                ;;
        esac
    done
}

resolve_listen() {
    if [ -z "$LISTEN_ADDR" ]; then
        LISTEN_ADDR="0.0.0.0:${PORT}"
    else
        PORT="${LISTEN_ADDR##*:}"
    fi
}

# ─── main ────────────────────────────────────────────────────────────────────

main() {
    detect_script_dir
    parse_args "$@"
    resolve_listen
    BIN_PATH="/usr/local/bin/aivpn-server"
    SERVER_CMD=("$BIN_PATH")

    emit_marker "start" "info" "begin" \
        "aivpn-server installer v${SCRIPT_VERSION} starting (mode=${INSTALL_MODE}, listen=${LISTEN_ADDR})"

    if [ "$INSTALL_MODE" = "docker" ]; then
        require_root
        run_docker_mode
        return 0
    fi

    if [ "$INSTALL_MODE" != "systemd" ]; then
        emit_marker "preflight" "error" "unknown_mode" "unknown --mode '${INSTALL_MODE}' (expected systemd or docker)"
        exit 1
    fi

    require_root
    detect_environment

    if ! is_systemd; then
        emit_marker "detect_env" "error" "no_systemd" \
            "PID 1 is not systemd on this host; re-run with --mode docker, or install systemd"
        exit 1
    fi

    port_precheck "$PORT"
    install_deps
    ensure_tun_device

    CURRENT_STEP="create_dirs"
    mkdir -p /etc/aivpn "$MASK_DIR" /var/log/aivpn /run/aivpn
    emit_marker "create_dirs" "ok" "ready" "/etc/aivpn, ${MASK_DIR}, /var/log/aivpn, /run/aivpn ready"

    fetch_and_install_binary
    seed_config
    gen_key
    seed_masks
    install_systemd_unit
    enable_ip_forward
    firewall_open_port "$PORT"

    CURRENT_STEP="start_service"
    systemctl restart aivpn-server
    emit_marker "start_service" "ok" "restarted" "aivpn-server.service (re)started"

    create_admin_client
    health_check
    final_marker
}

main "$@"
