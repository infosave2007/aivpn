#!/bin/sh
set -e

if [ -z "${AIVPN_KEY}" ]; then
    echo "[aivpn-mikrotik] ERROR: AIVPN_KEY environment variable is required" >&2
    echo "[aivpn-mikrotik] Set it in the RouterOS container envlist:" >&2
    echo "[aivpn-mikrotik]   /container/envs/add list=aivpn-env name=AIVPN_KEY value=\"aivpn://...\"" >&2
    exit 1
fi

if ! (exec 3>/dev/net/tun) 2>/dev/null; then
    echo "[aivpn-mikrotik] ERROR: Cannot open /dev/net/tun — ensure cap=net-admin is set and the tun module is loaded" >&2
    exit 1
fi

# Enable IP forwarding and set up NAT for gateway mode
# LAN_IF: container-side LAN interface for FORWARD rules (default eth0)
LAN_IF="${LAN_IF:-eth0}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
iptables -t nat -C POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE || true
iptables -C FORWARD -i "${LAN_IF}" -o tun0 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${LAN_IF}" -o tun0 -j ACCEPT || true
iptables -C FORWARD -i tun0 -o "${LAN_IF}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i tun0 -o "${LAN_IF}" -m state --state RELATED,ESTABLISHED -j ACCEPT || true

# Optional: full tunnel mode. Default: false (gateway mode — RouterOS handles routing).
# Set AIVPN_FULL_TUNNEL=true only for client-mode containers.
FULL_TUNNEL="${AIVPN_FULL_TUNNEL:-false}"

echo "[aivpn-mikrotik] Starting aivpn-client (full-tunnel=${FULL_TUNNEL})"

# Client crashes must not kill the restart loop (script runs under set -e),
# so capture the exit status explicitly.
while true; do
    rc=0
    if [ "${FULL_TUNNEL}" = "true" ]; then
        /usr/local/bin/aivpn-client --connection-key "${AIVPN_KEY}" --full-tunnel || rc=$?
    else
        /usr/local/bin/aivpn-client --connection-key "${AIVPN_KEY}" || rc=$?
    fi
    echo "[aivpn-mikrotik] aivpn-client exited (rc=${rc}), restarting in 5s..."
    sleep 5
done
