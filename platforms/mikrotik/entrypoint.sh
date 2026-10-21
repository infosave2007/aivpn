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
TUN_IF="${AIVPN_TUN_NAME:-tun0}"
case "$TUN_IF" in
    ''|*[!a-zA-Z0-9_.-]*) echo '[aivpn-mikrotik] Недопустимое имя TUN' >&2; exit 1 ;;
esac
[ "${#TUN_IF}" -le 15 ] || { echo '[aivpn-mikrotik] Имя TUN длиннее 15 байт' >&2; exit 1; }
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -C POSTROUTING -o "$TUN_IF" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$TUN_IF" -j MASQUERADE
iptables -C FORWARD -i "${LAN_IF}" -o "$TUN_IF" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${LAN_IF}" -o "$TUN_IF" -j ACCEPT
iptables -C FORWARD -i "$TUN_IF" -o "${LAN_IF}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$TUN_IF" -o "${LAN_IF}" -m state --state RELATED,ESTABLISHED -j ACCEPT

# RouterOS направляет пакет в контейнер, а контейнер должен направить его в TUN.
FULL_TUNNEL="${AIVPN_FULL_TUNNEL:-true}"
case "$FULL_TUNNEL" in true|false) ;; *) echo '[aivpn-mikrotik] Ожидается true или false' >&2; exit 1 ;; esac

echo "[aivpn-mikrotik] Starting aivpn-client (full-tunnel=${FULL_TUNNEL})"

# Client crashes must not kill the restart loop (script runs under set -e),
# so capture the exit status explicitly.
export AIVPN_CONNECTION_KEY="$AIVPN_KEY"
unset AIVPN_KEY
while true; do
    rc=0
    if [ "${FULL_TUNNEL}" = "true" ]; then
        /usr/local/bin/aivpn-client --tun-name "$TUN_IF" --full-tunnel || rc=$?
    else
        /usr/local/bin/aivpn-client --tun-name "$TUN_IF" || rc=$?
    fi
    echo "[aivpn-mikrotik] aivpn-client exited (rc=${rc}), restarting in 5s..."
    sleep 5
done
