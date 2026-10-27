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
for interface in "$TUN_IF" "$LAN_IF"; do
    case "$interface" in
        ''|[!a-zA-Z0-9]*|*[!a-zA-Z0-9_.-]*) echo '[aivpn-mikrotik] Недопустимое имя интерфейса' >&2; exit 1 ;;
    esac
    [ "${#interface}" -le 15 ] || { echo '[aivpn-mikrotik] Имя интерфейса длиннее 15 байт' >&2; exit 1; }
done
[ "$TUN_IF" != "$LAN_IF" ] || { echo '[aivpn-mikrotik] LAN и TUN должны различаться' >&2; exit 1; }
KILL_SWITCH="${AIVPN_KILL_SWITCH:-false}"
case "$KILL_SWITCH" in true|false) ;; *) echo '[aivpn-mikrotik] Ожидается true или false для kill-switch' >&2; exit 1 ;; esac
if [ "$KILL_SWITCH" = true ]; then
    for firewall in iptables ip6tables; do
        "$firewall" -C FORWARD -i "$LAN_IF" ! -o "$TUN_IF" -j DROP 2>/dev/null ||
            "$firewall" -I FORWARD 1 -i "$LAN_IF" ! -o "$TUN_IF" -j DROP
    done
fi
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
stopping=0
child_pid=""
stop_service() {
    stopping=1
    [ -z "$child_pid" ] || kill -TERM "$child_pid" 2>/dev/null || true
}
trap stop_service TERM INT
while [ "$stopping" = 0 ]; do
    set -- --tun-name "$TUN_IF"
    [ "$FULL_TUNNEL" = false ] || set -- "$@" --full-tunnel
    [ "$KILL_SWITCH" = false ] || set -- "$@" --kill-switch
    /usr/local/bin/aivpn-client "$@" &
    child_pid=$!
    rc=0
    wait "$child_pid" || rc=$?
    if [ "$stopping" = 1 ]; then
        wait "$child_pid" 2>/dev/null || true
        break
    fi
    child_pid=""
    echo "[aivpn-mikrotik] aivpn-client exited (rc=${rc}), restarting in 5s..."
    sleep 5 &
    child_pid=$!
    rc=0
    wait "$child_pid" || rc=$?
    child_pid=""
    [ "$stopping" = 0 ] || break
    [ "$rc" = 0 ] || exit "$rc"
done
