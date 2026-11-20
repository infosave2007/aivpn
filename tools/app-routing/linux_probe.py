#!/usr/bin/env python3
"""Проверяет сетевые предпосылки app-split в отдельном одноразовом KVM guest."""

import argparse
from functools import partial
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time


RESULTS = []


def require_guest(need_root=True):
    marker = Path("/lab/.app-routing-guest")
    if ((need_root and os.getuid() != 0) or not marker.is_file()
            or marker.read_text() != "aivpn-offline-routing-lab\n"
            or "aivpn.app-routing-lab=1" not in Path("/proc/cmdline").read_text().split()):
        raise SystemExit("Сетевые пробы разрешены только внутри отдельного тестового guest")


def command(args, **kwargs):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, **kwargs)
    except subprocess.CalledProcessError as error:
        print(error.output, flush=True)
        raise


def record(name, ok, **details):
    result = {"name": name, "ok": bool(ok), **details}
    RESULTS.append(result)
    print("AIVPN_RESULT " + json.dumps(result), flush=True)
    if not ok:
        raise AssertionError(name)


def dns_answer(query, address):
    end = 12
    while query[end]:
        end += query[end] + 1
    end += 5
    if query[end - 4:end - 2] != b"\x00\x01":
        return None
    reply = bytearray(query[:end])
    reply[2:4] = b"\x81\x80"
    reply[6:8] = b"\x00\x01"
    reply[8:12] = b"\x00" * 4
    reply += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04"
    reply += socket.inet_aton(address)
    return bytes(reply)


def make_endpoints():
    endpoints = {}
    for family, address, port, role in [
        (socket.AF_INET, "198.18.0.53", 9999, "echo4"),
        (socket.AF_INET6, "fd99::53", 9999, "echo6"),
        (socket.AF_INET, "192.0.2.53", 53, "system_dns"),
        (socket.AF_INET, "198.18.0.53", 53, "vpn_dns"),
    ]:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, port))
        endpoints[sock] = role
    for family, address in [(socket.AF_INET, "198.18.0.53"), (socket.AF_INET6, "fd99::53")]:
        sock = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, 9999))
        sock.listen(8)
        endpoints[sock] = "tcp_echo"
    return endpoints


def server():
    endpoints = make_endpoints()
    print(json.dumps({"ready": True}), flush=True)
    while True:
        readable, _, _ = select.select(list(endpoints), [], [], 10)
        for sock in readable:
            if endpoints[sock] == "tcp_echo":
                connection, peer = sock.accept()
                with connection:
                    connection.settimeout(1)
                    data = connection.recv(4096)
                    print(json.dumps({"role": "tcp_echo", "peer": peer[0], "label": data.decode()}), flush=True)
                    connection.sendall(data)
                continue
            data, peer = sock.recvfrom(4096)
            role = endpoints[sock]
            label = data.decode(errors="replace") if role.startswith("echo") else "DNS"
            print(json.dumps({"role": role, "peer": peer[0], "label": label}), flush=True)
            answer = data
            if role.endswith("dns"):
                answer = dns_answer(data, "203.0.113.7" if role == "system_dns" else "198.51.100.7")
            if answer is not None:
                try:
                    sock.sendto(answer, peer)
                except OSError:
                    pass


def client(family, label, source, tcp=False):
    sock = socket.socket(socket.AF_INET if family == "4" else socket.AF_INET6,
                         socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    if source:
        sock.bind((source, 0))
    target = "198.18.0.53" if family == "4" else "fd99::53"
    try:
        if tcp:
            sock.connect((target, 9999))
            sock.sendall(label.encode())
        else:
            sock.sendto(label.encode(), (target, 9999))
        echoed = sock.recv(4096) == label.encode()
    except OSError:
        echoed = False
    print(json.dumps({"source": sock.getsockname()[0], "echo": echoed, "uid": os.getuid()}), flush=True)
    sock.close()


def enter_group(group, uid=None):
    def enter():
        if group is not None:
            Path(group, "cgroup.procs").write_text(str(os.getpid()))
        if uid is not None:
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
    return enter


def configure_network():
    require_guest()
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "netns", "add", "peer"])
    command(["ip", "-n", "peer", "link", "set", "lo", "up"])
    for local, remote, address, peer_address, address6, peer6 in [
        ("wan0", "wan_s", "192.0.2.2/24", "192.0.2.1/24", "2001:db8:1::2/64", "2001:db8:1::1/64"),
        ("vpn0", "vpn_s", "10.77.0.2/24", "10.77.0.1/24", "fd77::2/64", "fd77::1/64"),
    ]:
        command(["ip", "link", "add", local, "type", "veth", "peer", "name", remote])
        command(["ip", "link", "set", remote, "netns", "peer"])
        command(["ip", "addr", "add", address, "dev", local])
        command(["ip", "-6", "addr", "add", address6, "dev", local, "nodad"])
        command(["ip", "link", "set", local, "up"])
        command(["ip", "-n", "peer", "addr", "add", peer_address, "dev", remote])
        command(["ip", "-n", "peer", "-6", "addr", "add", peer6, "dev", remote, "nodad"])
        command(["ip", "-n", "peer", "link", "set", remote, "up"])
    for address in ["192.0.2.53/32", "198.18.0.53/32"]:
        command(["ip", "-n", "peer", "addr", "add", address, "dev", "lo"])
    command(["ip", "-n", "peer", "-6", "addr", "add", "fd99::53/128", "dev", "lo", "nodad"])
    command(["ip", "route", "add", "default", "via", "192.0.2.1", "dev", "wan0"])
    command(["ip", "-6", "route", "add", "default", "via", "2001:db8:1::1", "dev", "wan0"])
    for family, gateway in [("-4", "10.77.0.1"), ("-6", "fd77::1")]:
        command(["ip", family, "route", "add", "table", "200", "default", "via", gateway, "dev", "vpn0"])
        command(["ip", family, "rule", "add", "pref", "100", "fwmark", "0xa1", "lookup", "200"])
    for item in Path("/proc/sys/net/ipv4/conf").glob("*/rp_filter"):
        item.write_text("0")
    group = Path("/sys/fs/cgroup/aivpn-selected")
    group.mkdir()
    command(["socket_mark", str(group), "0xa1"])
    record("bpf_attached", True)
    return group


def start_endpoint():
    packets = []
    ready = threading.Event()
    peer = subprocess.Popen(["ip", "netns", "exec", "peer", "python3", __file__, "--server"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def observe():
        for line in peer.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            packets.append(event)
            if event.get("ready"):
                ready.set()

    threading.Thread(target=observe, daemon=True).start()
    assert ready.wait(5), "UDP endpoint не запустился"

    return peer, packets


def send(label, family, marked, source="", tcp=False, *, group, packets):
    output = command(["python3", __file__, "--client", family, label, "--source", source] + (["--tcp"] if tcp else []),
                     preexec_fn=enter_group(group if marked else None, 1000))
    result = json.loads(output)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        seen = next((item for item in packets if item.get("label") == label), None)
        if seen:
            return result, seen
        time.sleep(0.01)
    raise AssertionError("На сервере нет пакета " + label)



def source_probes(send):
    for family, vpn_ip in [("4", "10.77.0.2"), ("6", "fd77::2")]:
        result, seen = send("early-" + family, family, True)
        record("early_mark_source_" + family, seen["peer"] == vpn_ip and result["echo"] and result["uid"] == 1000,
               peer_source=seen["peer"], **result)
        result, seen = send("tcp-early-" + family, family, True, tcp=True)
        record("early_mark_tcp_" + family, seen["peer"] == vpn_ip and result["echo"], peer_source=seen["peer"], **result)
    command(["nft", "-f", "-"], input="table inet late {\n chain out {\n type route hook output priority mangle; policy accept;\n meta mark set 0xa1\n }\n}\n")
    result, seen = send("late-4", "4", False)
    record("late_mark_retains_physical_source", seen["peer"] == "192.0.2.2", peer_source=seen["peer"])
    command(["nft", "delete", "table", "inet", "late"])
    for family, source in [("4", "192.0.2.2"), ("6", "2001:db8:1::2")]:
        result, seen = send("bound-" + family, family, True, source)
        record("bound_physical_source_" + family, seen["peer"] == source, peer_source=seen["peer"])
    command(["nft", "-f", "-"], input="table inet vpn_nat {\n chain post {\n type nat hook postrouting priority srcnat; policy accept;\n oifname \"vpn0\" meta mark 0xa1 ip saddr 192.0.2.2 snat ip to 10.77.0.2\n oifname \"vpn0\" meta mark 0xa1 ip6 saddr 2001:db8:1::2 snat ip6 to fd77::2\n }\n}\n")
    for family, source, assigned in [("4", "192.0.2.2", "10.77.0.2"), ("6", "2001:db8:1::2", "fd77::2")]:
        result, seen = send("nat-" + family, family, True, source)
        record("scoped_nat_roundtrip_" + family, seen["peer"] == assigned and result["echo"], peer_source=seen["peer"])
        result, seen = send("tcp-nat-" + family, family, True, source, tcp=True)
        record("scoped_nat_tcp_" + family, seen["peer"] == assigned and result["echo"], peer_source=seen["peer"])


def failure_probes(group, packets, send):
    for family, system_ip in [("4", "192.0.2.2"), ("6", "2001:db8:1::2")]:
        command(["ip", "-" + family, "route", "add", "table", "200", "unreachable", "default", "metric", "32760"])
        command(["ip", "-" + family, "route", "delete", "table", "200", "default", "dev", "vpn0"])
        failed = json.loads(command(["python3", __file__, "--client", family, "blocked-" + family, "--tcp"],
                                    preexec_fn=enter_group(group, 1000)))
        record("missing_vpn_route_is_blocked_" + family, not failed["echo"] and
               not any(item.get("label") == "blocked-" + family for item in packets))
        result, seen = send("system-survives-" + family, family, False, tcp=True)
        record("system_path_survives_vpn_failure_" + family, result["echo"] and seen["peer"] == system_ip)
        gateway = "10.77.0.1" if family == "4" else "fd77::1"
        command(["ip", "-" + family, "route", "add", "table", "200", "default", "via", gateway, "dev", "vpn0"])


def main():
    group = configure_network()
    peer, packets = start_endpoint()
    traffic = partial(send, group=group, packets=packets)
    source_probes(traffic)
    failure_probes(group, packets, traffic)
    try:
        dns_probes(group)
    except Exception:
        for path in [Path("/lab/resolved.log"), Path("/lab/dbus.log")]:
            if path.exists():
                print(path.name + ":\n" + path.read_text(), flush=True)
        print("Observed packets: " + json.dumps(packets), flush=True)
        raise
    peer.terminate()
    peer.wait(timeout=2)
    print("AIVPN_SUMMARY " + json.dumps({"checks": RESULTS}), flush=True)


def start_resolver():
    runtime = Path("/run/systemd/resolve")
    runtime.mkdir(parents=True)
    os.chown(runtime, 976, 976)
    Path("/run/dbus").mkdir()
    Path("/lab/dbus.conf").write_text('<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    Path("/etc/systemd/resolved.conf").write_text("[Resolve]\nDNS=192.0.2.53\nFallbackDNS=\nDomains=~.\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\nCache=no\nDNSStubListener=yes\n")
    Path("/etc/resolv.conf").write_text("nameserver 127.0.0.53\n")
    bus_log = open("/lab/dbus.log", "w")
    resolved_log = open("/lab/resolved.log", "w")
    bus = subprocess.Popen(["dbus-daemon", "--config-file=/lab/dbus.conf", "--nofork"], stdout=bus_log, stderr=subprocess.STDOUT)
    environment = os.environ | {"SYSTEMD_LOG_LEVEL": "debug"}
    resolved = subprocess.Popen(["/usr/lib/systemd/systemd-resolved"], stdout=resolved_log, stderr=subprocess.STDOUT, env=environment)
    bus_log.close()
    resolved_log.close()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not Path("/run/systemd/resolve/io.systemd.Resolve").exists():
        if resolved.poll() is not None:
            print(Path("/lab/resolved.log").read_text(), flush=True)
            raise RuntimeError("systemd-resolved завершился при запуске")
        time.sleep(0.02)
    return bus, resolved


def dns_probes(group):
    command(["nft", "-f", "-"], input='table inet dns_audit {\n counter system_dns {}\n chain out {\n type filter hook output priority filter; policy accept;\n oifname "wan0" udp dport 53 counter name system_dns\n }\n}\n')

    def system_queries():
        output = json.loads(command(["nft", "-j", "list", "counter", "inet", "dns_audit", "system_dns"]))
        return next(item["counter"]["packets"] for item in output["nftables"] if "counter" in item)

    bus, resolved = start_resolver()
    for subject, marked in [("selected", True), ("ordinary", False)]:
        output = command(["getent", "ahostsv4", subject + ".aivpn.test"], timeout=5,
                         preexec_fn=enter_group(group) if marked else None)
        record("shared_dns_context_" + subject, "203.0.113.7" in output, answer=output.split()[0],
               required_answer="198.51.100.7" if marked else "203.0.113.7")
    Path("/lab/resolv-vpn.conf").write_text("nameserver 198.18.0.53\n")
    output = command(["unshare", "-nm", "python3", __file__, "--isolated-dns"], timeout=5,
                     preexec_fn=enter_group(group))
    record("resolv_conf_does_not_isolate_nss_resolve", "203.0.113.7" in output,
           answer=output.split()[0], required_answer="198.51.100.7")
    record("dns_packets_owned_by_shared_service", system_queries() >= 3)
    command(["ip", "route", "add", "198.18.0.53/32", "via", "10.77.0.1", "dev", "vpn0"])
    command(["resolvectl", "dns", "vpn0", "198.18.0.53"])
    command(["resolvectl", "default-route", "vpn0", "no"])
    scoped_environment = os.environ | {"SYSTEMD_NSS_RESOLVE_INTERFACE": "vpn0"}
    probe = subprocess.run(["getent", "ahostsv4", "scoped.aivpn.test"], timeout=5,
                           env=scoped_environment, preexec_fn=enter_group(group), capture_output=True, text=True)
    record("nss_ifindex_without_resolver_scope_is_rejected", probe.returncode != 0,
           reason="Отрицательная проба относится к этой конфигурации resolver scope")
    output = command(["getent", "ahostsv4", "control.aivpn.test"], timeout=5)
    record("ordinary_nss_keeps_system_dns", "203.0.113.7" in output, answer=output.split()[0])
    broker_probes(group, system_queries)
    print("AIVPN_DNS_GATE " + json.dumps({"direct_classification": False, "resolv_conf_only": False,
          "nss_ifindex_requires_configured_scope": True, "caller_aware_managed_nss": True,
          "reason": "Общий резолвер не наследует контекст сокетов вызывающего приложения"}), flush=True)
    resolved.terminate()
    bus.terminate()
    resolved.wait(timeout=2)
    bus.wait(timeout=2)


def broker_probes(group, system_queries):
    from dns_context import start
    Path("/run/aivpn").mkdir()
    Path("/lab/nsswitch-protected.conf").write_text("passwd: files\ngroup: files\nhosts: files resolve\n")
    listener, context = start("/run/aivpn/resolve", "/aivpn-selected")
    os.chown("/run/aivpn/resolve", 1000, 1000)
    os.chmod("/run/aivpn/resolve", 0o600)
    for malformed in [b"{\0", b"x" * 65537 + b"\0"]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect("/run/aivpn/resolve")
            connection.sendall(malformed)
            connection.shutdown(socket.SHUT_WR)
            connection.recv(1)
    selected = command(["unshare", "-m", "python3", __file__, "--mediated-dns"], timeout=5,
                       preexec_fn=enter_group(group))
    ordinary = command(["getent", "ahostsv4", "same.aivpn.test"], timeout=5)
    record("caller_aware_dns_separates_identical_names", "198.51.100.7" in selected and "203.0.113.7" in ordinary,
           selected=selected.split()[0], ordinary=ordinary.split()[0])
    record("caller_identity_is_from_kernel", context["requests"][0]["selected"] and context["requests"][0]["uid"] == 1000,
           peer_pid=context["requests"][0]["pid"], peer_uid=context["requests"][0]["uid"])
    before = system_queries()
    dbus = json.loads(command(["unshare", "-m", "python3", __file__, "--mediated-dbus", "--guarded-nss"],
                             timeout=5, preexec_fn=enter_group(group)))
    addresses = [item[2] for item in dbus["data"][0]]
    record("dbus_dns_bypasses_managed_nss_context", [203, 0, 113, 7] in addresses and system_queries() > before)
    record("malformed_nss_requests_do_not_kill_broker", context["rejected"] == 2)
    before = system_queries()
    context["ready"] = False
    denied = subprocess.run(["unshare", "-m", "python3", __file__, "--mediated-dns"], timeout=5,
                            preexec_fn=enter_group(group), capture_output=True, text=True)
    after = system_queries()
    record("unavailable_vpn_dns_has_no_system_fallback", denied.returncode != 0 and after == before)
    output = command(["getent", "ahostsv4", "still-working.aivpn.test"], timeout=5)
    record("ordinary_dns_survives_vpn_dns_failure", "203.0.113.7" in output)
    context["stop"] = True
    listener.shutdown(socket.SHUT_RDWR)
    listener.close()
    unguarded = command(["unshare", "-m", "python3", __file__, "--mediated-dns"], timeout=5,
                        preexec_fn=enter_group(group))
    record("dead_broker_requires_nss_fallback_guard", "203.0.113.7" in unguarded,
           observed_answer=unguarded.split()[0])
    before = system_queries()
    denied = subprocess.run(["unshare", "-m", "python3", __file__, "--mediated-dns", "--guarded-nss"],
                            timeout=5, preexec_fn=enter_group(group), capture_output=True, text=True)
    after = system_queries()
    record("dead_broker_has_no_system_dns_fallback_with_guard", denied.returncode != 0 and before == after)
    output = command(["getent", "ahostsv4", "ordinary-after-broker.aivpn.test"], timeout=5)
    record("ordinary_dns_survives_broker_death", "203.0.113.7" in output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", action="store_true")
    parser.add_argument("--client", nargs=2)
    parser.add_argument("--source", default="")
    parser.add_argument("--tcp", action="store_true")
    parser.add_argument("--isolated-dns", action="store_true")
    parser.add_argument("--mediated-dns", action="store_true")
    parser.add_argument("--mediated-dbus", action="store_true")
    parser.add_argument("--guarded-nss", action="store_true")
    args = parser.parse_args()
    require_guest(need_root=not args.client)
    if args.server:
        server()
    elif args.client:
        client(*args.client, args.source, args.tcp)
    elif args.isolated_dns:
        command(["mount", "--bind", "/lab/resolv-vpn.conf", "/etc/resolv.conf"])
        command(["ip", "link", "add", "isolated0", "type", "dummy"])
        command(["ip", "addr", "add", "10.88.0.2/24", "dev", "isolated0"])
        command(["ip", "link", "set", "isolated0", "up"])
        print(command(["getent", "ahostsv4", "isolated.aivpn.test"], timeout=3), end="")
    elif args.mediated_dns or args.mediated_dbus:
        command(["mount", "--bind", "/run/aivpn/resolve", "/run/systemd/resolve/io.systemd.Resolve"])
        if args.guarded_nss:
            command(["mount", "--bind", "/lab/nsswitch-protected.conf", "/etc/nsswitch.conf"])
        query = ["getent", "ahostsv4", "same.aivpn.test"]
        if args.mediated_dbus:
            query = ["busctl", "--json=short", "call", "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                     "org.freedesktop.resolve1.Manager", "ResolveHostname", "isit", "0", "dbus.aivpn.test", "2", "0"]
        print(command(query, timeout=3, preexec_fn=enter_group(None, 1000)), end="")
    else:
        main()
