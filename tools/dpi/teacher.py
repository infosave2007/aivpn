"""Учитель nDPI 5: вердикт по целому PCAP, без сохранения адресов и кадров."""

from __future__ import annotations

import re
import subprocess

FLOW_RE = re.compile(
    r"\[proto: [0-9.]+/([^\]]+)\]\[Stack: ([^\]]+)\].*?"
    r"\[(?:Encrypted|ClearText)\]\[Confidence: ([^\]]+)\]"
)
RISK_RE = re.compile(r"\[Risk: ([^\]]+)\]")
RISK_NAME_RE = re.compile(r"\*\* ([^*]+?) \*\*")
VPN_TOKENS = (
    "OPENVPN",
    "WIREGUARD",
    "SOFTETHER",
    "NORDVPN",
    "EXPRESSVPN",
    "HOTSPOT SHIELD",
    "TOR",
    "OBFUSCATED",
    "ANONYMOUS SUBSCRIBER",
)


class FlowLabel:
    def __init__(self, proto: str, stack: str, confidence: str, risks: list[str]):
        self.proto = proto
        self.stack = stack
        self.confidence = confidence
        self.risks = risks

    def blob(self) -> str:
        return f"{self.proto} {self.stack}".upper()


def _risk_names(line: str) -> list[str]:
    match = RISK_RE.search(line)
    if not match:
        return []
    return [name.strip() for name in RISK_NAME_RE.findall(match.group(1))]


def parse_flows(text: str) -> list[FlowLabel]:
    flows: list[FlowLabel] = []
    for line in text.splitlines():
        match = FLOW_RE.search(line)
        if not match:
            continue
        flows.append(FlowLabel(match.group(1), match.group(2), match.group(3), _risk_names(line)))
    return flows


def detected_protocols(text: str) -> list[str]:
    lines = text.splitlines()
    names: list[str] = []
    started = False
    for line in lines:
        if line.startswith("Detected protocols:"):
            started = True
            continue
        if not started:
            continue
        if not line.strip() or line.startswith("Protocol statistics:"):
            break
        parts = line.split()
        if parts:
            names.append(parts[0])
    return names


def is_target(flow: FlowLabel) -> bool:
    blob = flow.blob()
    return "QUIC" in blob or "STUN" in blob


def is_unknown(flow: FlowLabel) -> bool:
    return flow.proto.upper() == "UNKNOWN" or flow.stack.upper() == "UNKNOWN"


def _token_present(blob: str, token: str) -> bool:
    return re.search(rf"\b{re.escape(token)}\b", blob) is not None


def is_vpn(flow: FlowLabel) -> bool:
    blob = f"{flow.blob()} {' '.join(flow.risks)}".upper()
    if _token_present(blob, "VPN"):
        return True
    return any(_token_present(blob, token) for token in VPN_TOKENS)


def _ndpi_failed(returncode: int) -> tuple[bool, str] | None:
    if returncode != 0:
        return False, f"nDPI завершился с кодом {returncode}"
    return None


def positive_ok(flows: list[FlowLabel], detected: list[str], returncode: int) -> tuple[bool, str]:
    failed = _ndpi_failed(returncode)
    if failed is not None:
        return failed
    if not flows:
        return False, "nDPI не увидел ни одного потока"
    if any(is_vpn(flow) for flow in flows):
        return False, "поток помечен как известный VPN"
    if not all(is_target(flow) and flow.confidence == "DPI" for flow in flows):
        brief = ", ".join(f"{flow.proto}/{flow.confidence}" for flow in flows)
        return False, f"нет QUIC/STUN с уверенностью DPI ({brief})"
    extra = [name for name in detected if name.upper() not in {"QUIC", "STUN"}]
    if extra:
        return False, "в сводке есть протокол кроме QUIC/STUN: " + ",".join(extra)
    return True, "QUIC/STUN, уверенность DPI"


def negative_ok(flows: list[FlowLabel], detected: list[str], returncode: int) -> tuple[bool, str]:
    failed = _ndpi_failed(returncode)
    if failed is not None:
        return failed
    if not flows:
        return False, "nDPI не увидел ни одного потока"
    if any(is_target(flow) for flow in flows):
        brief = ", ".join(flow.proto for flow in flows)
        return False, f"после порчи поток все еще целевой ({brief})"
    if any(name.upper() in {"QUIC", "STUN"} for name in detected):
        return False, "сводка nDPI все еще содержит QUIC или STUN"
    if all(is_unknown(flow) or is_vpn(flow) for flow in flows):
        brief = ", ".join(flow.proto for flow in flows)
        return True, f"учитель: {brief}"
    brief = ", ".join(f"{flow.proto}/{flow.confidence}" for flow in flows)
    return False, f"учитель узнал не-VPN протокол, отрицательная метка не ставится ({brief})"


def label_pcap(ndpi: str, path: str, timeout: float = 30.0) -> tuple[list[FlowLabel], list[str], int]:
    proc = subprocess.run(
        [ndpi, "-i", path, "-d", "-v", "2"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    text = proc.stdout or ""
    return parse_flows(text), detected_protocols(text), proc.returncode
