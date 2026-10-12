"""Target and port-specification parsing.

Supports IPs, hostnames, CIDR ranges (``10.0.0.0/24``), short ranges
(``192.168.1.1-20``) and nmap-style port specs (``22,80,1-1000``, ``top100``,
``all``).
"""

from __future__ import annotations

import ipaddress
import re
import socket

from .constants import TOP_PORTS
from .services import SERVICE_NAMES

_NAME_TO_PORT = {}
for _port, _name in SERVICE_NAMES.items():
    _NAME_TO_PORT.setdefault(_name, _port)


def parse_ports(spec: str | None) -> list[int]:
    """Turn a port specification string into a sorted list of ports."""
    if spec is None or not spec.strip():
        return sorted(set(TOP_PORTS))

    spec = spec.strip().lower()
    if spec in ("default", "curated"):
        return sorted(set(TOP_PORTS))
    if spec in ("all", "-", "*", "full"):
        return list(range(1, 65536))
    if spec in ("top100", "fast"):
        return sorted(set(TOP_PORTS[:100]))
    if spec.startswith("top"):
        try:
            n = int(spec[3:])
            if n <= len(TOP_PORTS):
                return sorted(set(TOP_PORTS[:n]))
            return list(range(1, min(n, 65535) + 1))
        except ValueError:
            pass

    ports: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            ports.update(range(max(1, start), min(65535, end) + 1))
        elif chunk.isdigit():
            port = int(chunk)
            if 1 <= port <= 65535:
                ports.add(port)
        elif chunk in _NAME_TO_PORT:
            ports.add(_NAME_TO_PORT[chunk])
    return sorted(ports)


_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})$")
_FULL_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")


def parse_targets(tokens: list[str], max_hosts: int = 1024) -> list[str]:
    """Expand target tokens into a list of IPs or hostnames."""
    hosts: list[str] = []
    for raw in tokens:
        token = raw.strip()
        if not token:
            continue
        try:
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                if network.num_addresses > max_hosts + 2:
                    raise ValueError(
                        f"{token} contiene {network.num_addresses} direcciones "
                        f"(máximo {max_hosts}). Dividí el rango."
                    )
                hosts.extend(str(h) for h in network.hosts())
                continue
            match = _RANGE_RE.match(token)
            if match:
                base, end = match.groups()
                prefix = base.rsplit(".", 1)[0]
                start = int(base.rsplit(".", 1)[1])
                hosts.extend(f"{prefix}.{i}" for i in range(start, int(end) + 1))
                continue
            if _FULL_RANGE_RE.match(token):
                start_s, end_s = token.split("-")
                start = int(ipaddress.IPv4Address(start_s))
                end = int(ipaddress.IPv4Address(end_s))
                hosts.extend(str(ipaddress.IPv4Address(i)) for i in range(start, end + 1))
                continue
        except ValueError as exc:
            raise SystemExit(f"Objetivo inválido '{token}': {exc}") from exc
        hosts.append(token)
    seen = set()
    ordered = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            ordered.append(h)
    return ordered


def resolve(host: str) -> tuple[str, str | None]:
    """Resolve *host* to ``(ip, hostname_or_None)``."""
    try:
        return socket.gethostbyname(host), (host if not _is_ip(host) else None)
    except socket.gaierror as exc:
        raise SystemExit(f"No se pudo resolver '{host}': {exc}") from exc


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
