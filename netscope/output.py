"""Renderers for the different output formats: text, JSON, XML and grep."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime

from .constants import (
    BOLD,
    CYAN,
    DIM,
    GRAY,
    GREEN,
    LEVEL_COLOR,
    LEVEL_ORDER,
    RED,
    RESET,
    WHITE,
    YELLOW,
)
from .models import Finding, ScanReport

_CATEGORY_COLOR = {
    "web": GREEN,
    "database": YELLOW,
    "remote": RED,
    "mail": CYAN,
    "file": YELLOW,
    "infra": CYAN,
    "other": WHITE,
}


def _c(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def all_findings(report: ScanReport) -> list[tuple[str, Finding]]:
    """Return ``(ip, finding)`` pairs sorted by severity."""
    out: list[tuple[str, Finding]] = []
    for host in report.hosts:
        for port in host.ports:
            for finding in port.findings:
                out.append((host.ip, finding))
    out.sort(key=lambda pair: LEVEL_ORDER.get(pair[1].level, 9))
    return out


def render_text(report: ScanReport, color: bool = True, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(_c(f"  Netscope {report.version} — report", BOLD + CYAN, color))
    lines.append(_c(f"  Objetivos: {', '.join(report.targets)}", GRAY, color))
    lines.append("")

    for host in report.hosts:
        name = f" ({host.hostname})" if host.hostname else ""
        header = f"  {host.ip}{name}"
        lines.append(_c(header, BOLD + WHITE, color))
        if host.state == "down":
            lines.append(_c("  Host parece caído (sin respuesta a discovery).", YELLOW, color))
            lines.append("")
            continue
        if host.latency_ms is not None:
            osc = f" · OS: {host.os_hint}" if host.os_hint else ""
            lines.append(_c(f"  Host is up · conexión en {host.latency_ms} ms{osc}", GRAY, color))

        if not host.ports:
            lines.append(_c("  No se encontraron puertos abiertos.", YELLOW, color))
            lines.append("")
            continue

        lines.append("")
        lines.append(_c(f"  {'PORT':<13}{'STATE':<7}{'SERVICE':<15}VERSION", GRAY, color))
        lines.append(_c("  " + "─" * 66, GRAY, color))
        for port in host.ports:
            color_c = _CATEGORY_COLOR.get(port.category, WHITE)
            port_label = f"{port.port}/{port.proto}"
            version = " ".join(x for x in (port.product, port.version) if x).strip()
            extra = ""
            if port.http and port.http.get("title"):
                extra = f'— HTTP {port.http.get("status")} "{port.http["title"]}"'
            elif port.http and port.http.get("status"):
                extra = f'— HTTP {port.http.get("status")}'
            elif port.tls and port.tls.get("version"):
                extra = f"— {port.tls['version']}"
            version = f"{version} {extra}".strip()
            lines.append(
                f"  {_c(f'{port_label:<13}', BOLD + color_c, color)}"
                f"{_c(f'{port.state:<7}', GREEN, color)}"
                f"{_c(f'{port.service:<15}', color_c, color)}"
                f"{_c(version, GRAY, color)}"
            )
            if verbose and port.banner:
                lines.append(_c(f"    banner: {port.banner[:120]}", DIM, color))
            if port.tls:
                tls = port.tls
                lines.append(_c(
                    f"    tls: {tls.get('version')} · {tls.get('cipher')}"
                    + (f" · CN={tls.get('subject')}" if tls.get("subject") else "")
                    + (f" · expira {tls.get('not_after')}" if tls.get("not_after") else ""),
                    DIM, color))

        findings = sorted(host.ports, key=lambda p: p.port)
        host_findings: list[tuple[str, Finding]] = []
        for port in findings:
            label = f"{port.port}/{port.proto}"
            host_findings.extend((label, f) for f in port.findings)
        if host_findings:
            lines.append("")
            lines.append(_c("  Hallazgos:", BOLD, color))
            for label, finding in sorted(host_findings,
                                         key=lambda p: LEVEL_ORDER.get(p[1].level, 9)):
                sev_color = LEVEL_COLOR.get(finding.level, WHITE)
                tag = _c(f"[{finding.level}]", BOLD + sev_color, color)
                lines.append(f"  {tag} {_c(label, DIM, color)} {finding.title}")
                if finding.detail:
                    lines.append(_c(f"      {finding.detail}", GRAY, color))
                for ref in finding.refs:
                    lines.append(_c(f"      ↳ {ref}", DIM, color))
        lines.append("")

    stats = report.stats
    summary = (
        f"  Netscope done: {stats.get('open_ports', 0)} open ports on "
        f"{stats.get('hosts_up', 0)} host(s) · scanned in {report.elapsed:.2f}s"
    )
    lines.append(_c(summary, BOLD + CYAN, color))

    risk = _risk_summary(report)
    if risk:
        parts = [f"{_c(level, LEVEL_COLOR[level], color)}={count}"
                 for level, count in risk]
        lines.append(_c("  Riesgos: " + "  ".join(parts), GRAY, color))
    lines.append("")
    return "\n".join(lines)


def _risk_summary(report: ScanReport) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for _, finding in all_findings(report):
        counts[finding.level] = counts.get(finding.level, 0) + 1
    return [(lvl, counts[lvl]) for lvl in LEVEL_ORDER if lvl in counts]


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_grep(report: ScanReport) -> str:
    lines = []
    for host in report.hosts:
        name = host.hostname or ""
        ports = []
        for port in host.ports:
            version = " ".join(x for x in (port.product, port.version) if x)
            ports.append("/".join([
                str(port.port), port.state, port.proto, "", port.service, "", version, "",
            ]))
        lines.append(f"Host: {host.ip} ({name})\tPorts: {', '.join(ports)}")
    return "\n".join(lines)


def render_xml(report: ScanReport) -> str:
    root = ET.Element("nmaprun", {
        "scanner": report.tool,
        "version": report.version,
        "args": report.command,
        "start": str(int(report.started)),
    })
    for host in report.hosts:
        host_el = ET.SubElement(root, "host", {"state": host.state})
        ET.SubElement(host_el, "address", {"addr": host.ip, "addrtype": "ipv4"})
        if host.hostname:
            hostnames = ET.SubElement(host_el, "hostnames")
            ET.SubElement(hostnames, "hostname", {"name": host.hostname})
        ports_el = ET.SubElement(host_el, "ports")
        for port in host.ports:
            port_el = ET.SubElement(ports_el, "port", {
                "protocol": port.proto,
                "portid": str(port.port),
            })
            ET.SubElement(port_el, "state", {"state": port.state, "reason": "syn-ack"})
            svc_el = ET.SubElement(port_el, "service", {"name": port.service})
            if port.product:
                svc_el.set("product", port.product)
            if port.version:
                svc_el.set("version", port.version)
            for finding in port.findings:
                script = ET.SubElement(port_el, "script", {
                    "id": f"netscope-{finding.level.lower()}",
                    "output": f"{finding.title}. {finding.detail}".strip(),
                })
                if finding.refs:
                    script.set("refs", " ".join(finding.refs))
        if host.latency_ms is not None:
            ET.SubElement(host_el, "times", {"srtt": str(host.latency_ms)})
    ET.indent(root, space="  ")
    xml = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml


def render_summary_line(report: ScanReport) -> str:
    stats = report.stats
    when = datetime.fromtimestamp(report.finished).strftime("%Y-%m-%d %H:%M:%S")
    return (f"{stats.get('open_ports', 0)} open · {stats.get('hosts_up', 0)} up · "
            f"{report.elapsed:.2f}s · {when}")
