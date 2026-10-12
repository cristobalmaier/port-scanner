"""Offline risk knowledge base: version → CVE heuristics and static port risks.

This is *heuristic*, not authoritative. It maps banners we manage to fingerprint
to well-known vulnerabilities so a scan immediately highlights "interesting"
targets. Always confirm manually before reporting a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Finding

# ── Version comparison ──────────────────────────────────────────────────────


def version_tuple(version: str) -> tuple[int, ...]:
    """``"8.2p1"`` → ``(8, 2, 1)``; non-numeric parts are ignored."""
    return tuple(int(n) for n in re.findall(r"\d+", version or ""))


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    size = max(len(a), len(b))
    return (a + (0,) * (size - len(a)), b + (0,) * (size - len(b)))


def compare_versions(a: str, b: str) -> int:
    """Return -1, 0 or 1 comparing two version strings."""
    ta, tb = _pad(version_tuple(a), version_tuple(b))
    return (ta > tb) - (ta < tb)


@dataclass
class VulnRule:
    """A version-bounded CVE rule matched against a fingerprinted product."""

    product: re.Pattern
    cve: str
    severity: str
    title: str
    ref: str = ""
    version_min: str | None = None  # inclusive
    version_max: str | None = None  # inclusive
    version_eq: str | None = None

    def matches(self, product: str, version: str) -> bool:
        if not self.product.search(product or ""):
            return False
        if not version:
            # Product-only rules (e.g. "any Samba 3.x") still fire.
            return self.version_eq is None and self.version_min is None
        if self.version_eq is not None:
            return compare_versions(version, self.version_eq) == 0
        if self.version_min is not None and compare_versions(version, self.version_min) < 0:
            return False
        if self.version_max is not None and compare_versions(version, self.version_max) > 0:
            return False
        return True


def _re(expr: str) -> re.Pattern:
    return re.compile(expr, re.I)


# Curated, well-known, remotely-relevant vulnerabilities.
VULN_RULES: list[VulnRule] = [
    VulnRule(_re(r"vsftpd"), "CVE-2011-2523", "CRITICAL",
             "vsftpd 2.3.4 backdoor (smiley face)",
             "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
             version_eq="2.3.4"),
    VulnRule(_re(r"ProFTPD"), "CVE-2010-4221", "CRITICAL",
             "ProFTPD 1.3.3c buffer overflow / RCE",
             "https://nvd.nist.gov/vuln/detail/CVE-2010-4221",
             version_eq="1.3.3"),
    VulnRule(_re(r"^OpenSSH$|OpenSSH"), "CVE-2024-6387", "HIGH",
             "regreSSHion — OpenSSH unauth RCE (glibc)",
             "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
             version_min="8.5", version_max="9.7"),
    VulnRule(_re(r"Apache"), "CVE-2021-41773", "CRITICAL",
             "Apache httpd 2.4.49 path traversal / RCE",
             "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
             version_eq="2.4.49"),
    VulnRule(_re(r"Apache"), "CVE-2021-42013", "CRITICAL",
             "Apache httpd 2.4.50 path traversal / RCE",
             "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
             version_eq="2.4.50"),
    VulnRule(_re(r"Exim"), "CVE-2019-10149", "CRITICAL",
             "Exim 4.87-4.91 'Return of the WIZard' RCE",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-10149",
             version_min="4.87", version_max="4.91"),
    VulnRule(_re(r"Samba"), "CVE-2007-2447", "CRITICAL",
             "Samba 3.0.20-3.0.25 'username map script' RCE",
             "https://nvd.nist.gov/vuln/detail/CVE-2007-2447",
             version_min="3.0.20", version_max="3.0.25"),
    VulnRule(_re(r"UnrealIRCd"), "CVE-2010-2075", "CRITICAL",
             "UnrealIRCd 3.2.8.1 backdoor",
             "https://nvd.nist.gov/vuln/detail/CVE-2010-2075",
             version_eq="3.2.8.1"),
    VulnRule(_re(r"Elasticsearch"), "CVE-2015-1427", "CRITICAL",
             "Elasticsearch 1.4.0-1.4.2 Groovy sandbox RCE",
             "https://nvd.nist.gov/vuln/detail/CVE-2015-1427",
             version_min="1.4.0", version_max="1.4.2"),
    VulnRule(_re(r"nginx"), "CVE-2019-20372", "MEDIUM",
             "nginx < 1.17.7 request smuggling (error_page)",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-20372",
             version_max="1.17.6"),
    VulnRule(_re(r"Apache"), "CVE-2017-5638", "CRITICAL",
             "Struts 2 (Apache) OGNL RCE — check for Struts apps",
             "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
             version_eq="2.3.31"),
]


# ── Static risks that only depend on an open port ───────────────────────────
STATIC_PORT_FINDINGS: dict[int, Finding] = {
    23: Finding("CRITICAL", "Telnet expuesto",
                "Telnet transmite credenciales y datos en texto plano. Deshabilitar y usar SSH.",
                ["https://cwe.mitre.org/data/definitions/319.html"]),
    445: Finding("CRITICAL", "SMB expuesto",
                "SMB accesible. Riesgo de EternalBlue (MS17-010), relay y ransomware.",
                ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"]),
    139: Finding("HIGH", "NetBIOS/SMB legado",
                "NetBIOS session service expuesto (SMBv1 habitualmente habilitado).",
                []),
    3389: Finding("HIGH", "RDP expuesto a Internet",
                "RDP es objetivo de fuerza bruta y de BlueKeep (CVE-2019-0708).",
                ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"]),
    5900: Finding("HIGH", "VNC expuesto",
                "VNC suele tener autenticación débil o nula. Verificar tipo de seguridad.",
                []),
    512: Finding("HIGH", "rexec expuesto", "Servicio remoto legado sin cifrado.", []),
    513: Finding("HIGH", "rlogin expuesto", "Servicio remoto legado sin cifrado.", []),
    514: Finding("HIGH", "rsh expuesto", "Shell remota legada sin cifrado.", []),
    3306: Finding("MEDIUM", "MySQL accesible remotamente",
                "Una base de datos expuesta a la red amplía la superficie de ataque.",
                []),
    1433: Finding("MEDIUM", "MSSQL accesible remotamente",
                "Verificar autenticación y credenciales por defecto (sa).", []),
    5432: Finding("MEDIUM", "PostgreSQL accesible remotamente",
                "Revisar `pg_hba.conf` y credenciales débiles.", []),
    27017: Finding("CRITICAL", "MongoDB expuesto",
                 "MongoDB sin autenticación permite leer y borrar toda la base de datos.",
                 []),
    28017: Finding("HIGH", "MongoDB web status expuesto",
                 "Panel HTTP de MongoDB con información interna.", []),
    11211: Finding("HIGH", "Memcached expuesto",
                 "Memcached sin auth permite robar caché y amplificación DDoS (CVE-2018-1000115).",
                 ["https://nvd.nist.gov/vuln/detail/CVE-2018-1000115"]),
    2375: Finding("CRITICAL", "Docker API sin TLS",
                 "Docker daemon expuesto sin autenticación: control total del host.",
                 []),
    2376: Finding("HIGH", "Docker API con TLS",
                 "Verificar que exija autenticación por certificado de cliente.", []),
    2379: Finding("HIGH", "etcd expuesto",
                 "etcd suele contener secretos de Kubernetes.", []),
    6443: Finding("MEDIUM", "Kubernetes API expuesto",
                 "Revisar autenticación anónima (CVE-2018-1002105).",
                 ["https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"]),
    10250: Finding("HIGH", "Kubelet API expuesto",
                  "Kubelet puede permitir ejecución de comandos en los pods.", []),
    9200: Finding("HIGH", "Elasticsearch expuesto",
                 "Índices expuestos sin autenticación; posible fuga de datos.", []),
    6379: Finding("CRITICAL", "Redis expuesto",
                 "Redis sin contraseña permite escribir archivos y RCE (cron/SSH).",
                 ["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"]),
    873: Finding("MEDIUM", "rsync expuesto", "Módulos rsync mal configurados permiten leer/escribir ficheros.", []),
    111: Finding("MEDIUM", "rpcbind expuesto", "Enumera servicios RPC/NFS y facilita ataques.", []),
    2049: Finding("MEDIUM", "NFS expuesto", "Shares NFS sin `root_squash` permiten escalada.", []),
    21: Finding("MEDIUM", "FTP expuesto",
                "FTP sin cifrado. Verificar login anónimo y credenciales por defecto.",
                ["https://cwe.mitre.org/data/definitions/319.html"]),
    161: Finding("MEDIUM", "SNMP expuesto",
                "Comunidad pública (public/private) filtra mucha información del sistema.", []),
    25: Finding("LOW", "SMTP expuesto", "Verificar relay abierto y usuarios válidos (VRFY).", []),
    4455: Finding("MEDIUM", "Puerto no estándar", "", []),
}


def match_cves(product: str, version: str) -> list[Finding]:
    """Return findings for every CVE rule matched by product/version."""
    findings: list[Finding] = []
    for rule in VULN_RULES:
        if rule.matches(product, version):
            detail = f"Producto detectado: {product} {version}".strip()
            findings.append(Finding(rule.severity, f"{rule.cve}: {rule.title}",
                                    detail, [rule.ref] if rule.ref else []))
    return findings


def static_findings(port: int) -> list[Finding]:
    finding = STATIC_PORT_FINDINGS.get(port)
    return [finding] if finding else []
