"""Per-port enrichment: banner grabbing, HTTP/TLS fingerprinting, active checks.

Enrichment runs only for ports already found open, so it can afford to be
thorough: it grabs service banners, parses product/version, fingerprints HTTP,
reads TLS certificates and runs a handful of safe, non-destructive active
checks (anonymous FTP, password-less Redis, etc.).
"""

from __future__ import annotations

import json
import re
import socket
import ssl

from .models import Finding, PortResult
from .services import (
    HTTPS_PORTS,
    HTTP_PORTS,
    banner_to_text,
    category,
    parse_product_version,
    service_name,
)
from .tls import fetch_tls
from .vulns import match_cves, static_findings

# Ports that speak HTTP but are not in the generic HTTP set.
_EXTRA_HTTP = {2375, 2379, 8500, 10250, 10255, 5601, 28017}

USER_AGENT = "netscope/2.0 (+recon)"

PROBES: dict[int, bytes] = {
    21: b"",  # passive banner
    6379: b"PING\r\n",
    11211: b"stats\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    9300: b"\r\n",
    15672: b"GET / HTTP/1.0\r\n\r\n",
    27017: b"",
    5672: b"",
    5900: b"",
}

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

_OS_SIGNATURES = [
    (re.compile(r"ubuntu", re.I), "Linux (Ubuntu)"),
    (re.compile(r"debian", re.I), "Linux (Debian)"),
    (re.compile(r"centos|red hat|rhel", re.I), "Linux (RHEL/CentOS)"),
    (re.compile(r"amazon linux", re.I), "Linux (Amazon)"),
    (re.compile(r"freebsd", re.I), "FreeBSD"),
    (re.compile(r"openbsd", re.I), "OpenBSD"),
    (re.compile(r"microsoft|windows|iis|smb|winnt", re.I), "Windows"),
    (re.compile(r"cisco", re.I), "Cisco IOS"),
    (re.compile(r"routeros|mikrotik", re.I), "MikroTik RouterOS"),
    (re.compile(r"synology", re.I), "Synology DSM"),
]

_TECH_SIGNATURES = [
    (re.compile(r"wp-content|wp-includes|wordpress", re.I), "WordPress"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"joomla", re.I), "Joomla"),
    (re.compile(r"grafana", re.I), "Grafana"),
    (re.compile(r"jenkins", re.I), "Jenkins"),
    (re.compile(r"gitlab", re.I), "GitLab"),
    (re.compile(r"phpmyadmin|pma", re.I), "phpMyAdmin"),
    (re.compile(r"tomcat|catalina", re.I), "Apache Tomcat"),
    (re.compile(r"kibana", re.I), "Kibana"),
    (re.compile(r"swagger|openapi", re.I), "Swagger/OpenAPI"),
    (re.compile(r"\"cluster_name\"", re.I), "Elasticsearch"),
    (re.compile(r"<title>\s*Apache Tomcat", re.I), "Apache Tomcat"),
]


# ── Low-level socket helpers ────────────────────────────────────────────────


def _connect(ip: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((ip, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def _read(sock: socket.socket, idle_timeout: float = 0.7, max_bytes: int = 65535) -> bytes:
    """Read until the peer goes quiet, closes, or we hit *max_bytes*."""
    sock.settimeout(idle_timeout)
    chunks = bytearray()
    while len(chunks) < max_bytes:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) >= 4096:  # enough for a banner/HTTP header block
            break
    return bytes(chunks)


# ── Banner grabbing ─────────────────────────────────────────────────────────


def grab_banner(ip: str, port: int, timeout: float) -> bytes:
    """Return the raw banner for a service, sending a probe when needed."""
    try:
        sock = _connect(ip, port, timeout)
    except OSError:
        return b""
    try:
        raw = b""
        try:
            raw = sock.recv(2048)  # server-speaks-first protocols
        except (socket.timeout, TimeoutError, OSError):
            raw = b""
        if not raw:
            probe = PROBES.get(port)
            if probe is None and port in HTTP_PORTS:
                probe = _http_request(ip).encode()
            if probe:
                try:
                    sock.sendall(probe)
                    raw = _read(sock, min(timeout, 0.8))
                except OSError:
                    raw = b""
        return raw
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ── HTTP fingerprinting ─────────────────────────────────────────────────────


def _http_request(host: str, path: str = "/") -> str:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )


def _connect_maybe_tls(ip: str, port: int, tls: bool, timeout: float):
    sock = _connect(ip, port, timeout)
    if not tls:
        return sock, False
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # Offer HTTP/1.1 so a plain request works (h2 is detected separately).
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return ctx.wrap_socket(sock, server_hostname=ip), True


def http_probe(ip: str, port: int, tls: bool, timeout: float,
               host: str | None = None) -> dict | None:
    """Fetch ``/`` and return status, headers, title and detected tech."""
    try:
        sock, _ = _connect_maybe_tls(ip, port, tls, timeout)
    except Exception:
        return None
    try:
        sock.sendall(_http_request(host or ip).encode())
        raw = _read(sock, min(timeout, 1.0), max_bytes=32768)
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if not raw:
        return None

    text = raw.decode("utf-8", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.splitlines()
    if not lines or not lines[0].upper().startswith("HTTP/"):
        return None
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    info: dict = {
        "status": status,
        "server": headers.get("server", ""),
        "powered_by": headers.get("x-powered-by", ""),
        "title": "",
        "headers": {k: v for k, v in headers.items() if k in _SECURITY_HEADERS},
        "missing_headers": [h for h in _SECURITY_HEADERS if h not in headers],
        "tech": [],
    }
    match = re.search(r"<title[^>]*>(.*?)</title>", body or text, re.I | re.S)
    if match:
        info["title"] = re.sub(r"\s+", " ", match.group(1)).strip()[:120]
    if "location" in headers:
        info["redirect"] = headers["location"]

    haystack = text + " " + headers.get("set-cookie", "")
    seen = set()
    for regex, label in _TECH_SIGNATURES:
        if label not in seen and regex.search(haystack):
            info["tech"].append(label)
            seen.add(label)
    return info


# ── Active security checks (safe / non-destructive) ─────────────────────────


def _check_ftp_anonymous(ip: str, port: int, timeout: float) -> Finding | None:
    try:
        sock = _connect(ip, port, timeout)
    except OSError:
        return None
    try:
        _read(sock, 0.6)
        sock.sendall(b"USER anonymous\r\n")
        resp = _read(sock, 0.6)
        if b"331" not in resp and b"230" not in resp:
            return None
        sock.sendall(b"PASS anonymous@example.com\r\n")
        resp += _read(sock, 0.6)
        if b"230" in resp:
            return Finding("CRITICAL", "FTP: login anónimo habilitado",
                           "El servidor acepta usuario `anonymous` sin contraseña.",
                           ["https://cwe.mitre.org/data/definitions/287.html"])
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return None


def _check_redis(ip: str, port: int, timeout: float) -> tuple[Finding | None, str]:
    """PING then INFO. Returns (finding, version)."""
    try:
        sock = _connect(ip, port, timeout)
    except OSError:
        return None, ""
    version = ""
    finding = None
    try:
        sock.sendall(b"PING\r\n")
        resp = _read(sock, 0.6)
        if b"+PONG" in resp:
            finding = Finding("CRITICAL", "Redis sin autenticación",
                              "Redis responde a PING sin pedir contraseña: RCE vía escritura de ficheros.",
                              ["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"])
            sock.sendall(b"INFO server\r\n")
            info = _read(sock, 0.6).decode("utf-8", errors="replace")
            m = re.search(r"redis_version:([\w.\-]+)", info)
            if m:
                version = m.group(1)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return finding, version


def _check_vnc(ip: str, port: int, timeout: float) -> Finding | None:
    try:
        sock = _connect(ip, port, timeout)
    except OSError:
        return None
    try:
        banner = _read(sock, 0.6)
        if not banner.startswith(b"RFB"):
            return None
        version = banner[:12]
        sock.sendall(version)  # echo the protocol version
        types = _read(sock, 0.6)
        # types[0] = number of security types; types[1:] = type ids
        if len(types) >= 2 and types[0] >= 1 and b"\x01" in types[1:]:
            return Finding("CRITICAL", "VNC sin autenticación",
                           "VNC ofrece el tipo de seguridad `None` (acceso sin contraseña).",
                           [])
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return None


def _check_memcached(ip: str, port: int, timeout: float) -> Finding | None:
    try:
        sock = _connect(ip, port, timeout)
    except OSError:
        return None
    try:
        sock.sendall(b"stats\r\n")
        resp = _read(sock, 0.6)
        if resp.startswith(b"STAT"):
            return Finding("HIGH", "Memcached sin autenticación",
                           "`stats` responde sin credenciales: fuga de datos y amplificación DDoS.",
                           ["https://nvd.nist.gov/vuln/detail/CVE-2018-1000115"])
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return None


def _http_findings(port: int, http: dict) -> list[Finding]:
    out: list[Finding] = []
    missing = http.get("missing_headers", [])
    critical_missing = [h for h in missing if h in ("x-frame-options", "x-content-type-options")]
    if critical_missing:
        out.append(Finding("LOW", "Cabeceras de seguridad ausentes",
                           "Faltan: " + ", ".join(missing), []))
    if http.get("server"):
        out.append(Finding("INFO", "Servidor web", http["server"], []))
    tech = http.get("tech", [])
    if "Elasticsearch" in tech or port == 9200:
        out.append(Finding("HIGH", "Elasticsearch accesible sin auth",
                           "El índice responde a HTTP sin autenticación.", []))
    if port in (2375,) and http.get("status"):
        out.append(Finding("CRITICAL", "Docker API sin autenticación",
                           "El daemon Docker responde por HTTP: control total del host.", []))
    if port == 2379 and http.get("status"):
        out.append(Finding("HIGH", "etcd accesible", "Posible fuga de secretos de Kubernetes.", []))
    return out


# ── Orchestration for a single TCP port ─────────────────────────────────────


def _os_hint(result: PortResult) -> str | None:
    haystack = " ".join(filter(None, [
        result.banner,
        result.product,
        (result.tls or {}).get("issuer", ""),
        (result.http or {}).get("server", ""),
    ]))
    for regex, label in _OS_SIGNATURES:
        if regex.search(haystack):
            return label
    return None


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.level, f.title)
        if key not in seen:
            out.append(f)
            seen.add(key)
    return out


def enrich_tcp(ip: str, port: int, opts, hostname: str | None = None) -> PortResult:
    """Build a fully-populated :class:`PortResult` for one open TCP port."""
    result = PortResult(
        port=port,
        proto="tcp",
        service=service_name(port),
        category=category(port),
    )

    is_tls = port in HTTPS_PORTS
    wants_http = (port in HTTP_PORTS) or (port in _EXTRA_HTTP) or is_tls

    # 1) TLS metadata
    if opts.version_detect and is_tls:
        tls_info = fetch_tls(ip, port, opts.timeout, server_hostname=hostname)
        if tls_info:
            result.tls = tls_info

    # 2) HTTP fingerprint
    http = None
    if opts.http_recon and wants_http:
        http = http_probe(ip, port, is_tls, opts.timeout, host=hostname)
        if http:
            result.http = http

    # 3) Banner + version detection (plaintext; TLS services skip this)
    findings: list[Finding] = list(static_findings(port))
    if opts.version_detect:
        product, version = "", ""
        if not is_tls:
            raw = grab_banner(ip, port, opts.timeout)
            text = banner_to_text(raw)
            result.banner = text
            product, version = parse_product_version(text)
        # HTTP Server header is usually more precise than the raw banner.
        if http and http.get("server"):
            h_product, h_version = parse_product_version(http["server"])
            if h_version or not version:
                product, version = h_product or product, h_version or version
        result.product, result.version = product, version
        if result.service == "unknown" and product:
            result.service = product.lower()
        findings += match_cves(product, version)

    # 4) Active checks
    if opts.checks:
        if port == 21:
            f = _check_ftp_anonymous(ip, port, opts.timeout)
            if f:
                findings.append(f)
        elif port == 6379:
            f, redis_version = _check_redis(ip, port, opts.timeout)
            if f:
                findings.append(f)
            if redis_version:
                result.product = result.product or "Redis"
                result.version = redis_version
                findings += match_cves("Redis", redis_version)
        elif port == 5900:
            f = _check_vnc(ip, port, opts.timeout)
            if f:
                findings.append(f)
        elif port == 11211:
            f = _check_memcached(ip, port, opts.timeout)
            if f:
                findings.append(f)
        if result.http:
            findings += _http_findings(port, result.http)
            # Docker/etcd/k8s over HTTP versions
            if port == 2375 and result.http.get("server"):
                findings.append(Finding("INFO", "Docker Engine",
                                        result.http["server"], []))

    result.findings = _dedupe(findings)
    hint = _os_hint(result)
    if hint:
        result.info["os_hint"] = hint
    return result


def enrich_udp(ip: str, port: int, opts) -> PortResult:
    """Best-effort UDP service probe (DNS, SNMP, NTP, NetBIOS)."""
    result = PortResult(port=port, proto="udp", state="open",
                        service=service_name(port, "udp"), category=category(port))
    result.findings = static_findings(port)
    if not opts.version_detect:
        return result

    probes = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07version\x04bind\x00\x00\x10\x00\x03",
        123: b"\x1b" + b"\x00" * 47,
        161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00"
             b"\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b"
             b"\x06\x01\x02\x01\x01\x05\x00",
    }
    payload = probes.get(port)
    if not payload:
        return result
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(opts.timeout)
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
    except OSError:
        return result
    if not data:
        return result
    text = banner_to_text(data)
    result.banner = text
    if port == 53:
        result.product = "BIND/DNS"
    if port == 161:
        result.product = "SNMP"
        result.findings.append(Finding("MEDIUM", "SNMP responde con comunidad `public`",
                                       "Fuga de información del sistema vía SNMP v1/v2c.", []))
    return result
