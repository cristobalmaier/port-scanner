#!/usr/bin/env python3
"""
netscope — escáner de puertos rápido y sencillo (alternativa ligera a nmap).

Uso:
    python3 netscope.py <objetivo>
    python3 netscope.py <objetivo> -p 1-65535
    python3 netscope.py <objetivo> --full
    python3 netscope.py <objetivo> -t 0.5 --top 500

Solo biblioteca estándar. Escaneá únicamente sistemas que te pertenezcan o
para los que tengas autorización por escrito.
"""

import argparse
import asyncio
import socket
import sys
import time

# ── Puertos comunes (por defecto) ────────────────────────────────────────────
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 636,
    873, 993, 995, 1025, 1080, 1099, 1433, 1434, 1521, 1723, 1883, 2049, 2181,
    2375, 2376, 3000, 3128, 3260, 3306, 3389, 4369, 5000, 5060, 5432, 5555,
    5601, 5672, 5900, 5984, 5985, 5986, 6379, 6443, 7001, 8000, 8008, 8009,
    8080, 8081, 8086, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 10000,
    11211, 15672, 27017, 50000,
]

# ── Servicios conocidos ──────────────────────────────────────────────────────
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "rsh", 587: "smtp", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "http-dev", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9200: "elasticsearch", 9300: "elasticsearch", 10000: "webmin",
    11211: "memcached", 15672: "rabbitmq", 27017: "mongodb", 50000: "sap",
}

# ── Puertos con riesgo ───────────────────────────────────────────────────────
DANGEROUS = {
    21: ("HIGH", "FTP sin cifrado; revisar login anónimo"),
    23: ("CRITICAL", "Telnet transmite credenciales en texto plano"),
    139: ("HIGH", "NetBIOS/SMB legado"),
    445: ("CRITICAL", "SMB expuesto (EternalBlue / ransomware)"),
    1433: ("MEDIUM", "MSSQL expuesto; revisar credenciales por defecto"),
    2375: ("CRITICAL", "Docker API sin autenticación: control del host"),
    3306: ("MEDIUM", "MySQL expuesto en red"),
    3389: ("HIGH", "RDP expuesto a fuerza bruta / BlueKeep"),
    5432: ("MEDIUM", "PostgreSQL expuesto en red"),
    5900: ("HIGH", "VNC con autenticación débil o nula"),
    6379: ("CRITICAL", "Redis sin contraseña: RCE por escritura de ficheros"),
    9200: ("HIGH", "Elasticsearch sin autenticación"),
    11211: ("HIGH", "Memcached sin autenticación"),
    27017: ("CRITICAL", "MongoDB sin autenticación"),
}

HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9200, 15672, 2375}

RESET, BOLD, GRAY = "\033[0m", "\033[1m", "\033[90m"
RED, GREEN, YELLOW, CYAN, WHITE = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[97m"

ISATTY = sys.stdout.isatty()


def color(text, code):
    return f"{code}{text}{RESET}" if ISATTY else text


async def grab_banner(loop, sock, port, timeout):
    """Lee el banner del servicio (envía una petición si hace falta)."""
    try:
        data = await asyncio.wait_for(loop.sock_recv(sock, 1024), min(timeout, 0.6))
    except (asyncio.TimeoutError, OSError):
        data = b""
    if not data:
        probe = b"GET / HTTP/1.0\r\nHost: x\r\n\r\n" if port in HTTP_PORTS else b"\r\n"
        try:
            await loop.sock_sendall(sock, probe)
            data = await asyncio.wait_for(loop.sock_recv(sock, 1024), min(timeout, 0.8))
        except (asyncio.TimeoutError, OSError):
            return ""
    if not data:
        return ""
    line = data.decode("utf-8", "ignore").replace("\r", "").split("\n")[0]
    return line.strip()[:70]


async def scan_port(ip, port, timeout, sem, banners):
    async with sem:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
        except (asyncio.TimeoutError, OSError):
            sock.close()
            return None
        banner = await grab_banner(loop, sock, port, timeout) if banners else ""
        sock.close()
        return port, banner


def parse_ports(args):
    if args.full:
        return list(range(1, 65536))
    if args.ports:
        ports = set()
        for chunk in args.ports.split(","):
            chunk = chunk.strip()
            if "-" in chunk:
                a, b = chunk.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            elif chunk:
                ports.add(int(chunk))
        return sorted(p for p in ports if 1 <= p <= 65535)
    return sorted(set(COMMON_PORTS))[: args.top]


async def run(ip, ports, args):
    sem = asyncio.Semaphore(args.threads)
    start = time.time()
    found = []
    tasks = [scan_port(ip, p, args.timeout, sem, not args.no_banner) for p in ports]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result:
            found.append(result)
    found.sort()
    return found, time.time() - start


def main():
    parser = argparse.ArgumentParser(
        description="Escáner de puertos rápido y sencillo (alternativa ligera a nmap).")
    parser.add_argument("target", help="IP o hostname objetivo")
    parser.add_argument("-p", "--ports", help="puertos: '22,80,443' o '1-1000'")
    parser.add_argument("--full", action="store_true", help="escanear los 65535 puertos")
    parser.add_argument("--top", type=int, default=len(COMMON_PORTS),
                        help="usar los N puertos más comunes (default: %(default)s)")
    parser.add_argument("-t", "--timeout", type=float, default=0.7,
                        help="timeout por puerto en segundos (default: 0.7)")
    parser.add_argument("-T", "--threads", type=int, default=1000,
                        help="conexiones simultáneas (default: 1000)")
    parser.add_argument("--no-banner", action="store_true",
                        help="no intentar leer banners/versiones")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{color('[!] No se pudo resolver:', RED)} {args.target}")
        return 1

    ports = parse_ports(args)
    print(color(f"\n  netscope — objetivo {args.target} ({ip})", BOLD + CYAN))
    print(color(f"  Escaneando {len(ports)} puertos TCP...\n", GRAY))

    try:
        found, elapsed = asyncio.run(run(ip, ports, args))
    except KeyboardInterrupt:
        print("\n  Interrumpido.")
        return 130

    if not found:
        print(color("  No se encontraron puertos abiertos.", YELLOW))
    else:
        print(color(f"  {'PUERTO':<12}{'ESTADO':<8}{'SERVICIO':<14}VERSION", GRAY))
        print(color("  " + "─" * 60, GRAY))
        for port, banner in found:
            service = SERVICES.get(port, "unknown")
            label = f"{port}/tcp"
            version = banner or ""
            row = (f"  {color(f'{label:<12}', BOLD + WHITE)}"
                   f"{color(f'{"open":<8}', GREEN)}"
                   f"{color(f'{service:<14}', CYAN)}"
                   f"{color(version, GRAY)}")
            print(row)
            if port in DANGEROUS:
                level, reason = DANGEROUS[port]
                col = RED if level == "CRITICAL" else YELLOW
                print(f"       {color(f'[{level}]', BOLD + col)} {reason}")

    print(color(f"\n  Listo: {len(found)} abiertos / {len(ports)} escaneados en {elapsed:.2f}s\n",
                GRAY))
    return 0


if __name__ == "__main__":
    sys.exit(main())
