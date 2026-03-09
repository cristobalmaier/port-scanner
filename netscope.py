#!/usr/bin/env python3
"""
NETSCOPE - Port Scanner
Uso: python3 netscope.py <objetivo> [puerto_inicio] [puerto_fin]
"""

import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colores ──────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GRAY   = "\033[90m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"

# ── Servicios conocidos: puerto → (nombre, color) ────
SERVICES = {
    21:    ("ftp",        YELLOW),
    22:    ("ssh",        GREEN),
    23:    ("telnet",     RED),
    25:    ("smtp",       CYAN),
    53:    ("dns",        CYAN),
    80:    ("http",       GREEN),
    110:   ("pop3",       CYAN),
    143:   ("imap",       CYAN),
    443:   ("https",      GREEN),
    445:   ("smb",        RED),
    3306:  ("mysql",      YELLOW),
    3389:  ("rdp",        RED),
    5432:  ("postgresql", YELLOW),
    5900:  ("vnc",        RED),
    6379:  ("redis",      RED),
    8080:  ("http-alt",   GREEN),
    8443:  ("https-alt",  GREEN),
    27017: ("mongodb",    RED),
}

# Puertos peligrosos con advertencia
DANGEROUS = {
    23:    "Telnet — transmite contraseñas en texto plano",
    445:   "SMB — vulnerable a EternalBlue/ransomware",
    3389:  "RDP — riesgo de fuerza bruta",
    5900:  "VNC — autenticación débil",
    6379:  "Redis — sin auth, acceso total a la BD",
    27017: "MongoDB — sin auth, fuga de datos",
}


def banner():
    print(f"""
\033[96m\033[1m  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██████╔╝█████╗
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝\033[0m
\033[90m  \033[0m
""")


def scan_port(ip, port):
    """Intenta conectar a un puerto. Devuelve el puerto si está abierto."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex((ip, port)) == 0:
            return port
    except:
        pass
    finally:
        sock.close()
    return None


def main():
    banner()

    # Argumentos básicos
    if len(sys.argv) < 2:
        print(f"  Uso: python3 netscope.py <objetivo> [inicio] [fin]")
        print(f"  Ej:  python3 netscope.py 192.168.1.1 1 1000\n")
        sys.exit(0)

    target   = sys.argv[1]
    port_min = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    port_max = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    ports    = range(port_min, port_max + 1)

    # Resolver IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"  \033[91m[✗] No se pudo resolver: {target}\033[0m\n")
        sys.exit(1)

    # Info del escaneo
    start = datetime.now()
    print(f"  \033[90mNmap scan report for \033[0m\033[1m\033[97m{target}\033[0m \033[90m({ip})\033[0m")
    print(f"  \033[90mEscaneando {len(ports)} puertos...\033[0m\n")

    # Escanear en paralelo
    open_ports = []
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort()

    # Mostrar resultados
    if not open_ports:
        print(f"  \033[93mNo se encontraron puertos abiertos.\033[0m")
    else:
        print(f"  \033[90m{'PORT':<16} {'STATE':<10} {'SERVICE'}\033[0m")
        print(f"  \033[90m{'─'*50}\033[0m")

        for port in open_ports:
            name, color = SERVICES.get(port, ("unknown", WHITE))
            port_str    = f"{BOLD}{color}{port}/tcp{RESET}"
            state_str   = f"{GREEN}open{RESET}"
            service_str = f"{color}{name}{RESET}"
            print(f"  {port_str:<38} {state_str:<18} {service_str}")

            if port in DANGEROUS:
                sev  = "CRITICAL" if port in [6379, 27017, 445, 23] else "HIGH"
                scol = RED if sev == "CRITICAL" else YELLOW
                print(f"  \033[90m|_\033[0m {scol}[{sev}]{RESET} \033[90m{DANGEROUS[port]}\033[0m")

    # Footer
    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n  \033[90mNetscope done: scanned in {elapsed:.2f}s — {len(open_ports)} open / {len(ports)} total\033[0m\n")


if __name__ == "__main__":
    main()