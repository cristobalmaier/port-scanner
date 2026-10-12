"""Command-line interface.

The goal is a *zero-configuration* default: ``netscope 10.0.0.1`` runs a full
reconnaissance pass (curated ports, service/version detection, HTTP/TLS
fingerprinting and active checks) without a single flag.
"""

from __future__ import annotations

import argparse
import os
import sys

from .constants import TIMING_PROFILES, __version__
from .output import (
    render_grep,
    render_json,
    render_text,
    render_xml,
)
from .scanner import ScanOptions, run
from .target import parse_ports, parse_targets

BANNER = r"""
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██████╔╝█████╗
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
"""

WEB_PORTS = "80,81,443,3000,5000,8000,8008,8080,8081,8443,8888,9000,9090,9443,10000,10443"
UDP_DEFAULT = "53,69,123,137,138,161,500,1900,2049,4500,5353"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="Escáner de puertos y reconocimiento rápido, sin dependencias.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
ejemplos:
  netscope 192.168.1.1                 escaneo inteligente (recomendado)
  netscope 10.0.0.0/24 --fast          toda la subred, puertos más comunes
  netscope example.com --full          los 65535 puertos TCP
  netscope 192.168.1.5 --web           recon web (HTTP/HTTPS + tecnologías)
  netscope 192.168.1.5 -p 22,80,1-1000 rango de puertos personalizado
  netscope host --udp --deep           UDP + chequeos activos completos
  netscope host -o report.json         guarda el resultado en JSON
  netscope host --stealth              escaneo silencioso (evita IDS)
""",
    )

    parser.add_argument("targets", nargs="*", metavar="objetivo",
                        help="IP, hostname, rango (192.168.1.1-20) o CIDR (10.0.0.0/24)")

    presets = parser.add_argument_group("presets (elige uno)")
    presets.add_argument("--fast", action="store_true", help="escaneo rápido (top 100 puertos)")
    presets.add_argument("--full", action="store_true", help="los 65535 puertos TCP")
    presets.add_argument("--web", action="store_true", help="solo puertos web + tecnologías")
    presets.add_argument("--deep", action="store_true", help="full + UDP + todos los chequeos")
    presets.add_argument("--stealth", action="store_true", help="bajo y lento (menos ruido, -T1)")

    scan = parser.add_argument_group("escaneo")
    scan.add_argument("-p", "--ports", metavar="SPEC",
                      help="puertos: 22,80,1-1000 | top100 | all  (default: set curado)")
    scan.add_argument("-T", "--timing", type=int, choices=range(0, 6), default=4,
                      metavar="0-5", help="perfil de velocidad: 0 paranoid .. 5 insane (default 4)")
    scan.add_argument("-c", "--concurrency", type=int, help="sockets simultáneos")
    scan.add_argument("--timeout", type=float, help="timeout por puerto en segundos")
    scan.add_argument("-U", "--udp", action="store_true", help="añadir sondeo UDP")
    scan.add_argument("--udp-ports", metavar="SPEC", help="puertos UDP (default comunes)")
    scan.add_argument("--discover", action="store_true",
                      help="omitir hosts que no responden (discovery previo)")
    scan.add_argument("--no-version", action="store_true", help="desactivar detección de versión")
    scan.add_argument("--no-checks", action="store_true", help="desactivar chequeos activos")
    scan.add_argument("--no-http", action="store_true", help="desactivar recon HTTP")
    scan.add_argument("--list-ports", action="store_true", help="mostrar puertos y salir")

    out = parser.add_argument_group("salida")
    out.add_argument("-o", "--output", metavar="FILE", help="guardar informe en FILE")
    out.add_argument("--format", choices=["auto", "text", "json", "xml", "grep"],
                     default="auto", help="formato de salida (default: por extensión)")
    out.add_argument("--save-all", metavar="DIR",
                     help="guardar informes .txt, .json y .xml en DIR")
    out.add_argument("-v", "--verbose", action="store_true", help="mostrar banners y TLS")
    out.add_argument("-q", "--quiet", action="store_true", help="sin progreso")
    out.add_argument("--no-color", action="store_true", help="desactivar colores")
    out.add_argument("--no-banner", action="store_true", help="no mostrar el banner")
    out.add_argument("--version", action="version", version=f"netscope {__version__}")
    return parser


def _resolve_ports(args: argparse.Namespace) -> tuple[list[int], list[int]]:
    if args.full or args.deep:
        spec = "all"
    elif args.web:
        spec = WEB_PORTS
    elif args.fast:
        spec = "top100"
    else:
        spec = args.ports or None

    ports = parse_ports(spec)

    udp_ports: list[int] = []
    if args.udp or args.deep:
        udp_ports = parse_ports(args.udp_ports or UDP_DEFAULT)
    return ports, udp_ports


def _make_progress(enabled: bool):
    if not enabled:
        return None

    def callback(host, done: int, total: int) -> None:
        if total <= 0:
            return
        pct = int(done * 100 / total)
        bar = "#" * (pct // 4) + "-" * (25 - pct // 4)
        target = str(host)[:20]
        sys.stderr.write(f"\r  [{bar}] {pct:3d}%  {target:<20}")
        sys.stderr.flush()
        if done >= total:
            sys.stderr.write("\r" + " " * 60 + "\r")
            sys.stderr.flush()

    return callback


def _infer_format(path: str, requested: str) -> str:
    if requested != "auto":
        return requested
    ext = os.path.splitext(path)[1].lower()
    return {".json": "json", ".xml": "xml", ".txt": "text",
            ".gnmap": "grep", ".grep": "grep"}.get(ext, "json")


def _serialize(report, fmt: str, color: bool, verbose: bool) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "xml":
        return render_xml(report)
    if fmt == "grep":
        return render_grep(report)
    return render_text(report, color=color, verbose=verbose)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.list_ports and not args.targets:
        parser.error("se requiere al menos un objetivo (o usá --list-ports)")

    if not args.no_banner and not args.list_ports:
        print(f"\033[96m{BANNER}\033[0m")
        print(f"\033[90m  v{__version__}  ·  solo usar en sistemas autorizados\033[0m\n")

    if args.web:
        args.timing = min(args.timing, 4)

    ports, udp_ports = _resolve_ports(args)

    if args.list_ports:
        label = ",".join(str(p) for p in ports)
        print(f"  TCP ({len(ports)}): {label}")
        if udp_ports:
            print(f"  UDP ({len(udp_ports)}): {','.join(str(p) for p in udp_ports)}")
        return 0

    targets = parse_targets(args.targets)

    profile = TIMING_PROFILES[args.timing]
    opts = ScanOptions(
        ports=ports,
        udp_ports=udp_ports,
        concurrency=args.concurrency or profile["concurrency"],
        timeout=args.timeout or profile["timeout"],
        delay=0.0 if args.stealth else profile["delay"],
        version_detect=not args.no_version,
        checks=not args.no_checks,
        http_recon=not args.no_http,
        discover=args.discover,
        progress=not args.quiet,
    )
    opts.command_args = ["netscope", *sys.argv[1:]]

    if args.stealth:
        opts.delay = 0.2
        opts.concurrency = min(opts.concurrency, 20)

    color = sys.stdout.isatty() and not args.no_color
    progress = _make_progress(not args.quiet and sys.stdout.isatty() and args.format == "auto")

    try:
        report = run(targets, opts, on_progress=progress)
    except KeyboardInterrupt:
        print("\n  Interrumpido por el usuario.", file=sys.stderr)
        return 130

    fmt = args.format if args.format != "auto" else "text"
    print(_serialize(report, fmt, color, args.verbose))

    if args.output:
        out_fmt = _infer_format(args.output, args.format)
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(_serialize(report, out_fmt, color=False, verbose=args.verbose))
        print(f"  Informe guardado en {args.output} ({out_fmt})", file=sys.stderr)

    if args.save_all:
        os.makedirs(args.save_all, exist_ok=True)
        for name, f in (("netscope.txt", "text"), ("netscope.json", "json"), ("netscope.xml", "xml")):
            path = os.path.join(args.save_all, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(_serialize(report, f, color=False, verbose=args.verbose))
        print(f"  Informes guardados en {args.save_all}/", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
