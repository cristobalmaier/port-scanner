"""Asynchronous scan orchestration: fast TCP discovery + enrichment.

Design: a two-phase pipeline.
  1. Discovery — pure asyncio TCP connect scan, thousands of sockets in flight,
     no blocking work. This is what makes it fast.
  2. Enrichment — only for the ports that came back open, so it can do slow,
     thorough work (banners, TLS, HTTP, active checks) without hurting speed.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field

from .banners import enrich_tcp, enrich_udp
from .constants import DISCOVERY_PORTS, TOOL_NAME, __version__
from .models import HostResult, ScanReport
from .target import resolve

HOST_CONCURRENCY = 32


@dataclass
class ScanOptions:
    ports: list[int] = field(default_factory=list)
    udp_ports: list[int] = field(default_factory=list)
    concurrency: int = 1500
    timeout: float = 1.0
    delay: float = 0.0
    version_detect: bool = True
    checks: bool = True
    http_recon: bool = True
    discover: bool = False
    enrich_concurrency: int = 64
    progress: bool = True
    command_args: list[str] = field(default_factory=list)


async def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
        return True
    except (asyncio.TimeoutError, OSError):
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


async def _host_alive(ip: str, timeout: float) -> bool:
    """Lightweight discovery: connect to a few common ports."""
    results = await asyncio.gather(
        *(_tcp_open(ip, port, timeout) for port in DISCOVERY_PORTS))
    return any(results)


async def _discover_tcp(ip: str, ports: list[int], opts: ScanOptions,
                        tick=None) -> list[int]:
    """Scan *ports* against *ip*, returning the open ones."""
    queue: asyncio.Queue[int] = asyncio.Queue()
    for port in ports:
        queue.put_nowait(port)
    open_ports: list[int] = []
    lock = asyncio.Lock()

    async def worker() -> None:
        while True:
            try:
                port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                if opts.delay:
                    await asyncio.sleep(opts.delay)
                if await _tcp_open(ip, port, opts.timeout):
                    async with lock:
                        open_ports.append(port)
            finally:
                if tick:
                    tick()

    workers = max(1, min(opts.concurrency, len(ports)))
    await asyncio.gather(*(worker() for _ in range(workers)))
    return sorted(open_ports)


async def _time_first_open(ip: str, ports: list[int], opts: ScanOptions) -> float | None:
    """Measure handshake latency to the first responsive port."""
    for port in ports[:8]:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        begin = time.perf_counter()
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), min(opts.timeout, 1.0))
            return round((time.perf_counter() - begin) * 1000, 2)
        except (asyncio.TimeoutError, OSError):
            continue
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return None


def _udp_probe(ip: str, port: int, timeout: float) -> bytes:
    payload = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x01",
        123: b"\x1b" + b"\x00" * 47,
        161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00"
             b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02"
             b"\x01\x01\x05\x00",
    }.get(port, b"\x00")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(4096)
        return data
    except OSError:
        return b""
    finally:
        try:
            sock.close()
        except OSError:
            pass


async def _discover_udp(ip: str, ports: list[int], opts: ScanOptions) -> list[int]:
    """Report UDP ports that answer to a probe (best-effort)."""
    loop = asyncio.get_running_loop()
    results = []
    responses = await asyncio.gather(
        *(loop.run_in_executor(None, _udp_probe, ip, p, opts.timeout) for p in ports))
    for port, data in zip(ports, responses):
        if data:
            results.append(port)
    return sorted(results)


async def _enrich(ip: str, open_tcp: list[int], open_udp: list[int],
                  opts: ScanOptions, hostname: str | None) -> list:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(opts.enrich_concurrency)
    results = []

    async def work_tcp(port: int) -> None:
        async with sem:
            results.append(await loop.run_in_executor(
                None, enrich_tcp, ip, port, opts, hostname))

    async def work_udp(port: int) -> None:
        async with sem:
            results.append(await loop.run_in_executor(
                None, enrich_udp, ip, port, opts))

    await asyncio.gather(*(work_tcp(p) for p in open_tcp),
                         *(work_udp(p) for p in open_udp))
    results.sort(key=lambda r: (r.port, r.proto))
    return results


async def scan_host(ip: str, hostname: str | None, opts: ScanOptions,
                    tick=None) -> HostResult:
    host = HostResult(ip=ip, hostname=hostname)

    if opts.discover and not await _host_alive(ip, min(opts.timeout, 1.0)):
        host.state = "down"
        return host

    open_tcp = await _discover_tcp(ip, opts.ports, opts, tick=tick)
    open_udp = await _discover_udp(ip, opts.udp_ports, opts) if opts.udp_ports else []

    if open_tcp:
        host.latency_ms = await _time_first_open(ip, open_tcp, opts)

    host.ports = await _enrich(ip, open_tcp, open_udp, opts, hostname)
    for port in host.ports:
        hint = port.info.get("os_hint")
        if hint:
            host.os_hint = hint
            break
    return host


async def scan(targets: list[str], opts: ScanOptions, on_progress=None) -> ScanReport:
    started = time.time()
    resolved = [resolve(target) for target in targets]

    total_steps = max(1, len(resolved) * (len(opts.ports) + len(opts.udp_ports)))
    state = {"done": 0}

    def make_tick(label: str):
        def tick() -> None:
            state["done"] += 1
            done = state["done"]
            if on_progress and (done % 200 == 0 or done == total_steps):
                on_progress(label, done, total_steps)
        return tick

    host_sem = asyncio.Semaphore(HOST_CONCURRENCY)

    async def one(index: int, ip: str, hostname: str | None):
        async with host_sem:
            label = hostname or ip
            host = await scan_host(ip, hostname, opts, tick=make_tick(label))
            return index, host

    gathered = await asyncio.gather(
        *(one(i, ip, name) for i, (ip, name) in enumerate(resolved)))
    gathered.sort(key=lambda pair: pair[0])
    if on_progress:
        on_progress("", total_steps, total_steps)

    report = ScanReport(
        tool=TOOL_NAME,
        version=__version__,
        command=" ".join(opts.command_args),
        targets=list(targets),
        started=started,
        finished=time.time(),
    )
    report.hosts = [host for _, host in gathered]

    total_open = sum(len(h.ports) for h in report.hosts)
    report.stats = {
        "hosts_scanned": len(report.hosts),
        "hosts_up": sum(1 for h in report.hosts if h.ports),
        "ports_scanned": len(opts.ports) + len(opts.udp_ports),
        "open_ports": total_open,
        "elapsed_seconds": round(report.elapsed, 3),
    }
    return report


def run(targets: list[str], opts: ScanOptions, on_progress=None) -> ScanReport:
    """Synchronous entry point used by the CLI."""
    return asyncio.run(scan(targets, opts, on_progress=on_progress))
