"""Data model for scan results (plain dataclasses, JSON-serialisable)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    """A security-relevant observation about an open port."""

    level: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str = ""
    refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PortResult:
    port: int
    proto: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    category: str = "other"
    product: str = ""
    version: str = ""
    banner: str = ""
    tls: dict | None = None
    http: dict | None = None
    info: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        return data


@dataclass
class HostResult:
    ip: str
    hostname: str | None = None
    state: str = "up"
    latency_ms: float | None = None
    os_hint: str | None = None
    ports: list[PortResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    tool: str
    version: str
    command: str
    targets: list[str]
    started: float
    finished: float
    hosts: list[HostResult] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        return self.finished - self.started

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "version": self.version,
            "command": self.command,
            "targets": self.targets,
            "started": self.started,
            "finished": self.finished,
            "elapsed_seconds": round(self.elapsed, 3),
            "stats": self.stats,
            "hosts": [h.to_dict() for h in self.hosts],
        }
