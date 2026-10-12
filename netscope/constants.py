"""Static data: version, colour codes, timing profiles and curated port lists."""

from __future__ import annotations

__version__ = "2.0.0"

TOOL_NAME = "netscope"

# ── ANSI colours ────────────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GRAY = "\033[90m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

# Risk levels ordered from most to least severe.
LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
LEVEL_COLOR = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": CYAN,
    "INFO": GRAY,
}

# ── Timing profiles (inspired by nmap -T0..-T5) ─────────────────────────────
# concurrency: simultaneous in-flight sockets
# timeout:     per-port connect/read timeout in seconds
# delay:       per-probe delay (politeness), in seconds
TIMING_PROFILES = {
    0: {"name": "paranoid", "concurrency": 5, "timeout": 6.0, "delay": 0.5},
    1: {"name": "sneaky", "concurrency": 20, "timeout": 4.0, "delay": 0.2},
    2: {"name": "polite", "concurrency": 100, "timeout": 2.5, "delay": 0.05},
    3: {"name": "normal", "concurrency": 500, "timeout": 1.5, "delay": 0.0},
    4: {"name": "aggressive", "concurrency": 1500, "timeout": 1.0, "delay": 0.0},
    5: {"name": "insane", "concurrency": 4000, "timeout": 0.5, "delay": 0.0},
}

# Curated "most commonly open" ports. Ordered by real-world frequency so that
# --top-ports N yields the same spirit as nmap's top-ports list.
TOP_PORTS = [
    80, 443, 22, 21, 25, 3389, 110, 445, 139, 143,
    53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025,
    587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000,
    514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26,
    1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000,
    5631, 631, 49153, 8081, 2049, 88, 79, 5800, 2222, 1911,
    4444, 9090, 3000, 5001, 5432, 6379, 11211, 27017, 9200, 2375,
    6443, 5672, 15672, 5984, 7001, 7002, 8009, 9000, 9042, 7077,
    1099, 1521, 1701, 1883, 2181, 3260, 4369, 5222, 5269, 5280,
    6443, 7474, 8069, 8161, 8000, 8500, 8883, 8983, 9092, 9300,
    10050, 10051, 10250, 10255, 11211, 15672, 16379, 25565, 50070, 61616,
]

# Ports probed by the lightweight host-discovery step.
DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 8080, 21, 25, 3306, 8081]
