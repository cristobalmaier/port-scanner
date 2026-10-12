"""
Netscope — fast, dependency-free network reconnaissance toolkit.

A pure-Python (standard library only) TCP/UDP port scanner with service and
version detection, TLS/HTTP analysis and active security checks, designed as a
lightweight, auditable alternative to nmap for the reconnaissance phase of a
penetration test.

Only use it against systems you own or are explicitly authorised to test.
"""

from .constants import __version__

__all__ = ["__version__"]
