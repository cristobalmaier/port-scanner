"""TLS metadata extraction using only the standard library.

``ssl`` can read the peer certificate in DER form; to decode it into a readable
dict we use the (private but stable) ``ssl._ssl._test_decode_cert`` on a
temporary PEM file, with a graceful fallback when it is unavailable.
"""

from __future__ import annotations

import os
import socket
import ssl
import tempfile


def _decode_der(der: bytes) -> dict:
    """Decode a DER certificate into a dict; ``{}`` on any failure."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        try:
            return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            os.unlink(path)
    except Exception:
        return {}


def _name(entry) -> str | None:
    """Flatten a ``((('commonName','x'),),)`` RDN tuple into ``'x'``."""
    if not entry:
        return None
    for rdn in entry:
        for key, value in rdn:
            if key in ("commonName", "organizationName"):
                return value
    try:
        return entry[0][0][1]
    except Exception:
        return None


def fetch_tls(ip: str, port: int, timeout: float = 3.0,
              server_hostname: str | None = None) -> dict | None:
    """Connect, perform a TLS handshake and return metadata, or ``None``."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Offer h2 so we can detect HTTP/2 support during the handshake.
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    raw = None
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=server_hostname or ip) as tls:
            info: dict = {
                "version": tls.version(),
                "cipher": (tls.cipher() or ("", "", 0))[0],
                "alpn": tls.selected_alpn_protocol(),
            }
            der = tls.getpeercert(binary_form=True)
            raw = None  # ownership transferred to the context manager
    except Exception:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass
        return None

    cert = _decode_der(der) if der else {}
    if cert:
        info["subject"] = _name(cert.get("subject"))
        info["issuer"] = _name(cert.get("issuer"))
        info["not_before"] = cert.get("notBefore")
        info["not_after"] = cert.get("notAfter")
        san = []
        for kind, value in cert.get("subjectAltName", ()):
            san.append(f"{kind}:{value}")
        if san:
            info["san"] = san[:20]
        if cert.get("serialNumber"):
            info["serial"] = cert["serialNumber"]
    # Flag weak protocol versions.
    if info.get("version") in ("TLSv1", "TLSv1.1"):
        info["weak_protocol"] = True
    return info
