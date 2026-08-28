"""
Allowlist enforcement and rate limiting.

Every tool that executes something inside the Kali container goes through
core.docker_exec.exec_in_kali(), which calls is_allowed() and rate_limit()
from here — no tool module re-implements this logic on its own.
"""

from __future__ import annotations

import ipaddress
import time

from core.db import allowlist_entries

# ── Allowlist ────────────────────────────────────────────────────────────────


def is_allowed(target: str) -> bool:
    """
    Checks whether the target (IP, hostname, or URL) is in the allowlist.

    Hostname entries only match on an exact match or a dot-bounded suffix
    (subdomain) match — never a raw substring. This prevents a bypass like
    an allowlisted "test.com" also matching "test.com.evil-domain.net" or
    "eviltest.com", both of which are unrelated domains.

    IP/CIDR entries are compared as actual network membership via the
    `ipaddress` module, so "10.0.0.5" does NOT match "10.0.0.50".
    """
    entries = allowlist_entries()
    if not entries:
        return False

    # Normalize: strip URL scheme and port to compare host/IP only
    normalized = target.lower().split("://")[-1].split("/")[0].split(":")[0]

    try:
        target_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(normalized)
    except ValueError:
        target_ip = None

    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            # Not a valid IP/CIDR — treat as a hostname entry.
            if normalized == entry or normalized.endswith(f".{entry}"):
                return True
            continue

        # Entry is a valid IP/CIDR: only a real network-membership match counts.
        if target_ip is not None and target_ip in network:
            return True

    return False


# ── Rate limiting ────────────────────────────────────────────────────────────

# Minimum interval in seconds between calls to the same tool.
RATE_LIMITS: dict[str, float] = {
    "ping":      1.0,
    "nmap":      5.0,
    "subfinder": 3.0,
    "gobuster":  3.0,
    "katana":    3.0,
    "nikto":     3.0,
    "testssl":   3.0,
    "nuclei":    5.0,
    "dalfox":    3.0,
    "hydra":    10.0,
    "sqlmap":    5.0,
    "gowitness": 2.0,
    "wpscan":   10.0,
    "curl":      1.0,
    "ffuf":      3.0,
    "mysql":     2.0,
}
_last_call_time: dict[str, float] = {}


def rate_limit(tool_name: str) -> None:
    now      = time.monotonic()
    interval = RATE_LIMITS.get(tool_name, 2.0)
    wait     = interval - (now - _last_call_time.get(tool_name, 0.0))
    if wait > 0:
        time.sleep(wait)
    _last_call_time[tool_name] = time.monotonic()
