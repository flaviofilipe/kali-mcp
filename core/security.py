"""
Allowlist enforcement and rate limiting.

Every tool that executes something inside the Kali container goes through
core.docker_exec.exec_in_kali(), which calls is_allowed() and rate_limit()
from here — no tool module re-implements this logic on its own.
"""

from __future__ import annotations

import ipaddress
import time
import uuid
from datetime import datetime

from core.config import CONFIRMATION_TTL_SECONDS
from core.db import allowlist_entries, get_confirmation, insert_confirmation, mark_confirmation_used

# ── Allowlist ────────────────────────────────────────────────────────────────


def normalize_target(target: str) -> str:
    """Strips URL scheme, path, and port so only the host/IP is compared."""
    return target.lower().split("://")[-1].split("/")[0].split(":")[0]


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

    normalized = normalize_target(target)

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


# ── High-risk action confirmation gate ──────────────────────────────────────
#
# Some actions (credential dumping, lateral movement, opening a pivot tunnel,
# Mimikatz, write/exec modes of AD enumeration tools) are gated behind a
# short-lived, single-use confirmation token: request_high_risk_action()
# issues one, and the gated tool must pass it back in `confirmation_token`.
# The token is bound to the exact (action, target) pair it was issued for —
# it can't be reused for a different target or a different action, and it
# can't be replayed once consumed.


def issue_confirmation_token(action: str, target: str, justification: str) -> dict[str, str]:
    token      = uuid.uuid4().hex
    expires_at = insert_confirmation(token, action, normalize_target(target), justification, CONFIRMATION_TTL_SECONDS)
    return {"token": token, "action": action, "target": target, "expires_at": expires_at}


def consume_confirmation(token: str, action: str, target: str) -> tuple[bool, str | None]:
    """
    Validates a high-risk confirmation token and marks it used (single-use).

    Returns (True, None) on success, or (False, error_message) otherwise.
    Never raises — callers should surface error_message as the tool's error.
    """
    if not token:
        return False, (
            f"This action ('{action}') requires a confirmation_token. "
            "Call request_high_risk_action(action=..., target=..., justification=...) first."
        )

    record = get_confirmation(token)
    if record is None:
        return False, "Invalid confirmation_token."
    if record["used_at"]:
        return False, "This confirmation_token has already been used. Request a new one."
    if record["action"] != action:
        return False, f"This confirmation_token was issued for action '{record['action']}', not '{action}'."
    if record["target"] != normalize_target(target):
        return False, f"This confirmation_token was issued for target '{record['target']}', not '{target}'."
    if datetime.fromisoformat(record["expires_at"]) < datetime.now():
        return False, "This confirmation_token has expired. Request a new one."

    mark_confirmation_used(token)
    return True, None
