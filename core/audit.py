"""
Audit logging: every execution (allowed, blocked, or errored) is recorded
to ~/.kali-mcp/audit.log via the stdlib logging module.
"""

from __future__ import annotations

import logging
from typing import Any

from core.config import LOG_PATH

logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
audit = logging.getLogger("audit")

# ── Redaction ────────────────────────────────────────────────────────────────
# Substrings of a dict key that mark its value as sensitive. Matched
# case-insensitively against the key name, so "password", "http_form_data"'s
# nested ^PASS^ placeholder (not a real secret) is left alone, but "password",
# "passwd", "hash_value", "secret", "token", "credential" etc. are masked.
_SENSITIVE_KEY_MARKERS = (
    "password", "passwd", "pwd", "pass_",
    "hash_value", "hash", "secret", "token", "credential", "cracked_plaintext",
    "api_key", "apikey", "private_key",
)


def _looks_sensitive(key: str) -> bool:
    low = key.lower()
    return any(marker in low for marker in _SENSITIVE_KEY_MARKERS)


def _mask(value: Any) -> str:
    s = str(value)
    if len(s) <= 4:
        return "***"
    return f"{s[:2]}***{s[-2:]}"


def redact(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Returns a copy of payload with any value whose key looks sensitive
    (password, hash_value, secret, token, credential, ...) masked as
    "pa***23" instead of appearing in the clear.

    Used before logging tool parameters to the audit log or persisting them
    anywhere outside the encrypted credentials table. Nested dicts are
    redacted recursively; lists are left as-is (no known caller puts secrets
    inside a list).
    """
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            out[key] = value
        elif isinstance(value, dict):
            out[key] = redact(value)
        elif _looks_sensitive(key):
            out[key] = _mask(value)
        else:
            out[key] = value
    return out
