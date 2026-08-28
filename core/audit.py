"""
Audit logging: every execution (allowed, blocked, or errored) is recorded
to ~/.kali-mcp/audit.log via the stdlib logging module.
"""

from __future__ import annotations

import logging

from core.config import LOG_PATH

logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
audit = logging.getLogger("audit")
