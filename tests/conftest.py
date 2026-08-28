"""Shared pytest fixtures. Nothing here ever touches a real Docker daemon."""

from __future__ import annotations

import sys
from pathlib import Path

# Make the repo root importable as `server`, `core`, `tools`, etc. without
# requiring the package to be installed.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
