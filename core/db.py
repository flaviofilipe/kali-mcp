"""
SQLite schema and persistence: findings, the allowlist table, and the
per-target output-directory session log used by resume_session().

Tool modules never talk to sqlite3 directly — they call _save_finding()
(via core.docker_exec) or the query helpers exposed here.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from core.config import DB_PATH, OUTPUTS_DIR

# ── Models ───────────────────────────────────────────────────────────────────


class ExecResult(BaseModel):
    """Standardized result of any execution inside the Kali container."""

    tool:      str
    target:    str
    exit_code: int
    success:   bool
    output:    str
    error:     str | None = None


# ── Schema ───────────────────────────────────────────────────────────────────


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                tool      TEXT    NOT NULL,
                target    TEXT    NOT NULL,
                timestamp TEXT    NOT NULL,
                exit_code INTEGER NOT NULL,
                success   INTEGER NOT NULL,
                output    TEXT,
                error     TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS allowlist (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                entry TEXT    NOT NULL UNIQUE,
                added TEXT    NOT NULL,
                note  TEXT
            )
        """)
        conn.commit()


init_db()


# ── Findings ─────────────────────────────────────────────────────────────────


def save_finding(result: ExecResult) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO findings (tool, target, timestamp, exit_code, success, output, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                result.tool,
                result.target,
                datetime.now().isoformat(),
                result.exit_code,
                int(result.success),
                result.output,
                result.error,
            ),
        )
        conn.commit()


def query_findings(target: str = "", limit: int = 50) -> list[tuple]:
    with sqlite3.connect(DB_PATH) as conn:
        if target:
            return conn.execute(
                "SELECT id, tool, target, timestamp, exit_code, success, error "
                "FROM findings WHERE target LIKE ? ORDER BY timestamp DESC LIMIT ?",
                (f"%{target}%", limit),
            ).fetchall()
        return conn.execute(
            "SELECT id, tool, target, timestamp, exit_code, success, error "
            "FROM findings ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()


def query_findings_full(target: str) -> list[tuple]:
    """Findings for a target including full output/error, oldest first (for reports)."""
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT tool, target, timestamp, exit_code, success, output, error "
            "FROM findings WHERE target LIKE ? ORDER BY timestamp ASC",
            (f"%{target}%",),
        ).fetchall()


# ── Allowlist ────────────────────────────────────────────────────────────────


def allowlist_add(entry: str, note: str = "") -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO allowlist (entry, added, note) VALUES (?, ?, ?)",
            (entry.lower(), datetime.now().isoformat(), note),
        )
        conn.commit()


def allowlist_remove(entry: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM allowlist WHERE entry = ?", (entry.lower(),))
        conn.commit()


def allowlist_list() -> list[tuple]:
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT entry, added, note FROM allowlist ORDER BY added"
        ).fetchall()


def allowlist_entries() -> list[str]:
    """Lowercased entry strings only — what _is_allowed() needs."""
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT entry FROM allowlist").fetchall()
    return [r[0].lower() for r in rows]


# ── Per-target output directory + session log ───────────────────────────────


def target_output_dir(target: str) -> Path:
    """Returns (and creates) ~/mcps/outputs/kali-mcp/<host>/ for the target."""
    host = target.lower().split("://")[-1].split("/")[0].split(":")[0]
    safe = re.sub(r"[^\w\-.]", "_", host)
    d = OUTPUTS_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_scan_output(result: ExecResult) -> None:
    """Persists output + updates session.json. Never raises."""
    try:
        out_dir = target_output_dir(result.target)
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname   = f"{result.tool}_{ts}.txt"
        body    = result.output or ""
        if result.error:
            body += f"\n\n[ERROR] {result.error}"
        (out_dir / fname).write_text(body, encoding="utf-8")

        session_path = out_dir / "session.json"
        session = (
            json.loads(session_path.read_text(encoding="utf-8"))
            if session_path.exists()
            else {"target": out_dir.name, "started": datetime.now().isoformat(), "scans": []}
        )
        session["scans"].append({
            "tool":      result.tool,
            "file":      fname,
            "success":   result.success,
            "exit_code": result.exit_code,
            "timestamp": datetime.now().isoformat(),
        })
        session["last_updated"] = datetime.now().isoformat()
        session_path.write_text(json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass  # persistence must never interrupt the scan
