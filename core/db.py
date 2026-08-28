"""
SQLite schema and persistence: findings, the allowlist table, and the
per-target output-directory session log used by resume_session().

Tool modules never talk to sqlite3 directly — they call _save_finding()
(via core.docker_exec) or the query helpers exposed here.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import BaseModel

from core.config import DB_PATH, OUTPUTS_DIR, SECRET_KEY_PATH

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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id           TEXT    PRIMARY KEY,
                target       TEXT    NOT NULL,
                session_type TEXT    NOT NULL,
                host         TEXT,
                port         INTEGER,
                status       TEXT    NOT NULL,
                opened_at    TEXT    NOT NULL,
                closed_at    TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id                          INTEGER PRIMARY KEY AUTOINCREMENT,
                target                      TEXT    NOT NULL,
                service                     TEXT,
                username                    TEXT,
                hash_type                   TEXT,
                hash_value_encrypted        BLOB,
                cracked_plaintext_encrypted BLOB,
                cracked_at                  TEXT,
                created_at                  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                target        TEXT    NOT NULL,
                cve           TEXT,
                exploit_db_id TEXT,
                tool_source   TEXT,
                found_at      TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS high_risk_confirmations (
                token         TEXT PRIMARY KEY,
                action        TEXT NOT NULL,
                target        TEXT NOT NULL,
                justification TEXT,
                issued_at     TEXT NOT NULL,
                expires_at    TEXT NOT NULL,
                used_at       TEXT
            )
        """)
        conn.commit()


init_db()


# ── Credential encryption ────────────────────────────────────────────────────
# Sensitive columns in `credentials` (hash_value, cracked plaintext) are never
# stored in the clear. The Fernet key lives at ~/.kali-mcp/secret.key with
# 0600 permissions, generated on first use. Anyone with both that file and
# findings.db can decrypt stored credentials — see SECURITY.md: treat
# ~/.kali-mcp/ itself as a secret.

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet

    if SECRET_KEY_PATH.exists():
        key = SECRET_KEY_PATH.read_bytes()
    else:
        key = Fernet.generate_key()
        SECRET_KEY_PATH.write_bytes(key)
        os.chmod(SECRET_KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    _fernet = Fernet(key)
    return _fernet


def _encrypt(value: str | None) -> bytes | None:
    if value is None:
        return None
    return _get_fernet().encrypt(value.encode("utf-8"))


def _decrypt(blob: bytes | None) -> str | None:
    if blob is None:
        return None
    return _get_fernet().decrypt(bytes(blob)).decode("utf-8")


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


# ── Sessions (reverse shells, SSH, evil-winrm, msf) ─────────────────────────


def create_session(
    session_id: str, target: str, session_type: str,
    host: str = "", port: int | None = None, status: str = "open",
) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO sessions (id, target, session_type, host, port, status, opened_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, target, session_type, host, port, status, datetime.now().isoformat()),
        )
        conn.commit()


def update_session_status(session_id: str, status: str, closed: bool = False) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        if closed:
            conn.execute(
                "UPDATE sessions SET status = ?, closed_at = ? WHERE id = ?",
                (status, datetime.now().isoformat(), session_id),
            )
        else:
            conn.execute("UPDATE sessions SET status = ? WHERE id = ?", (status, session_id))
        conn.commit()


def get_session(session_id: str) -> tuple | None:
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT id, target, session_type, host, port, status, opened_at, closed_at "
            "FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()


def list_sessions(target: str = "") -> list[tuple]:
    with sqlite3.connect(DB_PATH) as conn:
        if target:
            return conn.execute(
                "SELECT id, target, session_type, host, port, status, opened_at, closed_at "
                "FROM sessions WHERE target LIKE ? ORDER BY opened_at DESC",
                (f"%{target}%",),
            ).fetchall()
        return conn.execute(
            "SELECT id, target, session_type, host, port, status, opened_at, closed_at "
            "FROM sessions ORDER BY opened_at DESC"
        ).fetchall()


# ── Credentials (hash/plaintext columns always encrypted at rest) ──────────


def save_credential(
    target: str, service: str, username: str, hash_type: str,
    hash_value: str | None = None, cracked_plaintext: str | None = None,
) -> int:
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO credentials "
            "(target, service, username, hash_type, hash_value_encrypted, "
            " cracked_plaintext_encrypted, cracked_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target, service, username, hash_type,
                _encrypt(hash_value), _encrypt(cracked_plaintext),
                now if cracked_plaintext else None, now,
            ),
        )
        conn.commit()
        return cur.lastrowid


def mark_credential_cracked(credential_id: int, plaintext: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE credentials SET cracked_plaintext_encrypted = ?, cracked_at = ? WHERE id = ?",
            (_encrypt(plaintext), datetime.now().isoformat(), credential_id),
        )
        conn.commit()


def get_credential(credential_id: int) -> dict | None:
    """Returns a credential row with hash/plaintext decrypted for the caller."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, target, service, username, hash_type, hash_value_encrypted, "
            "cracked_plaintext_encrypted, cracked_at, created_at FROM credentials WHERE id = ?",
            (credential_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0], "target": row[1], "service": row[2], "username": row[3],
        "hash_type": row[4], "hash_value": _decrypt(row[5]),
        "cracked_plaintext": _decrypt(row[6]), "cracked_at": row[7], "created_at": row[8],
    }


def list_credentials(target: str = "") -> list[dict]:
    """Metadata only — never decrypts hash/plaintext for a bulk listing."""
    with sqlite3.connect(DB_PATH) as conn:
        if target:
            rows = conn.execute(
                "SELECT id, target, service, username, hash_type, "
                "(cracked_plaintext_encrypted IS NOT NULL) AS cracked, cracked_at, created_at "
                "FROM credentials WHERE target LIKE ? ORDER BY created_at DESC",
                (f"%{target}%",),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, target, service, username, hash_type, "
                "(cracked_plaintext_encrypted IS NOT NULL) AS cracked, cracked_at, created_at "
                "FROM credentials ORDER BY created_at DESC"
            ).fetchall()
    return [
        {
            "id": r[0], "target": r[1], "service": r[2], "username": r[3],
            "hash_type": r[4], "cracked": bool(r[5]), "cracked_at": r[6], "created_at": r[7],
        }
        for r in rows
    ]


# ── Exploits (searchsploit / nuclei CVE correlation) ────────────────────────


def save_exploit(target: str, cve: str, exploit_db_id: str, tool_source: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO exploits (target, cve, exploit_db_id, tool_source, found_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (target, cve, exploit_db_id, tool_source, datetime.now().isoformat()),
        )
        conn.commit()


def list_exploits(target: str = "") -> list[tuple]:
    with sqlite3.connect(DB_PATH) as conn:
        if target:
            return conn.execute(
                "SELECT id, target, cve, exploit_db_id, tool_source, found_at "
                "FROM exploits WHERE target LIKE ? ORDER BY found_at DESC",
                (f"%{target}%",),
            ).fetchall()
        return conn.execute(
            "SELECT id, target, cve, exploit_db_id, tool_source, found_at FROM exploits ORDER BY found_at DESC"
        ).fetchall()


# ── High-risk action confirmations ──────────────────────────────────────────


def insert_confirmation(token: str, action: str, target: str, justification: str, ttl_seconds: int) -> str:
    from datetime import timedelta

    issued_at  = datetime.now()
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO high_risk_confirmations "
            "(token, action, target, justification, issued_at, expires_at, used_at) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (token, action, target, justification, issued_at.isoformat(), expires_at.isoformat()),
        )
        conn.commit()
    return expires_at.isoformat()


def get_confirmation(token: str) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT token, action, target, justification, issued_at, expires_at, used_at "
            "FROM high_risk_confirmations WHERE token = ?",
            (token,),
        ).fetchone()
    if row is None:
        return None
    return {
        "token": row[0], "action": row[1], "target": row[2], "justification": row[3],
        "issued_at": row[4], "expires_at": row[5], "used_at": row[6],
    }


def mark_confirmation_used(token: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE high_risk_confirmations SET used_at = ? WHERE token = ?",
            (datetime.now().isoformat(), token),
        )
        conn.commit()
