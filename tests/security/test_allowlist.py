"""
Regression tests for the allowlist bypass fixed in core.security.is_allowed().

The original implementation matched with `entry in normalized`, a raw
substring check with no boundary. That allowed, e.g., an allowlisted
"test.com" to also authorize "test.com.evil-domain.net" or "eviltest.com",
and an allowlisted "10.0.0.5" to also authorize "10.0.0.50" — none of which
have any real relationship to the authorized entry.
"""

from __future__ import annotations

import sqlite3

import pytest

import core.db as db
import core.security as security


@pytest.fixture
def allowlist_db(tmp_path, monkeypatch):
    """Points core.db at a throwaway SQLite DB with a fresh schema."""
    db_path = tmp_path / "findings.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    db.init_db()
    return db_path


def _add_entry(db_path, entry: str, note: str = "") -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO allowlist (entry, added, note) VALUES (?, datetime('now'), ?)",
            (entry.lower(), note),
        )
        conn.commit()


# ── Empty allowlist ─────────────────────────────────────────────────────────


def test_empty_allowlist_blocks_everything(allowlist_db):
    assert security.is_allowed("example.com") is False
    assert security.is_allowed("10.0.0.1") is False


# ── Hostname: exact + subdomain matches (legitimate cases) ─────────────────


def test_hostname_exact_match(allowlist_db):
    _add_entry(allowlist_db, "test.com")
    assert security.is_allowed("test.com") is True


def test_hostname_subdomain_dot_boundary_match(allowlist_db):
    _add_entry(allowlist_db, "test.com")
    assert security.is_allowed("sub.test.com") is True
    assert security.is_allowed("deep.sub.test.com") is True


def test_hostname_match_strips_scheme_port_path(allowlist_db):
    _add_entry(allowlist_db, "test.com")
    assert security.is_allowed("https://test.com:8443/admin") is True


# ── Hostname bypass regression: no substring matching ───────────────────────


def test_hostname_suffix_bypass_blocked(allowlist_db):
    """'test.com' must NOT authorize 'test.com.evil-domain.net'."""
    _add_entry(allowlist_db, "test.com")
    assert security.is_allowed("test.com.evil-domain.net") is False


def test_hostname_prefix_bypass_blocked(allowlist_db):
    """'test.com' must NOT authorize 'eviltest.com' (substring, not a subdomain)."""
    _add_entry(allowlist_db, "test.com")
    assert security.is_allowed("eviltest.com") is False


def test_hostname_embedded_substring_bypass_blocked(allowlist_db):
    """'test.com' must NOT authorize 'nottest.commercial.net' etc."""
    _add_entry(allowlist_db, "test.com")
    assert security.is_allowed("nottest.com.attacker.io") is False
    assert security.is_allowed("mytest.comrade.net") is False


# ── IP: exact + CIDR matches (legitimate cases) ─────────────────────────────


def test_ip_exact_match(allowlist_db):
    _add_entry(allowlist_db, "10.0.0.5")
    assert security.is_allowed("10.0.0.5") is True


def test_cidr_match(allowlist_db):
    _add_entry(allowlist_db, "10.0.0.0/24")
    assert security.is_allowed("10.0.0.1") is True
    assert security.is_allowed("10.0.0.254") is True


def test_cidr_out_of_range_blocked(allowlist_db):
    _add_entry(allowlist_db, "10.0.0.0/24")
    assert security.is_allowed("10.0.1.1") is False


# ── IP bypass regression: no substring matching ─────────────────────────────


def test_ip_substring_bypass_blocked(allowlist_db):
    """'10.0.0.5' must NOT authorize '10.0.0.50' (substring, not the same host)."""
    _add_entry(allowlist_db, "10.0.0.5")
    assert security.is_allowed("10.0.0.50") is False


def test_ip_substring_bypass_blocked_other_direction(allowlist_db):
    """'10.0.0.50' must NOT authorize '10.0.0.5' either."""
    _add_entry(allowlist_db, "10.0.0.50")
    assert security.is_allowed("10.0.0.5") is False


# ── Unrelated targets stay blocked ──────────────────────────────────────────


def test_unrelated_target_blocked(allowlist_db):
    _add_entry(allowlist_db, "test.com")
    _add_entry(allowlist_db, "10.0.0.0/24")
    assert security.is_allowed("totally-different.org") is False
    assert security.is_allowed("192.168.1.1") is False
