"""
Confirmation gate: high-risk tools must refuse to run without a valid,
single-use, (action, target)-bound confirmation_token.
"""

from __future__ import annotations

import time

import pytest

import core.db as db
import core.security as security


@pytest.fixture
def confirmation_db(tmp_path, monkeypatch):
    db_path = tmp_path / "findings.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    db.init_db()
    return db_path


def test_missing_token_refused(confirmation_db):
    ok, error = security.consume_confirmation("", "impacket_secretsdump", "10.0.0.5")
    assert ok is False
    assert "confirmation_token" in error


def test_valid_token_accepted_and_consumed(confirmation_db):
    info = security.issue_confirmation_token("impacket_secretsdump", "10.0.0.5", "authorized pentest")
    ok, error = security.consume_confirmation(info["token"], "impacket_secretsdump", "10.0.0.5")
    assert ok is True
    assert error is None


def test_token_cannot_be_reused(confirmation_db):
    info = security.issue_confirmation_token("impacket_secretsdump", "10.0.0.5", "authorized pentest")
    ok1, _ = security.consume_confirmation(info["token"], "impacket_secretsdump", "10.0.0.5")
    ok2, error2 = security.consume_confirmation(info["token"], "impacket_secretsdump", "10.0.0.5")
    assert ok1 is True
    assert ok2 is False
    assert "already been used" in error2


def test_token_rejected_for_different_action(confirmation_db):
    info = security.issue_confirmation_token("impacket_secretsdump", "10.0.0.5", "authorized pentest")
    ok, error = security.consume_confirmation(info["token"], "run_mimikatz", "10.0.0.5")
    assert ok is False
    assert "issued for action" in error


def test_token_rejected_for_different_target(confirmation_db):
    info = security.issue_confirmation_token("impacket_secretsdump", "10.0.0.5", "authorized pentest")
    ok, error = security.consume_confirmation(info["token"], "impacket_secretsdump", "10.0.0.6")
    assert ok is False
    assert "issued for target" in error


def test_expired_token_rejected(confirmation_db, monkeypatch):
    monkeypatch.setattr(security, "CONFIRMATION_TTL_SECONDS", -1)  # expires immediately
    info = security.issue_confirmation_token("impacket_secretsdump", "10.0.0.5", "authorized pentest")
    ok, error = security.consume_confirmation(info["token"], "impacket_secretsdump", "10.0.0.5")
    assert ok is False
    assert "expired" in error


def test_invalid_token_rejected(confirmation_db):
    ok, error = security.consume_confirmation("not-a-real-token", "impacket_secretsdump", "10.0.0.5")
    assert ok is False
    assert "Invalid" in error
