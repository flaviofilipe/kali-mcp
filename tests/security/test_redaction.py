"""core.audit.redact() must mask secret-shaped values before they're logged."""

from __future__ import annotations

from core.audit import redact


def test_password_masked():
    out = redact({"username": "admin", "password": "SuperSecret123"})
    assert out["username"] == "admin"
    assert out["password"] != "SuperSecret123"
    assert "SuperSecret123" not in out["password"]
    assert out["password"].startswith("Su")
    assert out["password"].endswith("23")


def test_hash_value_masked():
    out = redact({"hash_value": "5f4dcc3b5aa765d61d8327deb882cf99"})
    assert "5f4dcc3b5aa765d61d8327deb882cf99" not in out["hash_value"]


def test_confirmation_token_masked():
    out = redact({"confirmation_token": "abcdef0123456789"})
    assert "abcdef0123456789" not in out["confirmation_token"]


def test_short_secret_fully_masked():
    out = redact({"password": "ab"})
    assert out["password"] == "***"


def test_non_sensitive_fields_untouched():
    out = redact({"target": "10.0.0.5", "port": 445, "service": "smb"})
    assert out == {"target": "10.0.0.5", "port": 445, "service": "smb"}


def test_nested_dict_redacted():
    out = redact({"options": {"password": "hunter2", "user": "admin"}})
    assert "hunter2" not in out["options"]["password"]
    assert out["options"]["user"] == "admin"


def test_none_value_left_as_none():
    out = redact({"password": None})
    assert out["password"] is None
