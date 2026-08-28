"""Unit tests for tools.secrets_js."""

from __future__ import annotations

import core.db as db
from tools import secrets_js


def test_trufflehog_filesystem_path_skips_allowlist(allowlist_db, fake_container, no_rate_limit):
    fake_container.when(lambda cmd: cmd[0] == "trufflehog", 0, "{}")
    result = secrets_js.scan_secrets_trufflehog(target_url_or_repo="/tmp/cloned-repo")
    assert result["success"] is True
    assert fake_container.calls[0][:2] == ["trufflehog", "filesystem"]


def test_trufflehog_remote_url_requires_allowlist(allowlist_db, fake_container, no_rate_limit):
    result = secrets_js.scan_secrets_trufflehog(target_url_or_repo="https://github.com/org/repo.git")
    assert result["success"] is False
    assert fake_container.calls == []


def test_trufflehog_remote_url_runs_once_allowlisted(allowlist_db, fake_container, no_rate_limit):
    db.allowlist_add("github.com")
    fake_container.when(lambda cmd: cmd[0] == "trufflehog", 0, "{}")
    result = secrets_js.scan_secrets_trufflehog(target_url_or_repo="https://github.com/org/repo.git")
    assert result["success"] is True
    assert fake_container.calls[0][:2] == ["trufflehog", "git"]


def test_scan_js_secretfinder_requires_allowlist(allowlist_db, fake_container, no_rate_limit):
    result = secrets_js.scan_js_secretfinder(target_url="http://app.local/main.js")
    assert result["success"] is False


def test_analyze_jwt_skips_allowlist(allowlist_db, fake_container, no_rate_limit):
    fake_container.when(lambda cmd: "jwt_tool.py" in cmd[1], 0, "alg: HS256\n")
    result = secrets_js.analyze_jwt(token="eyJhbGciOiJIUzI1NiJ9.e30.abc")
    assert result["success"] is True


def test_fingerprint_graphql_requires_allowlist(allowlist_db, fake_container, no_rate_limit):
    result = secrets_js.fingerprint_graphql_graphw00f(target_url="http://app.local/graphql")
    assert result["success"] is False
