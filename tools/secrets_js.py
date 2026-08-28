"""
Secrets / JS / API reconnaissance tools: git/filesystem secret scanning,
JavaScript secret extraction, JWT analysis, and GraphQL engine
fingerprinting.
"""

from __future__ import annotations

from typing import Any

from core.config import mcp
from core.docker_exec import exec_in_kali


@mcp.tool()
def scan_secrets_trufflehog(target_url_or_repo: str) -> dict[str, Any]:
    """
    Scans a git repository (cloned by TruffleHog itself, full history
    included) or a local filesystem path already inside the container for
    leaked secrets — API keys, credentials, tokens.

    A remote repo URL still goes through the normal allowlist check on its
    host (e.g. add "github.com", or your self-hosted git server, via
    manage_allowlist() first). A local filesystem path skips the allowlist.

    Args:
        target_url_or_repo: Git URL (e.g. "https://github.com/org/repo.git",
                            "git@gitlab.example.com:org/repo.git") or an
                            absolute filesystem path inside the container.
    """
    is_remote = target_url_or_repo.startswith(("http://", "https://", "git@"))
    cmd = ["trufflehog", "git" if is_remote else "filesystem", target_url_or_repo, "--json"]
    return exec_in_kali(
        cmd, tool_name="trufflehog", target=target_url_or_repo, skip_allowlist=not is_remote,
    ).model_dump()


@mcp.tool()
def scan_js_secretfinder(target_url: str) -> dict[str, Any]:
    """
    Scans a page's (or a direct .js file's) JavaScript for hardcoded
    secrets, API keys, and endpoints using SecretFinder.

    Args:
        target_url: URL of the page or JS file to scan.
    """
    cmd = ["python3", "/opt/secretfinder/SecretFinder.py", "-i", target_url, "-o", "cli"]
    return exec_in_kali(cmd, tool_name="secretfinder", target=target_url).model_dump()


@mcp.tool()
def analyze_jwt(token: str) -> dict[str, Any]:
    """
    Analyzes a JWT: decodes header/payload and runs jwt_tool's read-only
    playbook scan to flag common misconfigurations (alg=none acceptance,
    weak/guessable HMAC secret, missing expiry, known CVEs in the issuing
    library).

    Args:
        token: The JWT to analyze.
    """
    cmd = ["python3", "/opt/jwt_tool/jwt_tool.py", token, "-M", "pb"]
    return exec_in_kali(cmd, tool_name="jwt_tool", target="offline", skip_allowlist=True).model_dump()


@mcp.tool()
def fingerprint_graphql_graphw00f(target_url: str) -> dict[str, Any]:
    """
    Fingerprints the GraphQL engine behind an endpoint (Apollo, Hasura,
    Graphene, GraphQL-PHP, ...) using graphw00f, so you can target
    engine-specific known issues (e.g. introspection quirks, batching abuse).

    Args:
        target_url: GraphQL endpoint URL. E.g.: "http://app.local/graphql"
    """
    cmd = ["graphw00f", "-f", "-t", target_url]
    return exec_in_kali(cmd, tool_name="graphw00f", target=target_url).model_dump()
