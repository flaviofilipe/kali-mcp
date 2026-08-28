"""
Docker container access: fetching the running kali-mcp-box container and
executing commands inside it via execve (container.exec_run() with a list
of args — never a shell string), gated by the allowlist and rate limiter.
"""

from __future__ import annotations

import docker
from docker.errors import APIError, DockerException, NotFound

from core.audit import audit
from core.config import CONTAINER_NAME
from core.db import ExecResult, save_finding, save_scan_output
from core.security import is_allowed, rate_limit


def get_container() -> docker.models.containers.Container:
    try:
        client = docker.from_env()
    except DockerException as exc:
        raise RuntimeError(
            "Could not connect to Docker. "
            "Check that the daemon is running: sudo systemctl start docker"
        ) from exc

    try:
        container = client.containers.get(CONTAINER_NAME)
    except NotFound:
        raise RuntimeError(
            f"Container '{CONTAINER_NAME}' not found. "
            "Build and start it: cd ~/mcps/kali-mcp && docker compose up -d --build"
        )

    if container.status != "running":
        raise RuntimeError(
            f"Container '{CONTAINER_NAME}' exists but is not running "
            f"(status: {container.status}). Run: docker compose up -d"
        )

    return container


def exec_in_kali(
    cmd: list[str],
    tool_name: str,
    target: str,
    skip_allowlist: bool = False,
) -> ExecResult:
    """
    Executes cmd inside the Kali container via execve (no intermediate shell).
    Applies allowlist verification, rate limiting, and stores the result in the database.
    """
    if not cmd or not all(isinstance(a, str) for a in cmd):
        raise ValueError("`cmd` must be a non-empty list of strings.")

    if not skip_allowlist and not is_allowed(target):
        result = ExecResult(
            tool=tool_name, target=target, exit_code=-1, success=False, output="",
            error=(
                f"Target '{target}' is not in the allowlist. "
                "Use manage_allowlist(action='add', entry='<target>') to authorize it."
            ),
        )
        audit.warning("BLOCKED | tool=%s target=%s | not in allowlist", tool_name, target)
        return result

    rate_limit(tool_name)

    try:
        container = get_container()
        exit_code, raw = container.exec_run(
            cmd,
            demux=False,
            stdout=True,
            stderr=True,
        )
        output = raw.decode("utf-8", errors="replace").strip() if raw else ""
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=exit_code, success=(exit_code == 0), output=output,
        )

    except RuntimeError as exc:
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=-1, success=False, output="", error=str(exc),
        )
    except APIError as exc:
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=-1, success=False, output="",
            error=f"Docker API error: {exc.explanation}",
        )

    audit.info(
        "tool=%s target=%s exit_code=%d success=%s",
        tool_name, target, result.exit_code, result.success,
    )
    save_finding(result)
    save_scan_output(result)
    return result
