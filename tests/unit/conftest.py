"""
Shared fixtures for tests/unit/: a throwaway allowlist DB and a fake Docker
container so exec_in_kali()'s real allowlist/rate-limit/audit/persistence
pipeline runs, but nothing ever touches a real Docker daemon.
"""

from __future__ import annotations

from typing import Callable

import pytest

import core.db as db
import core.docker_exec as docker_exec
import core.security as security


@pytest.fixture
def allowlist_db(tmp_path, monkeypatch):
    """Points core.db at a throwaway SQLite DB with a fresh schema."""
    db_path = tmp_path / "findings.db"
    monkeypatch.setattr(db, "DB_PATH", db_path)
    db.init_db()
    return db_path


@pytest.fixture
def no_rate_limit(monkeypatch):
    """Rate limiting has its own dedicated tests — everywhere else, skip the sleep."""
    monkeypatch.setattr(security, "rate_limit", lambda tool_name: None)


class FakeContainer:
    """
    Stands in for docker.models.containers.Container. `responses` maps a
    predicate over the exec_run cmd list to an (exit_code, output_bytes)
    pair; the first matching predicate wins. With no match, returns (0, b"").
    """

    def __init__(self) -> None:
        self.status = "running"
        self.calls: list[list[str]] = []
        self.responses: list[tuple[Callable[[list[str]], bool], tuple[int, bytes]]] = []

    def when(self, predicate: Callable[[list[str]], bool], exit_code: int, output: str) -> None:
        self.responses.append((predicate, (exit_code, output.encode("utf-8"))))

    def exec_run(self, cmd, demux=False, stdout=True, stderr=True):
        self.calls.append(cmd)
        for predicate, response in self.responses:
            if predicate(cmd):
                return response
        return (0, b"")


class _FakeContainers:
    def __init__(self, container: FakeContainer) -> None:
        self._container = container

    def get(self, name):
        return self._container


class _FakeDockerClient:
    def __init__(self, container: FakeContainer) -> None:
        self.containers = _FakeContainers(container)


@pytest.fixture
def fake_container(monkeypatch, tmp_path) -> FakeContainer:
    container = FakeContainer()
    monkeypatch.setattr(docker_exec.docker, "from_env", lambda: _FakeDockerClient(container))
    # exec_in_kali() always persists output to disk via core.db.target_output_dir()
    # (OUTPUTS_DIR) — keep that inside tmp_path instead of the real ~/mcps/outputs/.
    monkeypatch.setattr(db, "OUTPUTS_DIR", tmp_path / "outputs")
    return container
