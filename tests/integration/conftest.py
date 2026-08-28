"""
Integration test fixtures. These run against a real, ephemeral Kali
container (kali-mcp-box-test) and real lab targets (juice-shop-test,
samba-test), all defined in docker-compose.test.yml — never the production
kali-mcp-box container, and never the internet.

Bring the lab up before running this suite:
    docker compose -f docker-compose.test.yml up -d --build

If kali-mcp-box-test isn't running, every test in tests/integration/ is
skipped rather than failed — tests/unit/ and tests/security/ are the ones
required to pass with no Docker at all.
"""

from __future__ import annotations

import time

import docker
import pytest

import core.db as db
import core.docker_exec as docker_exec

TEST_CONTAINER_NAME = "kali-mcp-box-test"
JUICE_SHOP_TARGET = "juice-shop-test"
SAMBA_TARGET = "samba-test"


def _test_container_running() -> bool:
    try:
        client = docker.from_env()
        container = client.containers.get(TEST_CONTAINER_NAME)
        return container.status == "running"
    except Exception:
        return False


requires_test_lab = pytest.mark.skipif(
    not _test_container_running(),
    reason=(
        f"{TEST_CONTAINER_NAME} is not running — bring up the test lab first: "
        "docker compose -f docker-compose.test.yml up -d --build"
    ),
)


@pytest.fixture(scope="module")
def test_lab(tmp_path_factory, monkeypatch_module):
    """Points the whole app at the test container + a throwaway DB, and allowlists the lab targets."""
    db_path = tmp_path_factory.mktemp("integration-db") / "findings.db"
    monkeypatch_module.setattr(db, "DB_PATH", db_path)
    monkeypatch_module.setattr(db, "OUTPUTS_DIR", tmp_path_factory.mktemp("integration-outputs"))
    monkeypatch_module.setattr(db, "SECRET_KEY_PATH", tmp_path_factory.mktemp("integration-key") / "secret.key")
    monkeypatch_module.setattr(docker_exec, "CONTAINER_NAME", TEST_CONTAINER_NAME)

    db.init_db()
    db.allowlist_add(JUICE_SHOP_TARGET, note="integration test lab target")
    db.allowlist_add(SAMBA_TARGET, note="integration test lab target")

    _wait_for_reachable(JUICE_SHOP_TARGET)
    return {"juice_shop": JUICE_SHOP_TARGET, "samba": SAMBA_TARGET}


def _wait_for_reachable(target: str, attempts: int = 20, delay: float = 2.0) -> None:
    """Best-effort readiness wait — pings the target from inside the Kali container."""
    for _ in range(attempts):
        result = docker_exec.exec_in_kali(["ping", "-c", "1", "-W", "2", target], "ping", target)
        if result.success:
            return
        time.sleep(delay)
    # Don't fail here — let the individual test surface a clear failure if the
    # target really is unreachable; this is just a startup grace period.


@pytest.fixture(scope="module")
def monkeypatch_module():
    """A module-scoped MonkeyPatch — pytest's built-in `monkeypatch` fixture is function-scoped."""
    from _pytest.monkeypatch import MonkeyPatch

    mp = MonkeyPatch()
    yield mp
    mp.undo()
