# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Shared fixtures.

Tests marked ``db`` need a PostgreSQL server given by ``NETSCANNER_TEST_DB_HOST``,
``_PORT``, ``_NAME``, ``_USER`` and ``_PASSWORD``. Without it they are skipped,
unless ``NETSCANNER_TEST_REQUIRE_DB=1`` (set in CI), which makes them fail.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from netscanner.core.config import ENV_PREFIX, Settings
from netscanner.core.db import create_engine, session_factory
from netscanner.migrate import upgrade
from netscanner.store.models import metadata
from netscanner.store.service import Store

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Canaries:
    """Random values used as secrets; they must never appear in any output."""

    secret_key: str
    db_password: str

    def all(self) -> list[str]:
        return [self.secret_key, self.db_password]

    def assert_absent(self, *texts: str) -> None:
        for output in texts:
            for canary in self.all():
                assert canary not in output


@pytest.fixture
def canaries() -> Canaries:
    return Canaries(
        secret_key="canary-sk-" + secrets.token_hex(12),
        db_password="canary-pw-" + secrets.token_hex(12),
    )


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """No NETSCANNER_* setting from the developer's shell leaks into a test."""
    for name in list(os.environ):
        if name.startswith(ENV_PREFIX) and not name.startswith(ENV_PREFIX + "TEST_"):
            monkeypatch.delenv(name)


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def closed_port() -> int:
    """A local port with nothing listening on it.

    Linux refuses the connection at once; Windows retries and the attempt
    times out, so tests accept either category (see ``REFUSED``).
    """
    return free_port()


REFUSED = r"\((?:connection refused|timeout)\)"


@dataclass(frozen=True)
class TestDatabase:
    __test__ = False

    host: str
    port: int
    name: str
    user: str
    password: str


@pytest.fixture(scope="session")
def test_db() -> TestDatabase:
    host = os.environ.get("NETSCANNER_TEST_DB_HOST")
    if not host:
        if os.environ.get("NETSCANNER_TEST_REQUIRE_DB") == "1":
            pytest.fail("NETSCANNER_TEST_DB_HOST is required (NETSCANNER_TEST_REQUIRE_DB=1)")
        pytest.skip("no test database (set NETSCANNER_TEST_DB_HOST)")
    return TestDatabase(
        host=host,
        port=int(os.environ.get("NETSCANNER_TEST_DB_PORT", "5432")),
        name=os.environ.get("NETSCANNER_TEST_DB_NAME", "netscanner"),
        user=os.environ.get("NETSCANNER_TEST_DB_USER", "netscanner"),
        password=os.environ["NETSCANNER_TEST_DB_PASSWORD"],
    )


def make_settings(canaries: Canaries, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "secret_key": canaries.secret_key,
        "db_password": canaries.db_password,
        "db_host": "127.0.0.1",
        "db_connect_timeout": 2.0,
    }
    values.update(overrides)
    return Settings(**values)


def db_settings(canaries: Canaries, db: TestDatabase, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "db_host": db.host,
        "db_port": db.port,
        "db_name": db.name,
        "db_user": db.user,
        "db_password": db.password,
    }
    values.update(overrides)
    return make_settings(canaries, **values)


def run_module(
    module: str, env: dict[str, str], timeout: float = 30
) -> subprocess.CompletedProcess:
    """Run ``python -m module`` with only the given NETSCANNER_* variables."""
    base = {k: v for k, v in os.environ.items() if not k.startswith(ENV_PREFIX)}
    return subprocess.run(
        [sys.executable, "-m", module],
        env={**base, **env},
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


# --- Databases for the persistence layer ------------------------------------


async def _admin(db: TestDatabase, statement: str) -> None:
    conn = await asyncpg.connect(
        host=db.host, port=db.port, user=db.user, password=db.password, database=db.name
    )
    try:
        await conn.execute(statement)
    finally:
        await conn.close()


@contextmanager
def fresh_database(db: TestDatabase) -> Iterator[Settings]:
    """A new empty database for one test session or test; dropped afterwards."""
    name = "netscanner_test_" + secrets.token_hex(6)
    asyncio.run(_admin(db, f'CREATE DATABASE "{name}"'))
    try:
        yield Settings(
            secret_key="test-only-" + secrets.token_hex(12),
            db_password=db.password,
            db_host=db.host,
            db_port=db.port,
            db_name=name,
            db_user=db.user,
        )
    finally:
        asyncio.run(_admin(db, f'DROP DATABASE "{name}" WITH (FORCE)'))


@pytest.fixture(scope="session")
def store_settings(test_db: TestDatabase) -> Iterator[Settings]:
    """Settings of a database migrated to the latest revision, shared by the session."""
    with fresh_database(test_db) as settings:
        assert upgrade(settings) == 0
        yield settings


KEPT_ROWS = {"discovery_settings"}
RESET_SETTINGS = (
    "UPDATE discovery_settings SET seeds = '{}', allowed_ranges = '{}', exclusions = '{}',"
    " max_depth = 1, follow_ip_mac = false, max_candidates = 4096, max_devices = 256,"
    " max_datagrams = 50000"
)


@pytest.fixture
async def engine(store_settings: Settings) -> AsyncIterator[AsyncEngine]:
    engine = create_engine(store_settings)
    try:
        yield engine
    finally:
        async with engine.begin() as conn:
            tables = ", ".join(t.name for t in metadata.sorted_tables if t.name not in KEPT_ROWS)
            await conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
            # The settings row created by migration 0004 is reset, not removed.
            await conn.execute(text(RESET_SETTINGS))
        await engine.dispose()


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    async with session_factory(engine)() as session:
        yield session


class Clock:
    """A settable clock for the persistence layer."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> datetime:
        self.now += delta
        return self.now


T0 = datetime(2026, 10, 6, 9, 0, tzinfo=UTC)


@pytest.fixture
def clock() -> Clock:
    return Clock(T0)


@pytest.fixture
def store(engine: AsyncEngine, clock: Clock) -> Store:
    return Store(engine, clock=clock)


async def all_rows_text(engine: AsyncEngine) -> str:
    """Text form of every row of every table, to search for values never stored."""
    parts = []
    async with engine.connect() as conn:
        for table in metadata.sorted_tables:
            # Table names come from the model metadata, not from input.
            rows = await conn.execute(text(f"SELECT t::text FROM {table.name} t"))  # noqa: S608
            parts.extend(rows.scalars())
    return "\n".join(parts)


# --- SNMP lab (add-snmp-client-and-lab, design D10) -------------------------

LAB_DATA = REPO_ROOT / "lab" / "snmpsim" / "data"
LAB_REQUIREMENTS = REPO_ROOT / "lab" / "snmpsim" / "requirements.txt"


@dataclass(frozen=True)
class SnmpLab:
    """snmpsim serving the lab data; each device is selected by its community."""

    host: str
    port: int
    v3_user: str
    v3_auth_key: str
    v3_priv_key: str

    def secrets(self) -> list[str]:
        return [self.v3_auth_key, self.v3_priv_key]


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _lab_unavailable(reason: str) -> None:
    if os.environ.get("NETSCANNER_TEST_REQUIRE_LAB") == "1":
        pytest.fail(f"SNMP lab required (NETSCANNER_TEST_REQUIRE_LAB=1): {reason}")
    pytest.skip(f"SNMP lab not available: {reason}")


async def _answers(host: str, port: int, community: str) -> bool:
    from netscanner.snmp import get_table
    from netscanner.snmp.pysnmp_client import PySnmpClient
    from netscanner.snmp.walker import SnmpLimits

    from .snmp_targets import RESOLVER, authorized

    client = PySnmpClient(RESOLVER, SnmpLimits(timeout=1, retries=0))
    target = authorized(host, port, community)
    result = await client.walk_table(target, get_table("SNMPv2-MIB::system"), ["sysName"])
    return result.row_count == 1


async def _lab_answers(lab: SnmpLab) -> bool:
    return await _answers(lab.host, lab.port, "lab-sw-02")


@dataclass(frozen=True)
class _V3User:
    user: str
    auth_key: str
    priv_key: str


def _v3_user() -> _V3User:
    return _V3User(
        "lab-v3-user", "lab-auth-" + secrets.token_hex(8), "lab-priv-" + secrets.token_hex(8)
    )


@contextmanager
def _workdir(tmp_path_factory: pytest.TempPathFactory, name: str) -> Iterator[tuple[Path, bool]]:
    as_root = hasattr(os, "geteuid") and os.geteuid() == 0
    # As root, snmpsim drops to nobody, which cannot enter pytest's private
    # temporary directories: use a readable one of its own.
    work = (
        Path(tempfile.mkdtemp(prefix=f"netscanner-{name}-"))
        if as_root
        else tmp_path_factory.mktemp(name)
    )
    try:
        yield work, as_root
    finally:
        if as_root:
            shutil.rmtree(work, ignore_errors=True)


def _start_snmpsim(
    uv: str, work: Path, data: Path, host: str, port: int, v3: _V3User, as_root: bool
) -> tuple[subprocess.Popen, object]:
    """One snmpsim process serving ``data`` on ``host:port`` from its own pinned tools."""
    cache = work / ("cache-" + str(port))
    cache.mkdir()
    if as_root:
        for path in (work, data, cache, *data.iterdir()):
            path.chmod(0o777 if path.is_dir() else 0o644)
    args = [
        uv, "run", "--no-project", "--python", "3.12",
        "--with-requirements", str(LAB_REQUIREMENTS),
        "snmpsim-command-responder",
        f"--data-dir={data}", f"--cache-dir={cache}",
        f"--agent-udpv4-endpoint={host}:{port}",
        f"--v3-user={v3.user}", f"--v3-auth-key={v3.auth_key}",
        "--v3-auth-proto=SHA256", f"--v3-priv-key={v3.priv_key}", "--v3-priv-proto=AES",
    ]  # fmt: skip
    if as_root:
        # snmpsim refuses to run as root without a user to drop privileges to.
        args += ["--process-user=nobody", "--process-group=nogroup"]
    log = (work / f"snmpsim-{port}.log").open("wb")
    process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, cwd=work)
    return process, log


def _stop_snmpsim(process: subprocess.Popen, log: object) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
    log.close()  # type: ignore[attr-defined]


def _wait_ready(processes: list[subprocess.Popen], ready: object) -> None:
    deadline = time.monotonic() + 180  # the first run installs the tools
    while not asyncio.run(ready()):  # type: ignore[operator]
        if any(p.poll() is not None for p in processes) or time.monotonic() > deadline:
            _lab_unavailable("snmpsim did not start (see its log in the pytest temp dir)")


@pytest.fixture(scope="session")
def snmp_lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SnmpLab]:
    """snmpsim with the lab data on a free local port; each device by its community."""
    uv = shutil.which("uv")
    if uv is None:
        _lab_unavailable("uv is not installed")
    with _workdir(tmp_path_factory, "snmpsim") as (work, as_root):
        data = work / "data"
        shutil.copytree(LAB_DATA, data)  # indexes are written next to the data
        v3 = _v3_user()
        lab = SnmpLab("127.0.0.1", free_udp_port(), v3.user, v3.auth_key, v3.priv_key)
        process, log = _start_snmpsim(uv, work, data, lab.host, lab.port, v3, as_root)  # type: ignore[arg-type]
        try:
            _wait_ready([process], lambda: _lab_answers(lab))
            yield lab
        finally:
            _stop_snmpsim(process, log)


# --- Discovery lab (add-discovery-and-basic-inventory, design D4) -----------

LAB_COMMUNITY = "netscanner-lab"
# Lab devices by management address (lab/manifest.yaml).
LAB_DEVICES = {"10.99.0.13": "srx-01", "10.99.0.2": "lab-sw-01", "10.99.0.3": "lab-sw-02"}


@dataclass(frozen=True)
class DiscoveryLab:
    """One snmpsim per lab device, each serving its data under the lab community.

    As in Compose, one credential serves the whole lab: the data file of each
    process is named after the community (and SNMPv3 context) ``netscanner-lab``.
    """

    host: str
    ports: dict[str, int]  # lab address -> local UDP port
    v3_user: str
    v3_auth_key: str
    v3_priv_key: str
    community: str = LAB_COMMUNITY

    def secrets(self) -> list[str]:
        return [self.v3_auth_key, self.v3_priv_key]


@pytest.fixture(scope="session")
def discovery_lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[DiscoveryLab]:
    uv = shutil.which("uv")
    if uv is None:
        _lab_unavailable("uv is not installed")
    with _workdir(tmp_path_factory, "discovery-lab") as (work, as_root):
        v3 = _v3_user()
        lab = DiscoveryLab(
            "127.0.0.1",
            {address: free_udp_port() for address in LAB_DEVICES},
            v3.user,
            v3.auth_key,
            v3.priv_key,
        )
        started = []
        try:
            for i, (address, label) in enumerate(LAB_DEVICES.items()):
                data = work / label
                data.mkdir()
                shutil.copyfile(LAB_DATA / f"{label}.snmprec", data / f"{LAB_COMMUNITY}.snmprec")
                port = lab.ports[address]
                started.append(_start_snmpsim(uv, work, data, lab.host, port, v3, as_root))  # type: ignore[arg-type]
                if i == 0:
                    # The first process installs the pinned tools; the others reuse them,
                    # so concurrent installs into the same environment cannot collide.
                    _wait_ready(
                        [started[0][0]], lambda p=port: _answers(lab.host, p, LAB_COMMUNITY)
                    )

            async def ready() -> bool:
                answers = [await _answers(lab.host, p, LAB_COMMUNITY) for p in lab.ports.values()]
                return all(answers)

            _wait_ready([p for p, _ in started], ready)
            yield lab
        finally:
            for process, log in started:
                _stop_snmpsim(process, log)
