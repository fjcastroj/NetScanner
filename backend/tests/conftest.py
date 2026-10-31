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
import socket
import subprocess
import sys
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


@pytest.fixture
async def engine(store_settings: Settings) -> AsyncIterator[AsyncEngine]:
    engine = create_engine(store_settings)
    try:
        yield engine
    finally:
        async with engine.begin() as conn:
            tables = ", ".join(t.name for t in metadata.sorted_tables)
            await conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
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
