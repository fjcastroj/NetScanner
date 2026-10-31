# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Database engine, sessions and error classification (design D6, D12)."""

from __future__ import annotations

import asyncio
import socket

import asyncpg
from sqlalchemy import URL, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from netscanner.core.config import Settings


def database_url(settings: Settings) -> URL:
    """Build the connection URL from separate settings.

    The result must never be logged with ``render_as_string(hide_password=False)``;
    its default text form hides the password.
    """
    return URL.create(
        "postgresql+asyncpg",
        username=settings.db_user,
        password=settings.db_password.get_secret_value(),
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )


def create_engine(settings: Settings) -> AsyncEngine:
    # pool_pre_ping replaces connections left stale by a database restart.
    return create_async_engine(
        database_url(settings),
        pool_pre_ping=True,
        connect_args={"timeout": settings.db_connect_timeout},
    )


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def ping(engine: AsyncEngine, timeout: float) -> None:
    """Run ``SELECT 1``; raise on any failure, including a timeout."""
    async with asyncio.timeout(timeout):
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))


def classify_db_error(exc: BaseException) -> str:
    """Map a database failure to a short category without its text.

    Exception messages can contain host names or connection details, so only
    the category is ever logged.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(
            current,
            asyncpg.InvalidPasswordError | asyncpg.InvalidAuthorizationSpecificationError,
        ):
            return "authentication failed"
        if isinstance(current, asyncpg.InvalidCatalogNameError):
            return "database not found"
        if isinstance(current, TimeoutError):
            return "timeout"
        if isinstance(current, ConnectionRefusedError):
            return "connection refused"
        if isinstance(current, socket.gaierror):
            return "host not found"
        if isinstance(current, ConnectionError):
            return "connection lost"
        if isinstance(current, OSError):
            return "host unreachable"
        if isinstance(current, asyncpg.CannotConnectNowError):
            return "database starting up"
        current = getattr(current, "orig", None) or current.__cause__ or current.__context__
    return "database error"
