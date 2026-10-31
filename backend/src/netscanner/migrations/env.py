# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Alembic environment: builds the engine from the validated settings."""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy import Connection

from netscanner.core.config import load_settings_or_exit
from netscanner.core.db import create_engine

# Metadata of the business tables; empty until add-data-provenance-model.
target_metadata = None


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _run_online() -> None:
    settings = context.config.attributes.get("settings") or load_settings_or_exit()
    engine = create_engine(settings)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline migrations are not supported")
asyncio.run(_run_online())
