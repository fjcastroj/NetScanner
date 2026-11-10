# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""The discovery settings row (design D6).

Storage only: validation against the scope rules and the server's ceilings
happens before saving (``netscanner.scope.settings``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from netscanner.store.errors import StoreError
from netscanner.store.models import discovery_settings

FIELDS = (
    "seeds",
    "allowed_ranges",
    "exclusions",
    "max_depth",
    "follow_ip_mac",
    "max_candidates",
    "max_devices",
    "max_datagrams",
)


def _text(value: Any) -> Any:
    if isinstance(value, list):
        return [str(v) for v in value]
    return value


async def read_discovery_settings(conn: AsyncConnection) -> dict[str, Any]:
    """The stored settings, addresses and ranges as text, with ``updated_at``."""
    row = (
        await conn.execute(select(discovery_settings).where(discovery_settings.c.id == 1))
    ).first()
    if row is None:
        raise StoreError("the discovery settings row is missing")
    values = {name: _text(row._mapping[name]) for name in FIELDS}
    values["updated_at"] = row.updated_at
    return values


async def save_discovery_settings(
    conn: AsyncConnection, values: dict[str, Any], now: datetime
) -> None:
    """Replace the stored settings with already validated values."""
    unknown = set(values) - set(FIELDS)
    if unknown:
        raise StoreError(f"unknown settings: {', '.join(sorted(unknown))}")
    await conn.execute(
        update(discovery_settings)
        .where(discovery_settings.c.id == 1)
        .values(**{name: _text(values[name]) for name in FIELDS}, updated_at=now)
    )
