# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Password guessing limit (design D7).

Five failed logins from one source address within 15 minutes give 429 with
``Retry-After`` until the oldest of them leaves the window. The account is
never locked. Successful logins are recorded but not counted. Rows older
than a day are deleted on each login.

The source address is the last entry of ``X-Forwarded-For``, the one nginx
appends, stripped and parsed as an IP address; the earlier entries are the
client's and are ignored. Without the header, or when that entry is not an
IP address, the connection address is used.
"""

from __future__ import annotations

import ipaddress
import math
from datetime import datetime, timedelta

from sqlalchemy import delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store.models import login_attempts

MAX_FAILURES = 5
WINDOW = timedelta(minutes=15)
KEEP = timedelta(days=1)
UNKNOWN_SOURCE = "0.0.0.0"  # noqa: S104 - a placeholder value, never a bind address


def _ip(text: str | None) -> str | None:
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def source_address(forwarded_for: str | None, connection_address: str | None) -> str:
    """The address the guessing limit counts for one request."""
    if forwarded_for is not None:
        last = _ip(forwarded_for.split(",")[-1])
        if last is not None:
            return last
    return _ip(connection_address) or UNKNOWN_SOURCE


class LoginLimiter:
    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine

    async def retry_after(self, source: str, now: datetime) -> int | None:
        """Seconds until the next attempt is allowed, or ``None`` if it is allowed now."""
        async with self.engine.begin() as conn:
            await conn.execute(delete(login_attempts).where(login_attempts.c.at < now - KEEP))
            count, oldest = (
                await conn.execute(
                    select(func.count(), func.min(login_attempts.c.at)).where(
                        login_attempts.c.source_address == source,
                        login_attempts.c.succeeded.is_(False),
                        login_attempts.c.at > now - WINDOW,
                    )
                )
            ).one()
        if count < MAX_FAILURES:
            return None
        return max(1, math.ceil((oldest + WINDOW - now).total_seconds()))

    async def record(self, source: str, succeeded: bool, now: datetime) -> None:
        async with self.engine.begin() as conn:
            await conn.execute(
                insert(login_attempts).values(at=now, source_address=source, succeeded=succeeded)
            )
