# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Server-side sessions (design D3).

The browser holds a random 32-byte token; the database holds only its
SHA-256. A session ends after the idle period without use, at its absolute
expiry, on logout or on password reset. ``last_used_at`` is written at most
once a minute, so idle expiry can be up to a minute late.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store.models import sessions

TOKEN_BYTES = 32
TOUCH_INTERVAL = timedelta(minutes=1)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Session:
    id: int
    created_at: datetime
    expires_at: datetime


class SessionStore:
    def __init__(self, engine: AsyncEngine, idle: timedelta, max_age: timedelta) -> None:
        self.engine = engine
        self.idle = idle
        self.max_age = max_age

    async def create(self, now: datetime, source_address: str | None) -> tuple[str, Session]:
        """A new session; the token is returned once and never stored."""
        token = secrets.token_urlsafe(TOKEN_BYTES)
        expires_at = now + self.max_age
        async with self.engine.begin() as conn:
            session_id = await conn.scalar(
                insert(sessions)
                .values(
                    token_hash=token_hash(token),
                    created_at=now,
                    last_used_at=now,
                    expires_at=expires_at,
                    source_address=source_address,
                )
                .returning(sessions.c.id)
            )
        return token, Session(session_id, now, expires_at)

    async def resolve(self, token: str, now: datetime) -> Session | None:
        """The valid session for a token, or ``None``; an expired one is deleted."""
        digest = token_hash(token)
        async with self.engine.begin() as conn:
            row = (
                await conn.execute(select(sessions).where(sessions.c.token_hash == digest))
            ).first()
            if row is None:
                return None
            if now >= row.expires_at or now - row.last_used_at > self.idle:
                await conn.execute(delete(sessions).where(sessions.c.id == row.id))
                return None
            if now - row.last_used_at >= TOUCH_INTERVAL:
                await conn.execute(
                    update(sessions).where(sessions.c.id == row.id).values(last_used_at=now)
                )
            return Session(row.id, row.created_at, row.expires_at)

    async def end(self, token: str) -> bool:
        async with self.engine.begin() as conn:
            result = await conn.execute(
                delete(sessions).where(sessions.c.token_hash == token_hash(token))
            )
            return result.rowcount > 0
