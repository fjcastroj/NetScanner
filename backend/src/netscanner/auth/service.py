# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Login, logout and the current session (design D5, D7).

An unknown user name, a missing account and a wrong password give the same
answer, and each performs exactly one Argon2id verification: against the
stored hash when the user name matches, otherwise against the fixed dummy
hash. A successful login always creates a new session. Login attempts are
logged with time, source address and result, and with the user name only
when it matches the account; the password is never logged.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.auth import passwords
from netscanner.auth.account import get_account, store_rehash
from netscanner.auth.limiter import LoginLimiter
from netscanner.auth.sessions import Session, SessionStore
from netscanner.core.config import Settings, normalise_origin, parse_web_bind

log = logging.getLogger("netscanner.auth")


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class LoginResult:
    outcome: Literal["ok", "failed", "limited"]
    token: str | None = None
    session: Session | None = None
    username: str | None = None
    retry_after: int | None = None


def allowed_origins(settings: Settings) -> frozenset[str]:
    """From configuration only, never from the request (design D6)."""
    if settings.public_origin:
        return frozenset({settings.public_origin})
    _, port = parse_web_bind(settings.web_bind)
    return frozenset(
        normalise_origin(f"http://{host}:{port}") for host in ("localhost", "127.0.0.1")
    )


class AuthService:
    def __init__(
        self, engine: AsyncEngine, settings: Settings, clock: Callable[[], datetime] = utcnow
    ) -> None:
        self.engine = engine
        self.settings = settings
        self.clock = clock
        self.sessions = SessionStore(engine, settings.session_idle, settings.session_max_age)
        self.limiter = LoginLimiter(engine)
        self.cookie_secure = settings.session_cookie_secure
        self.origins = allowed_origins(settings)

    async def login(self, username: str, password: str, source: str) -> LoginResult:
        now = self.clock()
        retry = await self.limiter.retry_after(source, now)
        if retry is not None:
            log.warning("login refused from %s: too many failures, retry in %s s", source, retry)
            return LoginResult("limited", retry_after=retry)
        async with self.engine.connect() as conn:
            account = await get_account(conn)
        if account is not None and _same(username, account.username):
            ok = passwords.verify(account.password_hash, password)
            who = f" as {account.username}"
        else:
            passwords.verify(passwords.dummy_hash(), password)
            ok, who = False, ""
        await self.limiter.record(source, ok, now)
        if not ok or account is None:
            log.warning("login failed from %s%s", source, who)
            return LoginResult("failed")
        if passwords.needs_rehash(account.password_hash):
            async with self.engine.begin() as conn:
                await store_rehash(conn, account.password_hash, passwords.hash_password(password))
        token, session = await self.sessions.create(now, source)
        log.info("login succeeded from %s%s", source, who)
        return LoginResult("ok", token, session, account.username)

    async def session_for(self, token: str | None) -> Session | None:
        if not token:
            return None
        return await self.sessions.resolve(token, self.clock())

    async def logout(self, token: str | None) -> None:
        if token and await self.sessions.end(token):
            log.info("logout")

    async def admin_exists(self) -> bool:
        return await self.username() is not None

    async def username(self) -> str | None:
        async with self.engine.connect() as conn:
            account = await get_account(conn)
        return None if account is None else account.username


def _same(given: str, stored: str) -> bool:
    return hmac.compare_digest(given.encode("utf-8"), stored.encode("utf-8"))
