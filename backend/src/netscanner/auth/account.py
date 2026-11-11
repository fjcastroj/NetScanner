# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""The single administrator account (design D2, D10).

Created and reset only from the server console (``netscanner.admin``); the
API has no route that creates or changes it. Resetting the password deletes
every session in the same transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from netscanner.auth import passwords
from netscanner.store.models import admin_account, sessions

ACCOUNT_ID = 1


class AccountExists(Exception):
    """An administrator already exists: use the reset command."""


class NoAccount(Exception):
    """No administrator exists yet: use the create command."""


@dataclass(frozen=True)
class Account:
    username: str
    password_hash: str


async def get_account(conn: AsyncConnection) -> Account | None:
    row = (
        await conn.execute(
            select(admin_account.c.username, admin_account.c.password_hash).where(
                admin_account.c.id == ACCOUNT_ID
            )
        )
    ).first()
    return None if row is None else Account(row.username, row.password_hash)


async def account_exists(engine: AsyncEngine) -> bool:
    async with engine.connect() as conn:
        return await get_account(conn) is not None


async def create_account(engine: AsyncEngine, username: str, password: str, now: datetime) -> None:
    passwords.check_username(username)
    passwords.check_password(password, username)
    password_hash = passwords.hash_password(password)
    try:
        async with engine.begin() as conn:
            if await get_account(conn) is not None:
                raise AccountExists
            await conn.execute(
                insert(admin_account).values(
                    id=ACCOUNT_ID,
                    username=username,
                    password_hash=password_hash,
                    created_at=now,
                    password_changed_at=now,
                )
            )
    except IntegrityError:
        # Created concurrently by another command: the one-row key refused this one.
        raise AccountExists from None


async def reset_password(engine: AsyncEngine, password: str, now: datetime) -> int:
    """Replace the password and end every session at once; return the sessions ended."""
    async with engine.begin() as conn:
        account = await get_account(conn)
        if account is None:
            raise NoAccount
        passwords.check_password(password, account.username)
        await conn.execute(
            update(admin_account)
            .where(admin_account.c.id == ACCOUNT_ID)
            .values(password_hash=passwords.hash_password(password), password_changed_at=now)
        )
        ended = await conn.execute(delete(sessions))
        return ended.rowcount


async def store_rehash(conn: AsyncConnection, old_hash: str, new_hash: str) -> None:
    """Replace a hash with outdated parameters, unless the password changed meanwhile."""
    await conn.execute(
        update(admin_account)
        .where(admin_account.c.id == ACCOUNT_ID, admin_account.c.password_hash == old_hash)
        .values(password_hash=new_hash)
    )
