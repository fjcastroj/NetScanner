# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Write-only credential service used by the API (RF-01, design D5).

The credential can be created and replaced, never read back: reads return
only whether it is configured, its version, the non-secret SNMPv3 fields,
when it was updated and whether it is usable with the current secret key,
which is decided by comparing key identifiers without decrypting anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from netscanner.credential_store.crypto import encrypt_secret, key_id
from netscanner.snmp.credentials import SnmpV2cCredential, SnmpV3Credential, parse_credential
from netscanner.store.models import snmp_credentials

Credential = SnmpV2cCredential | SnmpV3Credential


@dataclass(frozen=True)
class CredentialDescription:
    """What the API may say about the stored credential: nothing secret."""

    configured: bool
    version: str | None = None
    user: str | None = None
    level: str | None = None
    auth_protocol: str | None = None
    priv_protocol: str | None = None
    updated_at: datetime | None = None
    usable: bool = False
    credential_id: int | None = None


def _secret_fields(credential: Credential) -> dict[str, str]:
    if isinstance(credential, SnmpV2cCredential):
        return {"community": credential.community.get_secret_value()}
    fields = {"auth_key": credential.auth_key.get_secret_value()}
    if credential.priv_key is not None:
        fields["priv_key"] = credential.priv_key.get_secret_value()
    return fields


# Inactive rows that no pending or running run references (design D5).
_DELETE_UNUSED = text(
    "DELETE FROM snmp_credentials WHERE NOT active AND id NOT IN ("
    " SELECT (parameters->>'credential_id')::bigint FROM collection_runs"
    " WHERE status IN ('pending', 'running') AND parameters->>'credential_id' IS NOT NULL)"
)


async def delete_unused_credentials(conn: AsyncConnection) -> int:
    result = await conn.execute(_DELETE_UNUSED)
    return result.rowcount


async def credential_version(conn: AsyncConnection, credential_id: int | None) -> str | None:
    """The SNMP version of a stored credential (not secret), or None if there is none."""
    if credential_id is None:
        return None
    return await conn.scalar(
        select(snmp_credentials.c.version).where(snmp_credentials.c.id == credential_id)
    )


class CredentialService:
    def __init__(self, engine: AsyncEngine, secret_key: str) -> None:
        self._engine = engine
        self._key_id = key_id(secret_key)
        self._secret_key = secret_key

    async def save(self, credential: Credential | dict) -> int:
        """Replace the credential set; runs in progress keep theirs."""
        credential = parse_credential(credential)
        values: dict[str, object] = {
            "version": "v2c" if isinstance(credential, SnmpV2cCredential) else "v3",
            "secret": encrypt_secret(_secret_fields(credential), self._secret_key),
            "key_id": self._key_id,
            "active": True,
        }
        if isinstance(credential, SnmpV3Credential):
            values.update(
                v3_user=credential.user,
                v3_level=credential.level,
                v3_auth_protocol=credential.auth_protocol,
                v3_priv_protocol=credential.priv_protocol,
            )
        async with self._engine.begin() as conn:
            await conn.execute(
                update(snmp_credentials).where(snmp_credentials.c.active).values(active=False)
            )
            new_id = await conn.scalar(
                insert(snmp_credentials).values(**values).returning(snmp_credentials.c.id)
            )
            await delete_unused_credentials(conn)
        return new_id

    async def describe(self) -> CredentialDescription:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(
                        snmp_credentials.c.id,
                        snmp_credentials.c.version,
                        snmp_credentials.c.v3_user,
                        snmp_credentials.c.v3_level,
                        snmp_credentials.c.v3_auth_protocol,
                        snmp_credentials.c.v3_priv_protocol,
                        snmp_credentials.c.created_at,
                        snmp_credentials.c.key_id,
                    ).where(snmp_credentials.c.active)
                )
            ).first()
        if row is None:
            return CredentialDescription(configured=False)
        return CredentialDescription(
            configured=True,
            version=row.version,
            user=row.v3_user,
            level=row.v3_level,
            auth_protocol=row.v3_auth_protocol,
            priv_protocol=row.v3_priv_protocol,
            updated_at=row.created_at,
            usable=row.key_id == self._key_id,
            credential_id=row.id,
        )
