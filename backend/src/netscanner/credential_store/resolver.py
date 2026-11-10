# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Credential resolver: used by the SNMP adapter only (design D1, D5).

``resolve`` decrypts the credential of a device session and registers its
secret values with the log-masking filter before returning, inside the same
function that decrypts, so no later exception can carry an unmasked value.
``release`` unregisters them when the session ends.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.logging_setup import register_secrets, unregister_secrets
from netscanner.credential_store.crypto import CredentialUnreadable, decrypt_secret, key_id
from netscanner.snmp.credentials import SnmpV2cCredential, SnmpV3Credential, parse_credential
from netscanner.store.models import snmp_credentials

Credential = SnmpV2cCredential | SnmpV3Credential


class CredentialResolver:
    def __init__(self, engine: AsyncEngine, secret_key: str) -> None:
        self._engine = engine
        self._secret_key = secret_key
        self._key_id = key_id(secret_key)

    async def usable(self, credential_id: int | None) -> bool:
        """Whether a credential exists and matches the current key, without decrypting."""
        if credential_id is None:
            return False
        async with self._engine.connect() as conn:
            stored = await conn.scalar(
                select(snmp_credentials.c.key_id).where(snmp_credentials.c.id == credential_id)
            )
        return stored == self._key_id

    async def resolve(self, credential_id: int | None) -> Credential:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(snmp_credentials).where(snmp_credentials.c.id == credential_id)
                )
            ).first()
        if row is None or row.key_id != self._key_id:
            raise CredentialUnreadable("the SNMP credential of this run cannot be used")
        secret = decrypt_secret(row.secret, self._secret_key)
        register_secrets(secret.values())
        try:
            if row.version == "v2c":
                return parse_credential({"version": "2c", "community": secret["community"]})
            return parse_credential(
                {
                    "version": "3",
                    "user": row.v3_user,
                    "level": row.v3_level,
                    "auth_protocol": row.v3_auth_protocol,
                    "auth_key": secret["auth_key"],
                    "priv_protocol": row.v3_priv_protocol,
                    "priv_key": secret.get("priv_key"),
                }
            )
        except Exception:
            unregister_secrets(secret.values())
            raise CredentialUnreadable("the stored SNMP credential is malformed") from None

    @staticmethod
    def release(credential: Credential) -> None:
        unregister_secrets(credential.secrets())
