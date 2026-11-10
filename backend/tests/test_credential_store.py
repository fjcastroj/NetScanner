# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""SNMP credential storage (snmp-credentials spec, design D5)."""

from __future__ import annotations

import logging
import secrets

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.logging_setup import MASK, configure_logging
from netscanner.credential_store import (
    CredentialResolver,
    CredentialService,
    CredentialUnreadable,
    crypto,
    delete_unused_credentials,
)
from netscanner.snmp import SnmpV2cCredential, SnmpV3Credential
from netscanner.store.models import snmp_credentials
from netscanner.store.service import Store

from .conftest import all_rows_text

pytestmark = pytest.mark.db

KEY = "lab-secret-key-" + "k" * 32
OTHER_KEY = "lab-secret-key-" + "o" * 32


def canary(label: str) -> str:
    return f"canary-{label}-" + secrets.token_hex(8)


def v3(auth: str, priv: str) -> dict:
    return {
        "version": "3",
        "user": "lab-v3-user",
        "level": "authPriv",
        "auth_protocol": "SHA-256",
        "auth_key": auth,
        "priv_protocol": "AES-128",
        "priv_key": priv,
    }


def test_key_id_and_encryption_key_are_distinct_derivations() -> None:
    assert len(crypto.key_id(KEY)) == 32 and crypto.key_id(KEY) != crypto.key_id(OTHER_KEY)
    token = crypto.encrypt_secret({"community": "x"}, KEY)
    assert crypto.key_id(KEY) not in token.decode()
    assert crypto.decrypt_secret(token, KEY) == {"community": "x"}
    with pytest.raises(CredentialUnreadable):
        crypto.decrypt_secret(token, OTHER_KEY)


async def test_canary_secrets_absent_from_every_table(engine: AsyncEngine) -> None:
    service = CredentialService(engine, KEY)
    community = canary("community")
    auth, priv = canary("auth"), canary("priv")
    await service.save({"version": "2c", "community": community})
    await service.save(v3(auth, priv))
    text = await all_rows_text(engine)
    assert all(c not in text for c in (community, auth, priv))


async def test_reading_returns_only_the_description(engine: AsyncEngine) -> None:
    service = CredentialService(engine, KEY)
    assert (await service.describe()).configured is False
    auth, priv = canary("auth"), canary("priv")
    await service.save(v3(auth, priv))
    description = await service.describe()
    assert (description.configured, description.version, description.user, description.level) == (
        True,
        "v3",
        "lab-v3-user",
        "authPriv",
    )
    assert (description.auth_protocol, description.priv_protocol, description.usable) == (
        "SHA-256",
        "AES-128",
        True,
    )
    assert description.updated_at is not None
    assert auth not in repr(description) and priv not in repr(description)


async def test_changed_secret_key_reported_without_decrypting(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential_id = await CredentialService(engine, KEY).save(
        {"version": "2c", "community": canary("c")}
    )

    def forbidden(*args: object) -> None:
        raise AssertionError("the decryption helper must not be called")

    monkeypatch.setattr(crypto, "decrypt_secret", forbidden)
    monkeypatch.setattr("netscanner.credential_store.resolver.decrypt_secret", forbidden)
    assert (await CredentialService(engine, OTHER_KEY).describe()).usable is False
    resolver = CredentialResolver(engine, OTHER_KEY)
    assert await resolver.usable(credential_id) is False
    with pytest.raises(CredentialUnreadable):
        await resolver.resolve(credential_id)  # refused on the key identifier alone


async def test_corrupted_token_with_matching_key_id(engine: AsyncEngine) -> None:
    credential_id = await CredentialService(engine, KEY).save(
        {"version": "2c", "community": canary("c")}
    )
    async with engine.begin() as conn:
        await conn.execute(update(snmp_credentials).values(secret=b"not-a-fernet-token"))
    resolver = CredentialResolver(engine, KEY)
    assert await resolver.usable(credential_id) is True  # the identifier still matches
    with pytest.raises(CredentialUnreadable) as info:
        await resolver.resolve(credential_id)
    assert "not-a-fernet-token" not in str(info.value)


async def test_resolver_returns_the_models_and_masks_while_in_use(
    engine: AsyncEngine, capsys: pytest.CaptureFixture[str]
) -> None:
    community = canary("community")
    credential_id = await CredentialService(engine, KEY).save(
        {"version": "2c", "community": community}
    )
    resolver = CredentialResolver(engine, KEY)
    configure_logging("INFO", [])
    log = logging.getLogger("netscanner.test")

    credential = await resolver.resolve(credential_id)
    assert (
        isinstance(credential, SnmpV2cCredential)
        and credential.community.get_secret_value() == community
    )
    log.warning("in use: %s", community)
    assert MASK in capsys.readouterr().err
    resolver.release(credential)
    log.warning("released: %s", community)
    assert community in capsys.readouterr().err  # no longer registered after the session
    v3_id = await CredentialService(engine, KEY).save(v3(canary("a"), canary("p")))
    assert isinstance(await resolver.resolve(v3_id), SnmpV3Credential)


async def test_replacement_during_a_run_keeps_the_run_credential(
    store: Store, engine: AsyncEngine
) -> None:
    service = CredentialService(engine, KEY)
    first = await service.save({"version": "2c", "community": canary("first")})
    run = await store.create_run("discovery", {"credential_id": first})
    await store.start_run(run)
    second = await service.save({"version": "2c", "community": canary("second")})
    resolver = CredentialResolver(engine, KEY)
    # The running run still reads the credential it started with.
    assert (await resolver.resolve(first)).community.get_secret_value().startswith("canary-first-")
    assert (await service.describe()).credential_id == second
    async with engine.connect() as conn:
        rows = {r.id: r.active for r in await conn.execute(select(snmp_credentials))}
    assert rows == {first: False, second: True}
    # Once the run has finished, the inactive row is deleted.
    await store.finish_run(run)
    async with engine.begin() as conn:
        assert await delete_unused_credentials(conn) == 1
        assert [r.id for r in await conn.execute(select(snmp_credentials))] == [second]


async def test_only_one_active_credential(engine: AsyncEngine) -> None:
    service = CredentialService(engine, KEY)
    for i in range(3):
        await service.save({"version": "2c", "community": canary(str(i))})
    async with engine.connect() as conn:
        rows = list(await conn.execute(select(snmp_credentials.c.active)))
    assert [r.active for r in rows] == [True]  # earlier rows unused by any run were deleted
