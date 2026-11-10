# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Authorised targets and credentials for the SNMP client tests.

Targets are obtained the only legitimate way, from a scope policy (here with
loopback allowed, since test agents listen on local ports). Credentials come
from an in-memory resolver that masks secrets like the real
``CredentialResolver`` does, so the client under test runs its real session
logic.
"""

from __future__ import annotations

from netscanner.core.logging_setup import register_secrets, unregister_secrets
from netscanner.credential_store import CredentialUnreadable
from netscanner.scope import AuthorizedTarget, ScopePolicy
from netscanner.snmp import SnmpV2cCredential, SnmpV3Credential

Credential = SnmpV2cCredential | SnmpV3Credential
LOOPBACK = ("127.0.0.0/8",)


class StaticResolver:
    """In-memory credential source with the masking behaviour of the real resolver."""

    def __init__(self) -> None:
        self._credentials: dict[int, Credential] = {}
        self.resolved = 0

    def add(self, credential: Credential) -> int:
        credential_id = len(self._credentials) + 1
        self._credentials[credential_id] = credential
        return credential_id

    async def resolve(self, credential_id: int | None) -> Credential:
        credential = self._credentials.get(credential_id)  # type: ignore[arg-type]
        if credential is None:
            raise CredentialUnreadable("no such credential")
        register_secrets(credential.secrets())
        self.resolved += 1
        return credential

    def release(self, credential: Credential) -> None:
        unregister_secrets(credential.secrets())


RESOLVER = StaticResolver()


def authorized(
    address: str,
    port: int,
    credential: Credential | str,
    *,
    allowed: tuple[str, ...] = LOOPBACK,
    excluded: tuple[str, ...] = (),
    resolver: StaticResolver = RESOLVER,
) -> AuthorizedTarget:
    """An authorised target for ``address``; a string credential is a v2c community."""
    if isinstance(credential, str):
        credential = SnmpV2cCredential(community=credential)
    policy = ScopePolicy.build(allowed, excluded, credential_id=resolver.add(credential))
    target = policy.authorize(address, port)
    assert isinstance(target, AuthorizedTarget), target
    return target
