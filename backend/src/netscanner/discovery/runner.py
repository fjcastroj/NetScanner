# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""One discovery run from start to close (design D7).

Before any datagram, in this order: the scope (``empty_scope``,
``scope_not_allowed``), the frozen limits, which must be present and within
the current ceilings (``limits_not_allowed``) and the credential (``credential_unreadable``).
Then the engine runs; the run fails only with the categories of D7, and
otherwise completes with its summary. Credentials no longer active nor used
by a pending or running run are deleted when the run ends.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from sqlalchemy.exc import SQLAlchemyError

from netscanner.credential_store import (
    CredentialUnreadable,
    credential_version,
    delete_unused_credentials,
)
from netscanner.discovery.engine import DiscoveryEngine
from netscanner.scope import DiscoveryCeilings, LimitsAboveCeiling, ScopeError, ScopePolicy
from netscanner.scope.settings import check_run_limits
from netscanner.snmp import SnmpClient
from netscanner.store.runs import run_parameters
from netscanner.store.service import Store

log = logging.getLogger("netscanner.discovery")


class CredentialCheck(Protocol):
    async def usable(self, credential_id: int | None) -> bool: ...


class RunFailed(Exception):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


async def execute_run(
    store: Store,
    client: SnmpClient,
    credentials: CredentialCheck,
    run_id: int,
    ceilings: DiscoveryCeilings,
) -> str:
    """Run a started (``running``) discovery run and close it; return its final status."""
    engine: DiscoveryEngine | None = None
    try:
        engine = await _prepare(store, client, credentials, run_id, ceilings)
        summary = await engine.run()
    except RunFailed as failed:
        return await _close(store, run_id, "failed", failed.category, engine)
    except CredentialUnreadable:
        return await _close(store, run_id, "failed", "credential_unreadable", engine)
    except SQLAlchemyError:
        log.warning("discovery run %s failed (database_error)", run_id)
        return await _close(store, run_id, "failed", "database_error", engine)
    except Exception as exc:
        log.warning("discovery run %s failed (%s)", run_id, type(exc).__name__)
        return await _close(store, run_id, "failed", "internal_error", engine)
    return await _close(store, run_id, "completed", None, engine, summary)


async def _prepare(
    store: Store,
    client: SnmpClient,
    credentials: CredentialCheck,
    run_id: int,
    ceilings: DiscoveryCeilings,
) -> DiscoveryEngine:
    async with store.engine.connect() as conn:
        params = await run_parameters(conn, run_id)
    try:
        policy = ScopePolicy.from_parameters(params)
    except ScopeError as exc:
        raise RunFailed(exc.category) from None
    try:
        check_run_limits(params, ceilings)
    except LimitsAboveCeiling:
        raise RunFailed("limits_not_allowed") from None
    if params.limits is None:
        # A discovery run always has frozen limits (design D6); a run without
        # them was not created by the API and is not run with default values.
        raise RunFailed("limits_not_allowed")
    limits = params.limits
    if not await credentials.usable(params.credential_id):
        raise RunFailed("credential_unreadable")
    async with store.engine.connect() as conn:
        version = await credential_version(conn, params.credential_id)
    if version is None:
        raise RunFailed("credential_unreadable")
    return DiscoveryEngine(store, client, run_id, params, policy, limits, version)


async def _close(
    store: Store,
    run_id: int,
    status: str,
    category: str | None,
    engine: DiscoveryEngine | None,
    summary: dict[str, Any] | None = None,
) -> str:
    if summary is None and engine is not None:
        summary = engine.summary()
    await store.finish_run(run_id, status, error_category=category, summary=summary)  # type: ignore[arg-type]
    async with store.engine.begin() as conn:
        await delete_unused_credentials(conn)
    return status
