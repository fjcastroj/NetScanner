# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Whole discovery runs in tests (design D3, D4).

A run goes through the real path: the credential saved encrypted by
``CredentialService``, a pending run with frozen parameters, the claim, the
runner's checks and the engine, with ``PySnmpClient`` and the real
``CredentialResolver``. Only the transport mapping (``endpoint_for``) and the
SNMPv3 context are test-only: lab addresses go to local ports, unmapped
addresses to a silent agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.credential_store import CredentialResolver, CredentialService
from netscanner.discovery.runner import execute_run
from netscanner.scope import DiscoveryCeilings
from netscanner.snmp.pysnmp_client import PySnmpClient
from netscanner.snmp.walker import SnmpLimits
from netscanner.store.runs import RunLimits, RunParameters
from netscanner.store.service import Store

LAB_RANGE = "10.99.0.0/24"


@dataclass
class Network:
    """Logical address -> local port; anything else goes to ``default`` (a silent agent)."""

    ports: dict[str, int] = field(default_factory=dict)
    default: int | None = None
    host: str = "127.0.0.1"

    def endpoint_for(self, address: str, port: int) -> tuple[str, int]:
        target = self.ports.get(address, self.default)
        if target is None:
            raise AssertionError(f"no test agent behind {address}")
        return self.host, target


@dataclass
class Run:
    run_id: int
    status: str
    store: Store
    engine: AsyncEngine

    async def run(self) -> dict[str, Any]:
        return dict((await _rows(self.engine, RUN, self.run_id))[0])

    async def devices(self) -> list[dict[str, Any]]:
        return [dict(r) for r in await _rows(self.engine, RUN_DEVICES, self.run_id)]

    async def by_address(self) -> dict[str, dict[str, Any]]:
        return {str(r["target_address"]): r for r in await self.devices()}

    async def queries(self) -> list[dict[str, Any]]:
        return [dict(r) for r in await _rows(self.engine, QUERIES, self.run_id)]

    async def report(self) -> dict[str, Any]:
        return await self.store.run_report(self.run_id)


RUN = "SELECT * FROM collection_runs WHERE id = :run"
RUN_DEVICES = (
    "SELECT host(target_address) AS target_address, reached_via, depth, device_id, answered,"
    " skip_reason, found_from_device_id, first_query_id FROM run_devices WHERE run_id = :run"
    " ORDER BY id"
)
QUERIES = (
    "SELECT id, host(target_address) AS target_address, device_id, mib_object, operation,"
    " snmp_version, outcome, indicator, error_category, row_count, request_count"
    " FROM snmp_queries WHERE run_id = :run ORDER BY id"
)


async def _rows(engine: AsyncEngine, sql: str, run_id: int) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), {"run": run_id})).mappings())


async def save_credential(engine: AsyncEngine, secret_key: str, credential: dict) -> int:
    return await CredentialService(engine, secret_key).save(credential)


async def create_run(
    store: Store,
    *,
    seeds: list[str],
    credential_id: int | None,
    allowed: list[str] | None = None,
    exclusions: list[str] | None = None,
    max_depth: int = 1,
    follow_ip_mac: bool = False,
    limits: RunLimits | None = None,
    snapshot: bool = False,
) -> int:
    params = RunParameters(
        seeds=seeds,  # type: ignore[arg-type]
        allowed_ranges=[LAB_RANGE] if allowed is None else allowed,  # type: ignore[arg-type]
        exclusions=exclusions or [],  # type: ignore[arg-type]
        max_depth=max_depth,
        credential_id=credential_id,
        follow_ip_mac=follow_ip_mac,
        limits=limits or RunLimits(max_candidates=4096, max_devices=256, max_datagrams=50000),
        snapshot=snapshot,
    )
    return await store.create_run("discovery", params)


def lab_client(
    engine: AsyncEngine,
    secret_key: str,
    network: Network,
    *,
    snmp_limits: SnmpLimits | None = None,
    v3_context: str = "",
) -> tuple[PySnmpClient, CredentialResolver]:
    resolver = CredentialResolver(engine, secret_key)
    client = PySnmpClient(
        resolver,
        snmp_limits or SnmpLimits(timeout=2, retries=0),
        network.endpoint_for,
        v3_context=v3_context,
    )
    return client, resolver


async def discover(
    engine: AsyncEngine,
    secret_key: str,
    network: Network,
    *,
    credential: dict,
    seeds: list[str],
    snmp_limits: SnmpLimits | None = None,
    v3_context: str = "",
    ceilings: DiscoveryCeilings | None = None,
    **params: Any,
) -> Run:
    """Save the credential, create a pending run, claim it and run it to its end."""
    store = Store(engine)
    credential_id = await save_credential(engine, secret_key, credential)
    created = await create_run(store, seeds=seeds, credential_id=credential_id, **params)
    return await claim_and_run(
        engine, secret_key, network, created, snmp_limits=snmp_limits, v3_context=v3_context,
        ceilings=ceilings,
    )  # fmt: skip


async def claim_and_run(
    engine: AsyncEngine,
    secret_key: str,
    network: Network,
    expected_run: int,
    *,
    snmp_limits: SnmpLimits | None = None,
    v3_context: str = "",
    ceilings: DiscoveryCeilings | None = None,
) -> Run:
    store = Store(engine)
    run_id = await store.claim_pending_run()
    assert run_id == expected_run
    client, resolver = lab_client(
        engine, secret_key, network, snmp_limits=snmp_limits, v3_context=v3_context
    )
    status = await execute_run(store, client, resolver, run_id, ceilings or DiscoveryCeilings())
    return Run(run_id, status, store, engine)
