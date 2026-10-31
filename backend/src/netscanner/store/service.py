# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""The persistence layer's entry point: one transaction per call.

The collector and the API use :class:`Store`; the functions it wraps live in
the ``runs``, ``identity``, ``observations``, ``reading`` and ``evaluation``
modules.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.config import Settings
from netscanner.store import evaluation, identity, observations, reading, runs
from netscanner.store.identity import Chassis, Resolution
from netscanner.store.observations import OBSERVATION_LOCK, StoreResult
from netscanner.store.reading import DeviceView, RecordView
from netscanner.store.runs import QueryRecord, ReachedVia, RunKind, RunParameters

Address = str | IPv4Address | IPv6Address


def utcnow() -> datetime:
    return datetime.now(UTC)


class Store:
    def __init__(
        self,
        engine: AsyncEngine,
        *,
        stale_after: timedelta = timedelta(days=7),
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.engine = engine
        self.stale_after = stale_after
        self.clock = clock

    @classmethod
    def from_settings(cls, engine: AsyncEngine, settings: Settings) -> Store:
        return cls(engine, stale_after=settings.stale_after)

    # --- Runs and queries ---------------------------------------------------

    async def create_run(self, kind: RunKind, parameters: RunParameters | dict) -> int:
        async with self.engine.begin() as conn:
            return await runs.create_run(conn, kind, parameters, self.clock())

    async def start_run(self, run_id: int) -> None:
        async with self.engine.begin() as conn:
            await runs.start_run(conn, run_id, self.clock())

    async def finish_run(
        self,
        run_id: int,
        status: Literal["completed", "failed"] = "completed",
        *,
        error_category: str | None = None,
        summary: dict | None = None,
    ) -> None:
        """Close a run; build its evaluation snapshot if it requested one (design D11)."""
        async with self.engine.connect() as conn:
            wants_snapshot = (await runs.run_parameters(conn, run_id)).snapshot
        if not wants_snapshot:
            async with self.engine.begin() as conn:
                await runs.close_run(conn, run_id, status, self.clock(), error_category, summary)
            return
        async with self.engine.connect() as conn:
            # The exclusive lock is taken before the REPEATABLE READ transaction
            # starts, so its snapshot includes every write that held the shared
            # lock; new observation writes wait until the snapshot is stored.
            await conn.execution_options(isolation_level="AUTOCOMMIT")
            await conn.execute(select(func.pg_advisory_lock(OBSERVATION_LOCK)))
            await conn.commit()
            try:
                await conn.execution_options(isolation_level="REPEATABLE READ")
                async with conn.begin():
                    now = self.clock()
                    await runs.close_run(conn, run_id, status, now, error_category, summary)
                    await evaluation.store_snapshot(conn, run_id, now)
            finally:
                await conn.execution_options(isolation_level="AUTOCOMMIT")
                await conn.execute(select(func.pg_advisory_unlock(OBSERVATION_LOCK)))
                await conn.commit()

    async def mark_interrupted_runs(self) -> list[int]:
        async with self.engine.begin() as conn:
            return await runs.mark_interrupted_runs(conn, self.clock())

    async def record_query(
        self, record: QueryRecord | dict, error: BaseException | None = None
    ) -> int:
        async with self.engine.begin() as conn:
            return await runs.record_query(conn, record, error)

    async def record_run_device(
        self,
        run_id: int,
        target_address: Address,
        reached_via: ReachedVia,
        depth: int,
        *,
        first_query_id: int | None = None,
        answered: bool = False,
        device_id: int | None = None,
    ) -> int:
        async with self.engine.begin() as conn:
            return await runs.record_run_device(
                conn,
                run_id,
                target_address,
                reached_via,
                depth,
                first_query_id=first_query_id,
                answered=answered,
                device_id=device_id,
            )

    async def assign_device(self, run_id: int, target_address: Address, device_id: int) -> None:
        async with self.engine.begin() as conn:
            await runs.assign_device(conn, run_id, target_address, device_id)

    # --- Observations -------------------------------------------------------

    async def resolve_device(
        self, query_id: int, *, chassis: Chassis | None = None, sys_object_id: str | None = None
    ) -> Resolution:
        async with self.engine.begin() as conn:
            return await identity.resolve_device(
                conn, query_id, chassis=chassis, sys_object_id=sys_object_id, now=self.clock()
            )

    async def _rows(
        self,
        fn: Callable[..., Awaitable[StoreResult]],
        query_id: int,
        device_id: int,
        rows: Any,
    ) -> StoreResult:
        async with self.engine.begin() as conn:
            return await fn(conn, query_id, device_id, rows)

    async def store_system(self, query_id: int, device_id: int, row: dict) -> StoreResult:
        return await self._rows(observations.store_system, query_id, device_id, row)

    async def store_model(self, query_id: int, device_id: int, row: dict) -> StoreResult:
        return await self._rows(observations.store_model, query_id, device_id, row)

    async def infer_model_from_sysdescr(self, device_id: int) -> bool:
        async with self.engine.begin() as conn:
            return await observations.infer_model_from_sysdescr(conn, device_id)

    async def store_addresses(self, query_id: int, device_id: int, rows: list[dict]) -> StoreResult:
        return await self._rows(observations.store_addresses, query_id, device_id, rows)

    async def store_if_table(self, query_id: int, device_id: int, rows: list[dict]) -> StoreResult:
        return await self._rows(observations.store_if_table, query_id, device_id, rows)

    async def store_if_xtable(self, query_id: int, device_id: int, rows: list[dict]) -> StoreResult:
        return await self._rows(observations.store_if_xtable, query_id, device_id, rows)

    async def store_neighbors(self, query_id: int, device_id: int, rows: list[dict]) -> StoreResult:
        return await self._rows(observations.store_neighbors, query_id, device_id, rows)

    async def store_neighbor_man_addresses(
        self, query_id: int, device_id: int, rows: list[dict]
    ) -> StoreResult:
        return await self._rows(
            observations.store_neighbor_man_addresses, query_id, device_id, rows
        )

    async def map_local_ports(self, query_id: int, device_id: int, rows: list[dict]) -> StoreResult:
        return await self._rows(observations.map_local_ports, query_id, device_id, rows)

    async def store_ip_mac(self, query_id: int, device_id: int, rows: list[dict]) -> StoreResult:
        return await self._rows(observations.store_ip_mac, query_id, device_id, rows)

    # --- Reading and evaluation ---------------------------------------------

    async def _read(self, fn: Callable[..., Awaitable[Any]], device_id: int) -> Any:
        async with self.engine.connect() as conn:
            return await fn(conn, device_id, self.clock(), self.stale_after)

    async def read_device(self, device_id: int) -> DeviceView:
        return await self._read(reading.read_device, device_id)

    async def read_interfaces(self, device_id: int) -> list[RecordView]:
        return await self._read(reading.read_interfaces, device_id)

    async def read_addresses(self, device_id: int) -> list[RecordView]:
        return await self._read(reading.read_addresses, device_id)

    async def read_neighbors(self, device_id: int) -> list[RecordView]:
        return await self._read(reading.read_neighbors, device_id)

    async def read_ip_mac(self, device_id: int) -> list[RecordView]:
        return await self._read(reading.read_ip_mac, device_id)

    async def run_report(self, run_id: int) -> dict:
        async with self.engine.connect() as conn:
            return await evaluation.run_report(conn, run_id)

    async def get_snapshot(self, run_id: int) -> dict:
        async with self.engine.connect() as conn:
            return await evaluation.get_snapshot(conn, run_id)
