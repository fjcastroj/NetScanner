# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Helpers that build runs, queries and devices for the persistence-layer tests.

Addresses are from the lab range and names are fictitious (lab-sw-01...).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Table, select
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store.identity import Chassis
from netscanner.store.service import Store

from .conftest import T0


class Lab:
    def __init__(self, store: Store, engine: AsyncEngine) -> None:
        self.store = store
        self.engine = engine
        self._run: int | None = None

    async def run(self, kind: str = "discovery", parameters: dict | None = None) -> int:
        run = await self.store.create_run(kind, parameters or {})
        await self.store.start_run(run)
        self._run = run
        return run

    async def query(
        self,
        mib_object: str,
        *,
        run: int | None = None,
        address: str = "10.99.0.11",
        at: datetime | timedelta = T0,
        outcome: str = "ok",
        rows: int = 1,
        device: int | None = None,
        **extra: Any,
    ) -> int:
        run = run or self._run or await self.run()
        started = T0 + at if isinstance(at, timedelta) else at
        values: dict[str, Any] = {
            "run_id": run,
            "target_address": address,
            "device_id": device,
            "mib_object": mib_object,
            "operation": "get" if mib_object == "SNMPv2-MIB::system" else "walk",
            "outcome": outcome,
            "row_count": rows,
            "started_at": started,
            "duration_ms": 50,
            **extra,
        }
        return await self.store.record_query(values)

    async def device(
        self,
        address: str = "10.99.0.11",
        *,
        name: str = "lab-sw-01",
        chassis: Chassis | None = None,
        at: datetime | timedelta = T0,
        run: int | None = None,
    ) -> int:
        """A device resolved from a system query (and an LLDP local query with ``chassis``)."""
        system = await self.query("SNMPv2-MIB::system", address=address, at=at, run=run)
        if chassis is not None:
            lldp = await self.query(
                "LLDP-MIB::lldpLocalSystemData", address=address, at=at, run=run
            )
            device = (await self.store.resolve_device(lldp, chassis=chassis)).device_id
        else:
            device = (await self.store.resolve_device(system)).device_id
        await self.store.store_system(
            system, device, {"sys_name": name, "sys_object_id": "1.3.6.1.4.1.12356.101.1.1"}
        )
        return device

    async def rows(self, table: Table, **where: Any) -> list[Any]:
        stmt = select(table).order_by(table.c.id)
        for column, value in where.items():
            stmt = stmt.where(table.c[column] == value)
        async with self.engine.connect() as conn:
            return [r._mapping for r in (await conn.execute(stmt))]

    async def one(self, table: Table, **where: Any) -> Any:
        rows = await self.rows(table, **where)
        assert len(rows) == 1, rows
        return rows[0]
