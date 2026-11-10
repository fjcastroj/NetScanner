# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Reads with provenance, age, staleness and presence (RF-29, RF-30, design D6).

Every group of every record comes back with its origin, source device, MIB
object, method, first and last seen times, age, staleness and presence, so
the interface can show them without further queries. Staleness is computed
here, at read time; nothing is deleted or changed because it is stale.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import Table, and_, func, select
from sqlalchemy.ext.asyncio import AsyncConnection

from netscanner.store.errors import StoreError
from netscanner.store.groups import GroupSpec
from netscanner.store.models import (
    ADDRESS_GROUP,
    DEVICE_GROUPS,
    INTERFACE_GROUPS,
    IP_MAC_GROUP,
    NEIGHBOR_GROUPS,
    RESOLUTION_GROUP,
    device_addresses,
    devices,
    identity_resolutions,
    interfaces,
    ip_mac_entries,
    neighbor_entries,
    snmp_queries,
)

PresenceState = Literal["present", "absent", "unknown"]
# A field holds a value, a confirmed absence, or is unknown (never retrieved).
FieldState = Literal["value", "absent", "unknown"]


@dataclass(frozen=True)
class Presence:
    """Whether a datum appeared in the latest complete query of its source.

    ``latest_attempt_complete`` is false when the latest query of the source
    on the device was not complete (no response, partial, error or rejected
    rows); presence is then still judged against the latest complete query.
    """

    state: PresenceState
    latest_attempt_complete: bool


@dataclass(frozen=True)
class FieldSource:
    """Full provenance of one field: the group's, or its carried entry's."""

    query_id: int
    run_id: int
    mib_object: str
    seen_at: datetime
    age: timedelta
    stale: bool
    origin: str
    method: str | None
    evidence: dict | None


@dataclass(frozen=True)
class GroupView:
    values: dict[str, Any]
    origin: str
    method: str | None
    evidence: dict | None
    source_device_id: int
    mib_object: str
    query_id: int
    run_id: int
    first_seen_at: datetime
    first_query_id: int
    last_seen_at: datetime
    age: timedelta
    stale: bool
    presence: Presence
    carried: dict[str, FieldSource] = field(default_factory=dict)
    # Fields no query has retrieved yet: unknown, not absent.
    not_retrieved: frozenset[str] = frozenset()

    def field_state(self, name: str) -> FieldState:
        if name in self.not_retrieved:
            return "unknown"
        return "absent" if self.values[name] is None else "value"

    def field_source(self, name: str) -> FieldSource | None:
        """Provenance of one field: its carried entry, or the group's last query.

        ``None`` for a field never retrieved, which has no provenance.
        """
        if name in self.not_retrieved:
            return None
        if name in self.carried:
            return self.carried[name]
        return FieldSource(
            self.query_id,
            self.run_id,
            self.mib_object,
            self.last_seen_at,
            self.age,
            self.stale,
            self.origin,
            self.method,
            self.evidence,
        )


@dataclass(frozen=True)
class RecordView:
    table: str
    id: int
    device_id: int
    key: dict[str, Any]
    groups: dict[str, GroupView | None]


@dataclass(frozen=True)
class DeviceView:
    id: int
    groups: dict[str, GroupView | None]
    resolutions: list[RecordView]


@dataclass(frozen=True)
class _Query:
    id: int
    run_id: int
    device_id: int
    mib_object: str


class _Reader:
    """Builds group views for rows of one or more tables, batching the lookups."""

    def __init__(self, conn: AsyncConnection, now: datetime, stale_after: timedelta) -> None:
        self.conn = conn
        self.now = now
        self.stale_after = stale_after
        self.queries: dict[int, _Query] = {}
        self.latest: dict[tuple[int, str], tuple[int | None, int | None]] = {}

    async def load(self, rows: list[Any], specs: tuple[GroupSpec, ...]) -> None:
        ids: set[int] = set()
        for row in rows:
            for spec in specs:
                if row[spec.col("last_query_id")] is not None:
                    ids.add(row[spec.col("last_query_id")])
                    ids.update(
                        entry["query_id"]
                        for entry in row[spec.col("carried")].values()
                        if "query_id" in entry
                    )
        missing = ids - set(self.queries)
        if missing:
            result = await self.conn.execute(
                select(
                    snmp_queries.c.id,
                    snmp_queries.c.run_id,
                    snmp_queries.c.device_id,
                    snmp_queries.c.mib_object,
                ).where(snmp_queries.c.id.in_(missing))
            )
            self.queries.update({r.id: _Query(**r._mapping) for r in result})
        pairs = {(self.queries[i].device_id, self.queries[i].mib_object) for i in ids} - set(
            self.latest
        )
        for device_id, mib_object in pairs:
            self.latest[(device_id, mib_object)] = await self._latest(device_id, mib_object)

    async def _latest(self, device_id: int, mib_object: str) -> tuple[int | None, int | None]:
        """Latest complete query and latest query of a source on a device."""
        base = (
            select(snmp_queries.c.id)
            .where(snmp_queries.c.device_id == device_id, snmp_queries.c.mib_object == mib_object)
            .order_by(snmp_queries.c.started_at.desc(), snmp_queries.c.id.desc())
            .limit(1)
        )
        complete = base.where(
            and_(snmp_queries.c.outcome.in_(("ok", "empty")), snmp_queries.c.rejected_count == 0)
        )
        return await self.conn.scalar(complete), await self.conn.scalar(base)

    def _age(self, seen_at: datetime) -> tuple[timedelta, bool]:
        age = self.now - seen_at
        return age, age > self.stale_after

    def group(self, row: Any, spec: GroupSpec) -> GroupView | None:
        c = spec.col
        if row[c("origin")] is None:
            return None
        q = self.queries[row[c("last_query_id")]]
        latest_complete, latest = self.latest[(q.device_id, q.mib_object)]
        if latest_complete is None:
            state: PresenceState = "unknown"
        else:
            state = "present" if row[c("last_complete_query_id")] == latest_complete else "absent"
        carried, not_retrieved = {}, set()
        for name, entry in row[c("carried")].items():
            if "query_id" not in entry:
                not_retrieved.add(name)
                continue
            source = self.queries[entry["query_id"]]
            seen_at = datetime.fromisoformat(entry["seen_at"])
            carried[name] = FieldSource(
                source.id,
                source.run_id,
                source.mib_object,
                seen_at,
                *self._age(seen_at),
                entry["origin"],
                entry["method"],
                entry["evidence"],
            )
        age, stale = self._age(row[c("last_seen_at")])
        return GroupView(
            values={name: _plain(row[name]) for name in spec.fields},
            origin=row[c("origin")],
            method=row[c("method")],
            evidence=row[c("evidence")],
            source_device_id=q.device_id,
            mib_object=q.mib_object,
            query_id=q.id,
            run_id=q.run_id,
            first_seen_at=row[c("first_seen_at")],
            first_query_id=row[c("first_query_id")],
            last_seen_at=row[c("last_seen_at")],
            age=age,
            stale=stale,
            presence=Presence(state, latest == latest_complete),
            carried=carried,
            not_retrieved=frozenset(not_retrieved),
        )

    async def records(
        self, table: Table, specs: tuple[GroupSpec, ...], key: tuple[str, ...], *conditions: Any
    ) -> list[RecordView]:
        rows = [
            r._mapping
            for r in await self.conn.execute(select(table).where(*conditions).order_by(table.c.id))
        ]
        await self.load(rows, specs)
        return [
            RecordView(
                table=table.name,
                id=row["id"],
                device_id=row["device_id"],
                key={k: _plain(row[k]) for k in key},
                groups={spec.name: self.group(row, spec) for spec in specs},
            )
            for row in rows
        ]


def _plain(value: Any) -> Any:
    """Addresses as text, so views compare and serialise simply."""
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if value is not None and type(value).__module__ == "ipaddress":
        return str(value)
    return value


async def read_device(
    conn: AsyncConnection, device_id: int, now: datetime, stale_after: timedelta
) -> DeviceView:
    row = (await conn.execute(select(devices).where(devices.c.id == device_id))).first()
    if row is None:
        raise StoreError(f"unknown device {device_id}")
    reader = _Reader(conn, now, stale_after)
    await reader.load([row._mapping], DEVICE_GROUPS)
    resolutions = await reader.records(
        identity_resolutions,
        (RESOLUTION_GROUP,),
        ("method", "key_value"),
        identity_resolutions.c.device_id == device_id,
    )
    return DeviceView(
        id=device_id,
        groups={spec.name: reader.group(row._mapping, spec) for spec in DEVICE_GROUPS},
        resolutions=resolutions,
    )


async def read_interfaces(
    conn: AsyncConnection, device_id: int, now: datetime, stale_after: timedelta
) -> list[RecordView]:
    return await _Reader(conn, now, stale_after).records(
        interfaces, INTERFACE_GROUPS, ("if_index",), interfaces.c.device_id == device_id
    )


async def read_addresses(
    conn: AsyncConnection, device_id: int, now: datetime, stale_after: timedelta
) -> list[RecordView]:
    return await _Reader(conn, now, stale_after).records(
        device_addresses,
        (ADDRESS_GROUP,),
        ("address", "source"),
        device_addresses.c.device_id == device_id,
    )


async def read_neighbors(
    conn: AsyncConnection, device_id: int, now: datetime, stale_after: timedelta
) -> list[RecordView]:
    return await _Reader(conn, now, stale_after).records(
        neighbor_entries,
        NEIGHBOR_GROUPS,
        ("protocol", "local_port_num", "remote_index"),
        neighbor_entries.c.device_id == device_id,
    )


async def read_ip_mac(
    conn: AsyncConnection, device_id: int, now: datetime, stale_after: timedelta
) -> list[RecordView]:
    return await _Reader(conn, now, stale_after).records(
        ip_mac_entries,
        (IP_MAC_GROUP,),
        ("if_index", "ip_address"),
        ip_mac_entries.c.device_id == device_id,
    )


@dataclass(frozen=True)
class DeviceSummary:
    """One row of the device list: its groups with provenance and two counts."""

    id: int
    groups: dict[str, GroupView | None]
    management_address: str | None
    interface_count: int


async def list_devices(
    conn: AsyncConnection, limit: int, offset: int, now: datetime, stale_after: timedelta
) -> tuple[int, list[DeviceSummary]]:
    """A page of devices in identifier order, and the total number of devices."""
    total = await conn.scalar(select(func.count()).select_from(devices))
    count = (
        select(func.count())
        .where(interfaces.c.device_id == devices.c.id)
        .correlate(devices)
        .scalar_subquery()
    )
    management = (
        select(func.min(device_addresses.c.address))
        .where(
            device_addresses.c.device_id == devices.c.id,
            device_addresses.c.source == "management",
        )
        .correlate(devices)
        .scalar_subquery()
    )
    rows = [
        r._mapping
        for r in await conn.execute(
            select(
                devices,
                count.label("interface_count"),
                management.label("management_address"),
            )
            .order_by(devices.c.id)
            .limit(limit)
            .offset(offset)
        )
    ]
    reader = _Reader(conn, now, stale_after)
    await reader.load(rows, DEVICE_GROUPS)
    return total or 0, [
        DeviceSummary(
            id=row["id"],
            groups={spec.name: reader.group(row, spec) for spec in DEVICE_GROUPS},
            management_address=_plain(row["management_address"]),
            interface_count=row["interface_count"],
        )
        for row in rows
    ]
