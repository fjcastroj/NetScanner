# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Device identity resolution (design D3, D8; network-observations spec).

Deciding that an answer comes from an already known device is an inference:
no standard guarantees stable, unique chassis identifiers or addresses. Every
decision is stored as an identity resolution with its method and evidence,
and contradictions are recorded as conflicts instead of merging devices.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from sqlalchemy import func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from netscanner.store.errors import StoreError
from netscanner.store.evidence import QueryInput, RecordInput, build_evidence
from netscanner.store.merge import GroupUpdate, apply_updates, upsert
from netscanner.store.models import (
    RESOLUTION_GROUP,
    device_addresses,
    devices,
    identity_conflicts,
    identity_resolutions,
)
from netscanner.store.observations import CHASSIS, observation_lock, store_management_address
from netscanner.store.registry import Origin
from netscanner.store.runs import QueryInfo, assign_device, get_query

IdentityMethod = Literal["chassis-id", "address"]


@dataclass(frozen=True)
class Chassis:
    subtype: int
    value: str

    def __post_init__(self) -> None:
        if not 1 <= self.subtype <= 7 or not 0 < len(self.value) <= 255:
            raise StoreError("invalid chassis identifier")

    @property
    def key(self) -> str:
        return f"{self.subtype}:{self.value}"


@dataclass
class Resolution:
    device_id: int
    method: IdentityMethod
    created: bool
    conflicts: list[int] = field(default_factory=list)


async def _known_addresses(conn: AsyncConnection, device_id: int) -> list[str]:
    rows = await conn.execute(
        select(device_addresses.c.address)
        .where(device_addresses.c.device_id == device_id)
        .distinct()
        .order_by(device_addresses.c.address)
        .limit(32)
    )
    return [str(a) for a in rows.scalars()]


async def _devices_by_chassis(conn: AsyncConnection, chassis: Chassis) -> list[int]:
    rows = await conn.execute(
        select(identity_resolutions.c.device_id)
        .where(
            identity_resolutions.c.method == "chassis-id",
            identity_resolutions.c.key_value == chassis.key,
        )
        .order_by(identity_resolutions.c.device_id)
    )
    return list(dict.fromkeys(rows.scalars()))


async def _devices_by_address(conn: AsyncConnection, address: str) -> list[int]:
    rows = await conn.execute(
        select(device_addresses.c.device_id)
        .where(device_addresses.c.address == address)
        .distinct()
        .order_by(device_addresses.c.device_id)
    )
    return list(rows.scalars())


async def _device_facts(conn: AsyncConnection, device_id: int) -> tuple[str | None, str | None]:
    row = (
        await conn.execute(
            select(
                devices.c.chassis_id_subtype, devices.c.chassis_id, devices.c.sys_object_id
            ).where(devices.c.id == device_id)
        )
    ).one()
    chassis = f"{row.chassis_id_subtype}:{row.chassis_id}" if row.chassis_id is not None else None
    return chassis, row.sys_object_id


async def _evidence(
    conn: AsyncConnection,
    method: IdentityMethod,
    q: QueryInfo,
    address: str,
    chassis: Chassis | None,
    device_id: int | None,
) -> object:
    reported: dict[str, object] = {"address": address}
    if chassis is not None:
        reported["chassis_id"] = chassis.key
    inputs: list[QueryInput | RecordInput] = [
        QueryInput(id=q.id, mib_object=q.mib_object, snapshot=reported)
    ]
    if device_id is not None:
        known_chassis, _ = await _device_facts(conn, device_id)
        snapshot: dict[str, object] = {"addresses": await _known_addresses(conn, device_id)}
        if known_chassis is not None:
            snapshot["chassis_id"] = known_chassis
        inputs.append(RecordInput(table="devices", id=device_id, snapshot=snapshot))
    return build_evidence(method, Origin.INFERRED, inputs)


async def _record_resolution(
    conn: AsyncConnection,
    q: QueryInfo,
    device_id: int,
    method: IdentityMethod,
    key_value: str,
    evidence: object,
    status: str = "active",
) -> None:
    update_ = GroupUpdate(RESOLUTION_GROUP, {"status": status}, Origin.INFERRED, method, evidence)
    key = {"method": method, "key_value": key_value, "device_id": device_id}
    await upsert(conn, identity_resolutions, key, [update_], q)


async def _record_conflict(
    conn: AsyncConnection,
    q: QueryInfo,
    method: IdentityMethod,
    key_value: str,
    known: int,
    other: int,
    evidence: object,
    now: datetime,
) -> int | None:
    stmt = (
        pg_insert(identity_conflicts)
        .values(
            key_method=method,
            key_value=key_value,
            device_id=known,
            other_device_id=other,
            evidence=evidence.to_json(),
            query_id=q.id,
            detected_at=now,
        )
        .on_conflict_do_nothing()
        .returning(identity_conflicts.c.id)
    )
    conflict = await conn.scalar(stmt)
    # Resolutions of the contested key are flagged; the devices stay separate.
    await conn.execute(
        update(identity_resolutions)
        .where(
            identity_resolutions.c.method == method,
            identity_resolutions.c.key_value == key_value,
            identity_resolutions.c.device_id.in_([known, other]),
        )
        .values(status="conflicted")
    )
    return conflict


async def resolve_device(
    conn: AsyncConnection,
    query_id: int,
    *,
    chassis: Chassis | None = None,
    sys_object_id: str | None = None,
    now: datetime,
) -> Resolution:
    """Resolve the device that answered ``query_id`` and attach the run's queries to it.

    With ``chassis`` (read by an ``lldpLocalSystemData`` query) the device is
    matched by chassis identifier, otherwise (a system group query) by the
    queried address. ``sys_object_id`` lets a chassis match be rejected when it
    contradicts the stored device. The queried address becomes a management
    address of the device and the chassis identifier is stored as observed.
    Contradictions are recorded as conflicts; devices are never merged.
    """
    await observation_lock(conn)
    q = await get_query(conn, query_id)
    expected = "LLDP-MIB::lldpLocalSystemData" if chassis else "SNMPv2-MIB::system"
    if q.mib_object != expected:
        raise StoreError(
            f"a device is resolved {'by chassis id' if chassis else 'by address'} from {expected}"
        )
    address = str(q.target_address)
    by_address = await _devices_by_address(conn, address)
    chassis_of = {d: (await _device_facts(conn, d))[0] for d in by_address}
    pending: list[tuple[IdentityMethod, str, int]] = []
    matched_by_address = False

    if chassis is not None:
        method: IdentityMethod = "chassis-id"
        key_value = chassis.key
        known = next(iter(await _devices_by_chassis(conn, chassis)), None)
        incompatible = False
        if known is not None and sys_object_id is not None:
            known_oid = (await _device_facts(conn, known))[1]
            incompatible = known_oid is not None and known_oid != sys_object_id
            if incompatible:
                pending.append(("chassis-id", chassis.key, known))
                known = None
        unlabelled = [d for d in by_address if chassis_of[d] is None]
        if known is not None:
            device, created = known, False
        elif unlabelled and not incompatible:
            # Known by its address, reporting a chassis identifier for the first time.
            device, created, matched_by_address = unlabelled[0], False, True
        else:
            device, created = (
                await conn.scalar(insert(devices).values().returning(devices.c.id)),
                True,
            )
        for other in by_address:
            if other != device and chassis_of[other] != chassis.key:
                pending.append(("address", address, other))
    else:
        method, key_value = "address", address
        if by_address:
            device, created = by_address[0], False
            pending.extend(("address", address, other) for other in by_address[1:])
        else:
            device, created = (
                await conn.scalar(insert(devices).values().returning(devices.c.id)),
                True,
            )

    known_device = None if created else device
    evidence = await _evidence(conn, method, q, address, chassis, known_device)
    await assign_device(conn, q.run_id, address, device)
    q = await get_query(conn, query_id)
    if q.device_id != device:
        raise StoreError(f"query {query_id} already belongs to another device")
    await _record_resolution(conn, q, device, method, key_value, evidence)
    if matched_by_address:
        by_addr_evidence = await _evidence(conn, "address", q, address, chassis, device)
        await _record_resolution(conn, q, device, "address", address, by_addr_evidence)
    if chassis is not None:
        update_ = GroupUpdate(
            CHASSIS,
            {"chassis_id_subtype": chassis.subtype, "chassis_id": chassis.value},
            confirms_row=True,
        )
        await apply_updates(conn, devices, device, [update_], q)
    await store_management_address(conn, q, address)

    resolution = Resolution(device_id=device, method=method, created=created)
    for key_method, key, other in pending:
        evidence_ = await _evidence(conn, key_method, q, address, chassis, other)
        conflict = await _record_conflict(conn, q, key_method, key, other, device, evidence_, now)
        if conflict is not None:
            resolution.conflicts.append(conflict)
    return resolution


async def conflicts_count(conn: AsyncConnection) -> int:
    return await conn.scalar(select(func.count()).select_from(identity_conflicts))
