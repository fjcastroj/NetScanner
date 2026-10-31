# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Records for the evaluation (OE6): run reports and evaluation snapshots (design D11, D12).

A snapshot is built by ``Store.finish_run`` inside the transaction that closes
the run, at ``REPEATABLE READ`` and holding the observation lock exclusively,
so the document is a consistent picture of the data when the run closed.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sqlalchemy import and_, exists, func, insert, select
from sqlalchemy.ext.asyncio import AsyncConnection

from netscanner.store import reading
from netscanner.store.errors import StoreError
from netscanner.store.models import (
    collection_runs,
    devices,
    evaluation_snapshots,
    run_devices,
    snmp_queries,
)
from netscanner.store.runs import RunParameters

SNAPSHOT_SCHEMA_VERSION = 1
# Excluded from snapshots: free text that may contain identifiers (design D10).
SNAPSHOT_EXCLUDED_FIELDS = frozenset({"sys_descr"})


class SnapshotUnavailable(StoreError):
    """The evaluation snapshot of a run does not exist."""


# --- Run report -------------------------------------------------------------


async def run_report(conn: AsyncConnection, run_id: int) -> dict[str, Any]:
    """Evaluation figures of one run from ``run_devices`` and ``snmp_queries``."""
    run = (
        await conn.execute(select(collection_runs).where(collection_runs.c.id == run_id))
    ).first()
    if run is None:
        raise StoreError(f"unknown run {run_id}")
    duration = None
    if run.started_at is not None and run.finished_at is not None:
        duration = (run.finished_at - run.started_at).total_seconds()

    reached = run_devices.alias("reached")
    earlier = run_devices.alias("earlier")
    by_way = await conn.execute(
        select(reached.c.reached_via, func.count())
        .where(reached.c.run_id == run_id)
        .group_by(reached.c.reached_via)
        .order_by(reached.c.reached_via)
    )
    totals = (
        await conn.execute(
            select(
                func.count(),
                func.count().filter(reached.c.answered.is_(False)),
                func.count(func.distinct(reached.c.device_id)),
            ).where(reached.c.run_id == run_id)
        )
    ).one()
    new_devices = await conn.scalar(
        select(func.count(func.distinct(reached.c.device_id))).where(
            reached.c.run_id == run_id,
            reached.c.device_id.is_not(None),
            ~exists().where(
                and_(earlier.c.device_id == reached.c.device_id, earlier.c.run_id < run_id)
            ),
        )
    )
    vendor = func.coalesce(devices.c.vendor_name, "unknown")
    outcomes = await conn.execute(
        select(vendor, snmp_queries.c.mib_object, snmp_queries.c.outcome, func.count())
        .select_from(snmp_queries.outerjoin(devices, devices.c.id == snmp_queries.c.device_id))
        .where(snmp_queries.c.run_id == run_id)
        .group_by(vendor, snmp_queries.c.mib_object, snmp_queries.c.outcome)
        .order_by(vendor, snmp_queries.c.mib_object, snmp_queries.c.outcome)
    )
    return {
        "run_id": run_id,
        "kind": run.kind,
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "duration_seconds": duration,
        "reached": totals[0],
        "reached_by": dict(by_way.all()),
        "without_answer": totals[1],
        "devices": totals[2],
        "new_devices": new_devices,
        "outcomes": [
            {"vendor": v, "mib_object": m, "outcome": o, "count": n} for v, m, o, n in outcomes
        ],
    }


# --- Snapshots --------------------------------------------------------------


def _json(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, IPv4Address | IPv6Address):
        return str(value)
    if isinstance(value, dict):
        return {k: _json(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_json(v) for v in value]
    return value


def _group(group: reading.GroupView | None, run_id: int) -> dict[str, Any] | None:
    if group is None:
        return None
    return _json(
        {
            "values": {k: v for k, v in group.values.items() if k not in SNAPSHOT_EXCLUDED_FIELDS},
            "origin": group.origin,
            "method": group.method,
            "evidence": group.evidence,
            "mib_object": group.mib_object,
            "first_seen_at": group.first_seen_at,
            "first_query_id": group.first_query_id,
            "last_seen_at": group.last_seen_at,
            "last_query_id": group.query_id,
            # Data confirmed again by another run before this one closed is
            # attributed to that run, not to this one.
            "last_run_id": group.run_id,
            "confirmed_by_this_run": group.run_id == run_id,
            "presence": dataclasses.asdict(group.presence),
            "carried": {
                name: {
                    "query_id": s.query_id,
                    "run_id": s.run_id,
                    "mib_object": s.mib_object,
                    "seen_at": s.seen_at,
                    "origin": s.origin,
                    "method": s.method,
                    "evidence": s.evidence,
                }
                for name, s in group.carried.items()
            },
            "not_retrieved": sorted(group.not_retrieved),
        }
    )


def _record(record: reading.RecordView, run_id: int) -> dict[str, Any]:
    return {
        "id": record.id,
        "key": _json(record.key),
        "groups": {name: _group(g, run_id) for name, g in record.groups.items()},
    }


async def build_snapshot(conn: AsyncConnection, run_id: int, now: datetime) -> dict[str, Any]:
    """Devices reached by the run with their observations and provenance."""
    rows = await conn.execute(
        select(run_devices).where(run_devices.c.run_id == run_id).order_by(run_devices.c.id)
    )
    reached = rows.all()
    by_device: dict[int, list[dict[str, Any]]] = {}
    unanswered = []
    for r in reached:
        entry = _json(
            {
                "target_address": r.target_address,
                "reached_via": r.reached_via,
                "depth": r.depth,
                "answered": r.answered,
            }
        )
        if r.device_id is None:
            unanswered.append(entry)
        else:
            by_device.setdefault(r.device_id, []).append(entry)
    # Staleness depends on the reading time and is left out of the document.
    stale_after = timedelta.max
    devices_doc = []
    for device_id, ways in sorted(by_device.items()):
        device = await reading.read_device(conn, device_id, now, stale_after)
        devices_doc.append(
            {
                "id": device_id,
                "reached": ways,
                "groups": {name: _group(g, run_id) for name, g in device.groups.items()},
                "resolutions": [_record(r, run_id) for r in device.resolutions],
                "addresses": [
                    _record(r, run_id)
                    for r in await reading.read_addresses(conn, device_id, now, stale_after)
                ],
                "interfaces": [
                    _record(r, run_id)
                    for r in await reading.read_interfaces(conn, device_id, now, stale_after)
                ],
                "neighbors": [
                    _record(r, run_id)
                    for r in await reading.read_neighbors(conn, device_id, now, stale_after)
                ],
                "ip_mac": [
                    _record(r, run_id)
                    for r in await reading.read_ip_mac(conn, device_id, now, stale_after)
                ],
            }
        )
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "run_id": run_id,
        "closed_at": now.isoformat(),
        "devices": devices_doc,
        "unanswered": unanswered,
    }


async def store_snapshot(conn: AsyncConnection, run_id: int, now: datetime) -> None:
    content = await build_snapshot(conn, run_id, now)
    await conn.execute(
        insert(evaluation_snapshots).values(
            run_id=run_id, created_at=now, schema_version=SNAPSHOT_SCHEMA_VERSION, content=content
        )
    )


async def get_snapshot(conn: AsyncConnection, run_id: int) -> dict[str, Any]:
    run = (
        await conn.execute(
            select(collection_runs.c.status, collection_runs.c.parameters).where(
                collection_runs.c.id == run_id
            )
        )
    ).first()
    if run is None:
        raise StoreError(f"unknown run {run_id}")
    content = await conn.scalar(
        select(evaluation_snapshots.c.content).where(evaluation_snapshots.c.run_id == run_id)
    )
    if content is not None:
        return content
    if RunParameters.model_validate(run.parameters).snapshot:
        if run.status in ("pending", "running"):
            raise SnapshotUnavailable(
                f"run {run_id} has not closed yet; its snapshot is taken then"
            )
        raise SnapshotUnavailable(f"run {run_id} was interrupted before its snapshot was taken")
    raise SnapshotUnavailable(
        f"run {run_id} did not request a snapshot, so it cannot be reconstructed retrospectively"
    )
