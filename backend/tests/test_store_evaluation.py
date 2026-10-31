# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Run reports, evaluation snapshots and data minimisation (OE6, design D10, D11, D12)."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store import evaluation
from netscanner.store.evaluation import SnapshotUnavailable
from netscanner.store.models import devices, metadata
from netscanner.store.service import Store

from .conftest import Canaries, Clock, all_rows_text
from .store_lab import Lab

pytestmark = pytest.mark.db

SNAPSHOT = {"snapshot": True}


@pytest.fixture
def lab(store: Store, engine: AsyncEngine) -> Lab:
    return Lab(store, engine)


async def _reach(
    lab: Lab, run: int, address: str, way: str, depth: int, *, oid: str | None, at: timedelta
) -> int | None:
    """One candidate: a system query; resolved and stored when ``oid`` is given."""
    if oid is None:
        q = await lab.query(
            "SNMPv2-MIB::system", run=run, address=address, at=at, outcome="no_response", rows=0
        )
        await lab.store.record_run_device(run, address, way, depth, first_query_id=q)
        return None
    q = await lab.query("SNMPv2-MIB::system", run=run, address=address, at=at)
    await lab.store.record_run_device(run, address, way, depth, first_query_id=q)
    device = (await lab.store.resolve_device(q)).device_id
    await lab.store.store_system(
        q, device, {"sys_name": f"lab-{address.rsplit('.', 1)[1]}", "sys_object_id": oid}
    )
    rem = await lab.query("LLDP-MIB::lldpRemTable", run=run, address=address, device=device, at=at)
    await lab.store.store_neighbors(rem, device, [])
    return device


FORTINET = "1.3.6.1.4.1.12356.101.1.1"
NET_SNMP = "1.3.6.1.4.1.8072.3.2.10"


async def test_report_figures(lab: Lab, clock: Clock) -> None:
    first = await lab.run()
    await _reach(lab, first, "10.99.0.11", "seed", 0, oid=FORTINET, at=timedelta(0))
    await _reach(lab, first, "10.99.0.12", "lldp", 1, oid=NET_SNMP, at=timedelta(seconds=5))
    await _reach(lab, first, "10.99.0.40", "ip-mac", 1, oid=None, at=timedelta(seconds=6))
    clock.advance(timedelta(minutes=3))
    await lab.store.finish_run(first)

    clock.advance(timedelta(days=1))
    second = await lab.run("rediscovery")
    clock.advance(timedelta(seconds=90))
    day = timedelta(days=1, minutes=3)
    await _reach(lab, second, "10.99.0.11", "seed", 0, oid=FORTINET, at=day)
    await _reach(lab, second, "10.99.0.12", "lldp", 1, oid=NET_SNMP, at=day)
    await _reach(lab, second, "10.99.0.13", "lldp", 1, oid=FORTINET, at=day)
    await lab.store.finish_run(second)

    report = await lab.store.run_report(first)
    assert (
        report["reached"],
        report["devices"],
        report["new_devices"],
        report["without_answer"],
    ) == (3, 2, 2, 1)
    assert report["reached_by"] == {"ip-mac": 1, "lldp": 1, "seed": 1}
    assert report["duration_seconds"] == 180.0

    report = await lab.store.run_report(second)
    assert (
        report["reached"],
        report["devices"],
        report["new_devices"],
        report["without_answer"],
    ) == (3, 3, 1, 0)
    assert report["duration_seconds"] == 90.0
    assert report["outcomes"] == [
        {"vendor": "Fortinet", "mib_object": "LLDP-MIB::lldpRemTable", "outcome": "ok", "count": 2},
        {"vendor": "Fortinet", "mib_object": "SNMPv2-MIB::system", "outcome": "ok", "count": 2},
        {"vendor": "unknown", "mib_object": "LLDP-MIB::lldpRemTable", "outcome": "ok", "count": 1},
        {"vendor": "unknown", "mib_object": "SNMPv2-MIB::system", "outcome": "ok", "count": 1},
    ]
    first_outcomes = {
        (o["vendor"], o["mib_object"], o["outcome"]): o["count"]
        for o in (await lab.store.run_report(first))["outcomes"]
    }
    assert first_outcomes[("unknown", "SNMPv2-MIB::system", "no_response")] == 1


async def test_report_is_a_query_over_stored_records(lab: Lab, engine: AsyncEngine) -> None:
    """The figures come from tables, not logs: a fresh store on the same database sees them."""
    run = await lab.run()
    await _reach(lab, run, "10.99.0.11", "seed", 0, oid=FORTINET, at=timedelta(0))
    await lab.store.finish_run(run)
    assert (await Store(engine).run_report(run))["reached"] == 1


async def _interface_run(
    lab: Lab, descr: str, *, params: dict | None = None, at: timedelta = timedelta(0)
) -> tuple[int, int]:
    run = await lab.run("discovery", params)
    device = await lab.device(run=run, at=at)
    q = await lab.query("IF-MIB::ifTable", run=run, device=device, at=at)
    await lab.store.store_if_table(q, device, [{"if_index": 1, "if_descr": descr}])
    await lab.store.record_run_device(
        run, "10.99.0.11", "seed", 0, first_query_id=q, answered=True, device_id=device
    )
    return run, device


async def test_snapshot_unchanged_after_later_runs(lab: Lab) -> None:
    first, device = await _interface_run(lab, "before", params=SNAPSHOT)
    await lab.store.finish_run(first)
    snapshot = await lab.store.get_snapshot(first)

    second, _ = await _interface_run(lab, "after", at=timedelta(days=1))
    rem = await lab.query("LLDP-MIB::lldpRemTable", run=second, device=device, at=timedelta(days=1))
    await lab.store.store_neighbors(
        rem, device, [{"local_port_num": 1, "remote_index": 1, "remote_sys_name": "lab-sw-02"}]
    )
    await lab.store.finish_run(second)

    assert await lab.store.get_snapshot(first) == snapshot
    (doc,) = snapshot["devices"]
    assert doc["id"] == device and doc["neighbors"] == []
    base = doc["interfaces"][0]["groups"]["base"]
    assert (
        base["values"]["if_descr"],
        base["origin"],
        base["mib_object"],
        base["last_run_id"],
    ) == (
        "before",
        "observed",
        "IF-MIB::ifTable",
        first,
    )
    assert base["confirmed_by_this_run"] is True
    assert snapshot["schema_version"] == evaluation.SNAPSHOT_SCHEMA_VERSION
    assert doc["reached"] == [
        {"target_address": "10.99.0.11", "reached_via": "seed", "depth": 0, "answered": True}
    ]


async def test_datum_confirmed_by_another_run_before_closing(lab: Lab) -> None:
    first, device = await _interface_run(lab, "seen by the first run", params=SNAPSHOT)
    other = await lab.run("polling")
    q = await lab.query("IF-MIB::ifTable", run=other, device=device, at=timedelta(minutes=5))
    await lab.store.store_if_table(q, device, [{"if_index": 1, "if_descr": "confirmed later"}])
    await lab.store.finish_run(first)
    base = (await lab.store.get_snapshot(first))["devices"][0]["interfaces"][0]["groups"]["base"]
    assert (base["last_run_id"], base["confirmed_by_this_run"], base["values"]["if_descr"]) == (
        other,
        False,
        "confirmed later",
    )


async def test_run_without_snapshot_cannot_be_reconstructed(lab: Lab) -> None:
    run, _ = await _interface_run(lab, "x")
    await lab.store.finish_run(run)
    with pytest.raises(SnapshotUnavailable, match="cannot be reconstructed retrospectively"):
        await lab.store.get_snapshot(run)
    pending = await lab.store.create_run("discovery", SNAPSHOT)
    with pytest.raises(SnapshotUnavailable, match="has not closed yet"):
        await lab.store.get_snapshot(pending)
    await lab.store.start_run(pending)
    await lab.store.mark_interrupted_runs()
    with pytest.raises(SnapshotUnavailable, match="interrupted"):
        await lab.store.get_snapshot(pending)


async def test_observation_write_waits_while_snapshot_is_built(
    lab: Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, device = await _interface_run(lab, "before", params=SNAPSHOT)
    q = await lab.query("IF-MIB::ifTable", run=run, device=device, at=timedelta(minutes=1))
    building, release = asyncio.Event(), asyncio.Event()
    real = evaluation.build_snapshot

    isolation = []

    async def slow_build(conn, *args: object) -> dict:
        isolation.append(await conn.scalar(text("SHOW transaction_isolation")))
        building.set()
        await release.wait()
        return await real(conn, *args)

    monkeypatch.setattr(evaluation, "build_snapshot", slow_build)
    finishing = asyncio.create_task(lab.store.finish_run(run))
    await asyncio.wait_for(building.wait(), 10)
    write = asyncio.create_task(
        lab.store.store_if_table(q, device, [{"if_index": 1, "if_descr": "after"}])
    )
    await asyncio.sleep(0.5)
    assert not write.done()  # blocked on the observation lock
    release.set()
    await asyncio.wait_for(finishing, 10)
    await asyncio.wait_for(write, 10)
    snapshot = await lab.store.get_snapshot(run)
    assert (
        snapshot["devices"][0]["interfaces"][0]["groups"]["base"]["values"]["if_descr"] == "before"
    )
    (iface,) = await lab.store.read_interfaces(device)
    assert iface.groups["base"].values["if_descr"] == "after"


async def test_data_minimisation(lab: Lab, engine: AsyncEngine, canaries: Canaries) -> None:
    contact, location = canaries.secret_key, canaries.db_password
    serial = "canary-serial-" + contact[-8:]
    run = await lab.run("discovery", SNAPSHOT)
    system = await lab.query("SNMPv2-MIB::system")
    device = (await lab.store.resolve_device(system)).device_id
    await lab.store.record_run_device(
        run, "10.99.0.11", "seed", 0, first_query_id=system, answered=True, device_id=device
    )
    await lab.store.store_system(
        system,
        device,
        {
            "sys_name": "lab-sw-01",
            "sys_descr": f"LabOS version 7.2.5 model LAB-1000F serial {serial}",
            "sys_object_id": FORTINET,
            "sys_contact": contact,
            "sysContact": contact,
            "sys_location": location,
            "sysLocation": location,
            "serial_number": serial,
        },
    )
    assert await lab.store.infer_model_from_sysdescr(device)
    await lab.store.finish_run(run)

    everything = await lab.store.read_device(device)
    assert everything.groups["model"].values["model"] == "LAB-1000F"
    rows = await all_rows_text(engine)
    assert contact not in rows and location not in rows
    evidence_and_snapshots = await _evidence_and_snapshots(engine)
    assert serial not in evidence_and_snapshots
    snapshot = json.dumps(await lab.store.get_snapshot(run))
    assert contact not in snapshot and location not in snapshot and serial not in snapshot
    # sysDescr itself is kept, as RF-03 requires; nowhere else holds it.
    assert serial in (await lab.one(devices, id=device))["sys_descr"]
    columns = {c.name for t in metadata.sorted_tables for c in t.columns}
    assert not {
        c for c in columns if any(w in c for w in ("contact", "location", "serial", "community"))
    }


async def _evidence_and_snapshots(engine: AsyncEngine) -> str:
    parts = []
    async with engine.connect() as conn:
        for table in metadata.sorted_tables:
            for column in table.columns:
                if column.name.endswith("evidence") or column.name in (
                    "content",
                    "carried",
                    "parameters",
                    "summary",
                ):
                    # Names come from the model metadata, not from input.
                    sql = f"SELECT {column.name}::text FROM {table.name}"  # noqa: S608
                    rows = await conn.execute(text(sql))
                    parts.extend(v for v in rows.scalars() if v)
    return "\n".join(parts)
