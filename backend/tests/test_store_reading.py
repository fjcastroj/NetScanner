# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Reads with provenance, age, staleness and presence (RF-29, RF-30, design D6)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store.models import devices
from netscanner.store.service import Store

from .conftest import T0, Clock
from .store_lab import Lab

pytestmark = pytest.mark.db

DAY = timedelta(days=1)
REM = "LLDP-MIB::lldpRemTable"


@pytest.fixture
def lab(store: Store, engine: AsyncEngine) -> Lab:
    return Lab(store, engine)


def entry(port: int, name: str = "lab-sw-02") -> dict:
    return {"local_port_num": port, "remote_index": 1, "remote_sys_name": name}


async def test_device_and_interfaces_carry_their_provenance(lab: Lab, clock: Clock) -> None:
    run = await lab.run()
    device = await lab.device(name="lab-sw-01")
    base = await lab.query("IF-MIB::ifTable", device=device, at=timedelta(seconds=10))
    await lab.store.store_if_table(base, device, [{"if_index": 1, "if_descr": "port 1"}])
    clock.advance(timedelta(hours=2))

    view = await lab.store.read_device(device)
    system = view.groups["system"]
    assert system.values["sys_name"] == "lab-sw-01"
    assert (system.origin, system.mib_object, system.source_device_id, system.run_id) == (
        "observed",
        "SNMPv2-MIB::system",
        device,
        run,
    )
    vendor = view.groups["vendor"]
    assert (vendor.origin, vendor.method, vendor.values["vendor_name"]) == (
        "inferred",
        "enterprise-registry",
        "Fortinet",
    )
    assert view.groups["model"] is None
    assert [(r.key["method"], r.groups["resolution"].origin) for r in view.resolutions] == [
        ("address", "inferred")
    ]

    (iface,) = await lab.store.read_interfaces(device)
    group = iface.groups["base"]
    assert (iface.key, group.values["if_descr"], group.origin, group.method) == (
        {"if_index": 1},
        "port 1",
        "observed",
        None,
    )
    assert (group.source_device_id, group.mib_object, group.query_id, group.run_id) == (
        device,
        "IF-MIB::ifTable",
        base,
        run,
    )
    assert (group.first_seen_at, group.last_seen_at) == (T0 + timedelta(seconds=10),) * 2
    assert group.age == timedelta(hours=2) - timedelta(seconds=10)
    assert (group.stale, group.presence.state, group.presence.latest_attempt_complete) == (
        False,
        "present",
        True,
    )
    assert iface.groups["ext"] is None


async def test_staleness_around_the_period(lab: Lab, clock: Clock) -> None:
    await lab.run()
    device = await lab.device()
    clock.now = T0 + 7 * DAY
    assert not (await lab.store.read_device(device)).groups["system"].stale
    clock.now = T0 + 7 * DAY + timedelta(seconds=1)
    system = (await lab.store.read_device(device)).groups["system"]
    # Stale data is still stored and readable, with its last seen time.
    assert (system.stale, system.last_seen_at, system.values["sys_name"]) == (True, T0, "lab-sw-01")


async def test_configured_staleness_period(engine: AsyncEngine, clock: Clock) -> None:
    store = Store(engine, stale_after=timedelta(hours=1), clock=clock)
    lab = Lab(store, engine)
    await lab.run()
    device = await lab.device()
    clock.advance(timedelta(hours=1, seconds=1))
    assert (await store.read_device(device)).groups["system"].stale


async def test_present_after_a_later_partial_confirmation(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    complete = await lab.query(REM, device=device, rows=1)
    await lab.store.store_neighbors(complete, device, [entry(1)])
    partial = await lab.query(
        REM, device=device, at=DAY, outcome="partial", error_category="transport-error"
    )
    await lab.store.store_neighbors(partial, device, [entry(1)])
    (neighbor,) = await lab.store.read_neighbors(device)
    group = neighbor.groups["entry"]
    assert group.query_id == partial
    assert (group.presence.state, group.presence.latest_attempt_complete) == ("present", False)


async def test_missing_from_the_latest_complete_query(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    first = await lab.query(REM, device=device, rows=2)
    await lab.store.store_neighbors(first, device, [entry(1), entry(2, "lab-sw-03")])
    second = await lab.query(REM, device=device, at=DAY, rows=1)
    await lab.store.store_neighbors(second, device, [entry(1)])
    states = {
        n.key["local_port_num"]: n.groups["entry"].presence
        for n in await lab.store.read_neighbors(device)
    }
    assert (states[1].state, states[2].state) == ("present", "absent")
    assert states[2].latest_attempt_complete


@pytest.mark.parametrize(
    "latest",
    [
        {"outcome": "no_response", "rows": 0},
        {"outcome": "partial", "error_category": "transport-error"},
        {"outcome": "error", "rows": 0, "error_category": "snmp-error-status"},
        {"outcome": "ok", "rows": 2, "rejected": 1},
    ],
)
async def test_latest_attempt_did_not_complete(lab: Lab, latest: dict) -> None:
    await lab.run()
    device = await lab.device()
    first = await lab.query(REM, device=device, rows=1)
    await lab.store.store_neighbors(first, device, [entry(1)])
    rejected = latest.pop("rejected", 0)
    later = await lab.query(REM, device=device, at=DAY, **latest)
    if rejected:
        # A full walk with one bad row: the good row is stored, the query is not complete.
        await lab.store.store_neighbors(
            later, device, [entry(1), {"local_port_num": 0, "remote_index": 1}]
        )
    (neighbor,) = await lab.store.read_neighbors(device)
    presence = neighbor.groups["entry"].presence
    assert (presence.state, presence.latest_attempt_complete) == ("present", False)


async def test_presence_unknown_without_a_complete_query(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    partial = await lab.query(
        REM, device=device, outcome="partial", error_category="transport-error"
    )
    await lab.store.store_neighbors(partial, device, [entry(1)])
    (neighbor,) = await lab.store.read_neighbors(device)
    assert neighbor.groups["entry"].presence.state == "unknown"


async def test_age_of_a_carried_field_comes_from_its_own_query(lab: Lab, clock: Clock) -> None:
    run = await lab.run()
    device = await lab.device()
    first = await lab.query("IF-MIB::ifXTable", device=device)
    await lab.store.store_if_xtable(
        first, device, [{"if_index": 1, "if_name": "lab-port-1", "if_alias": "uplink"}]
    )
    partial = await lab.query(
        "IF-MIB::ifXTable",
        device=device,
        at=2 * DAY,
        outcome="partial",
        error_category="transport-error",
    )
    await lab.store.store_if_xtable(partial, device, [{"if_index": 1, "if_name": "lab-port-1"}])
    clock.now = T0 + 8 * DAY

    (iface,) = await lab.store.read_interfaces(device)
    ext = iface.groups["ext"]
    assert (ext.last_seen_at, ext.age, ext.stale) == (T0 + 2 * DAY, 6 * DAY, False)
    alias = ext.field_source("if_alias")
    assert (alias.query_id, alias.run_id, alias.mib_object, alias.seen_at) == (
        first,
        run,
        "IF-MIB::ifXTable",
        T0,
    )
    assert (alias.age, alias.stale) == (8 * DAY, True)
    name = ext.field_source("if_name")
    assert (name.query_id, name.stale) == (partial, False)


async def test_observed_model_is_not_touched_by_an_inferred_one(lab: Lab, clock: Clock) -> None:
    await lab.run()
    device = await lab.device()
    entity = await lab.query("ENTITY-MIB::entPhysicalTable", device=device)
    await lab.store.store_model(entity, device, {"model": "LAB-1000F", "software_version": "7.2.5"})
    before = {k: v for k, v in (await lab.one(devices, id=device)).items() if k.startswith("model")}
    system = await lab.query("SNMPv2-MIB::system", device=device, at=3 * DAY)
    await lab.store.store_system(system, device, {"sys_descr": "LabOS version 8.0 model LAB-2000E"})
    assert not await lab.store.infer_model_from_sysdescr(device)
    after = {k: v for k, v in (await lab.one(devices, id=device)).items() if k.startswith("model")}
    assert after == before
    assert (after["model_last_query_id"], after["model_last_complete_query_id"]) == (entity, entity)

    # The observed value ages normally: stale once the period has passed.
    clock.now = T0 + 7 * DAY + timedelta(seconds=1)
    model = (await lab.store.read_device(device)).groups["model"]
    assert (model.values["model"], model.origin, model.stale) == ("LAB-1000F", "observed", True)
    assert not (await lab.store.read_device(device)).groups["system"].stale
