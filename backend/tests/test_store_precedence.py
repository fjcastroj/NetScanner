# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Full provenance of carried fields and per-field observed/inferred precedence (design D9)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store.errors import StoreError
from netscanner.store.evidence import EvidenceError, RecordInput, build_evidence
from netscanner.store.merge import GroupUpdate, check_evidence_size, merge_group, upsert
from netscanner.store.models import ADDRESS_GROUP, device_addresses, devices, interfaces
from netscanner.store.observations import BASE, EXT, MODEL
from netscanner.store.registry import Origin
from netscanner.store.runs import QueryInfo, get_query
from netscanner.store.service import Store

from .conftest import T0, Clock
from .store_lab import Lab

H = timedelta(hours=1)
PATTERN = "sysdescr-model-pattern"
PARTIAL = {"outcome": "partial", "error_category": "transport-error"}


@pytest.fixture
def lab(store: Store, engine: AsyncEngine) -> Lab:
    return Lab(store, engine)


async def _inferred_then_partial_observed(lab: Lab, run: int | None = None) -> dict[str, int]:
    """Model and version inferred from sysDescr, then a partial ENTITY-MIB walk
    gives the model only."""
    device = await lab.device(run=run)
    system = await lab.query("SNMPv2-MIB::system", device=device, run=run)
    await lab.store.store_system(
        system, device, {"sys_descr": "LabOS version 7.2.5 model LAB-1000F"}
    )
    assert await lab.store.infer_model_from_sysdescr(device)
    entity = await lab.query(
        "ENTITY-MIB::entPhysicalTable", device=device, run=run, at=H, **PARTIAL
    )
    await lab.store.store_model(entity, device, {"model": "LAB-1000F-R2"})
    return {"device": device, "system": system, "entity": entity}


@pytest.mark.db
async def test_carried_field_keeps_its_inferred_provenance(lab: Lab) -> None:
    await lab.run()
    ids = await _inferred_then_partial_observed(lab)
    row = await lab.one(devices, id=ids["device"])
    model = (await lab.store.read_device(ids["device"])).groups["model"]

    assert model.values == {"model": "LAB-1000F-R2", "software_version": "7.2.5"}
    observed = model.field_source("model")
    assert (observed.origin, observed.method, observed.evidence, observed.query_id) == (
        "observed",
        None,
        None,
        ids["entity"],
    )
    version = model.field_source("software_version")
    assert (version.origin, version.method, version.query_id, version.seen_at) == (
        "inferred",
        PATTERN,
        ids["system"],
        T0,
    )
    assert version.evidence == row["model_carried"]["software_version"]["evidence"]
    assert version.evidence["inputs"][1]["snapshot"] == {
        "model_fragment": "model LAB-1000F",
        "version_fragment": "version 7.2.5",
    }


@pytest.mark.db
async def test_newer_inference_updates_only_the_inferred_field(lab: Lab, clock: Clock) -> None:
    await lab.run()
    ids = await _inferred_then_partial_observed(lab)
    device = ids["device"]
    newer = await lab.query("SNMPv2-MIB::system", device=device, at=2 * H)
    await lab.store.store_system(
        newer, device, {"sys_descr": "LabOS version 7.4.0 model LAB-2000E"}
    )
    assert await lab.store.infer_model_from_sysdescr(device)
    clock.now = T0 + timedelta(days=1)

    model = (await lab.store.read_device(device)).groups["model"]
    assert model.values == {"model": "LAB-1000F-R2", "software_version": "7.4.0"}
    version = model.field_source("software_version")
    assert (version.origin, version.method, version.query_id) == ("inferred", PATTERN, newer)
    assert version.evidence["inputs"][1]["snapshot"]["version_fragment"] == "version 7.4.0"
    # The observed model is carried with its own provenance and original age.
    kept = model.field_source("model")
    assert (kept.origin, kept.method, kept.query_id, kept.seen_at) == (
        "observed",
        None,
        ids["entity"],
        T0 + H,
    )
    assert kept.age == timedelta(days=1) - H
    assert "model" in model.carried and "software_version" not in model.carried


@pytest.mark.db
async def test_inference_leaves_a_fully_observed_model_unchanged(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    entity = await lab.query("ENTITY-MIB::entPhysicalTable", device=device)
    await lab.store.store_model(entity, device, {"model": "LAB-1000F", "software_version": "7.2.5"})
    system = await lab.query("SNMPv2-MIB::system", device=device, at=H)
    await lab.store.store_system(system, device, {"sys_descr": "LabOS version 8.0 model LAB-2000E"})
    before = {k: v for k, v in (await lab.one(devices, id=device)).items() if k.startswith("model")}
    assert not await lab.store.infer_model_from_sysdescr(device)
    after = {k: v for k, v in (await lab.one(devices, id=device)).items() if k.startswith("model")}
    assert after == before


@pytest.mark.db
async def test_snapshot_keeps_full_provenance_of_carried_fields(lab: Lab) -> None:
    run = await lab.run("discovery", {"snapshot": True})
    ids = await _inferred_then_partial_observed(lab, run)
    await lab.store.record_run_device(
        run, "10.99.0.11", "seed", 0, answered=True, device_id=ids["device"]
    )
    stored = (await lab.one(devices, id=ids["device"]))["model_carried"]["software_version"]
    await lab.store.finish_run(run)

    group = (await lab.store.get_snapshot(run))["devices"][0]["groups"]["model"]
    assert group["origin"] == "observed" and group["last_query_id"] == ids["entity"]
    carried = group["carried"]["software_version"]
    assert (carried["origin"], carried["method"], carried["query_id"], carried["run_id"]) == (
        "inferred",
        PATTERN,
        ids["system"],
        run,
    )
    assert carried["evidence"] == stored["evidence"]
    assert carried["seen_at"] == T0.isoformat()


# --- Joint evidence size (no database needed) -------------------------------


def _big_evidence(record_id: int) -> object:
    snapshot = {"fragment": "x" * 1000}
    inputs = [RecordInput(table="devices", id=record_id + i, snapshot=snapshot) for i in range(9)]
    return build_evidence(PATTERN, Origin.INFERRED, inputs)


def _query(query_id: int, at: timedelta) -> QueryInfo:
    return QueryInfo(
        id=query_id,
        run_id=1,
        device_id=1,
        target_address="10.99.0.11",
        mib_object="SNMPv2-MIB::system",
        outcome="partial",
        rejected_count=0,
        started_at=T0 + at,
    )


async def test_joint_evidence_size_limit_enforced() -> None:
    first = _big_evidence(1)
    stored = {
        "model": "LAB-1000F",
        "software_version": "7.2.5",
        "model_origin": "inferred",
        "model_method": PATTERN,
        "model_evidence": first.to_json(),
        "model_first_seen_at": T0,
        "model_first_query_id": 1,
        "model_last_seen_at": T0,
        "model_last_query_id": 1,
        "model_last_complete_query_id": None,
        "model_carried": {},
    }
    # Each document alone is within the limit.
    check_evidence_size(first.to_json(), {})
    later = GroupUpdate(
        MODEL, {"software_version": "7.4.0"}, Origin.INFERRED, PATTERN, _big_evidence(100)
    )
    # The model is carried with the first evidence; together they exceed it.
    with pytest.raises(EvidenceError, match="carried fields"):
        await merge_group(None, stored, later, _query(2, H))


# --- Row confirmation -------------------------------------------------------


def _stored_model(origin: str = "observed") -> dict:
    return {
        "model": "LAB-1000F",
        "software_version": "7.2.5",
        "model_origin": origin,
        "model_method": None,
        "model_evidence": None,
        "model_first_seen_at": T0,
        "model_first_query_id": 1,
        "model_last_seen_at": T0,
        "model_last_query_id": 1,
        "model_last_complete_query_id": None,
        "model_carried": {},
    }


async def test_update_without_fields_and_without_row_confirmation_changes_nothing() -> None:
    update_ = GroupUpdate(MODEL, {})
    assert await merge_group(None, _stored_model(), update_, _query(2, H)) == {}


async def test_inferred_update_fully_blocked_changes_nothing_even_as_a_row() -> None:
    evidence = _big_evidence(1)
    update_ = GroupUpdate(
        MODEL, {"model": "LAB-2000E"}, Origin.INFERRED, PATTERN, evidence, confirms_row=True
    )
    assert await merge_group(None, _stored_model(), update_, _query(2, H)) == {}


@pytest.mark.db
async def test_reconfirmed_management_address_renews_its_observation(
    lab: Lab, clock: Clock
) -> None:
    await lab.run()
    device = await lab.device()
    second = await lab.run("rediscovery")
    system = await lab.query("SNMPv2-MIB::system", run=second, at=timedelta(days=1))
    assert (await lab.store.resolve_device(system)).device_id == device
    clock.now = T0 + timedelta(days=1, hours=1)

    (address,) = [
        a for a in await lab.store.read_addresses(device) if a.key["source"] == "management"
    ]
    group = address.groups["address"]
    assert (group.last_seen_at, group.query_id, group.first_seen_at) == (
        T0 + timedelta(days=1),
        system,
        T0,
    )
    assert group.presence.state == "present" and not group.stale
    assert [group.field_state(f) for f in ("if_index", "interface_id")] == ["unknown", "unknown"]
    assert group.field_source("if_index") is None


@pytest.mark.db
async def test_late_row_confirmation_from_an_older_query(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    newer = await lab.query("IF-MIB::ifTable", device=device, at=H)
    await lab.store.store_if_table(newer, device, [{"if_index": 1, "if_descr": "port 1"}])
    older = await lab.query("IF-MIB::ifTable", device=device, at=-H)
    # The older walk returned the row but no field of the base group.
    await lab.store.store_if_table(older, device, [{"if_index": 1}])
    row = await lab.one(interfaces)
    assert (row["base_last_seen_at"], row["base_last_query_id"], row["if_descr"]) == (
        T0 + H,
        newer,
        "port 1",
    )
    assert (row["base_first_seen_at"], row["base_first_query_id"]) == (T0 - H, older)


# --- Group initialization ---------------------------------------------------


async def _store(lab: Lab, table, key: dict, updates: list[GroupUpdate], query_id: int) -> int:
    async with lab.engine.begin() as conn:
        return await upsert(conn, table, key, updates, await get_query(conn, query_id))


@pytest.mark.db
async def test_optional_group_not_initialized_on_a_new_row(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    q = await lab.query("IF-MIB::ifTable", device=device)
    key = {"device_id": device, "if_index": 1}
    base = GroupUpdate(BASE, {"if_descr": "port 1"}, confirms_row=True)
    await _store(lab, interfaces, key, [base, GroupUpdate(EXT, {})], q)
    row = await lab.one(interfaces)
    assert (row["base_origin"], row["ext_origin"], row["ext_last_query_id"]) == (
        "observed",
        None,
        None,
    )
    assert row["ext_carried"] == {}


@pytest.mark.db
async def test_never_populated_group_of_an_existing_row_stays_empty(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    base = await lab.query("IF-MIB::ifTable", device=device)
    await lab.store.store_if_table(base, device, [{"if_index": 1, "if_descr": "port 1"}])
    partial = await lab.query("IF-MIB::ifXTable", device=device, at=H, **PARTIAL)
    key = {"device_id": device, "if_index": 1}
    for update_ in (GroupUpdate(EXT, {}), GroupUpdate(EXT, {"if_alias": None, "if_name": None})):
        # No fields at all, then only None values from a partial query.
        await _store(lab, interfaces, key, [update_], partial)
        row = await lab.one(interfaces)
        assert (row["ext_origin"], row["ext_first_query_id"], row["ext_carried"]) == (
            None,
            None,
            {},
        )
        assert row["base_last_query_id"] == base


@pytest.mark.db
async def test_only_none_values_from_a_partial_query_do_not_create_a_group(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    partial = await lab.query("IF-MIB::ifXTable", device=device, **PARTIAL)
    key = {"device_id": device, "if_index": 1}
    ext = GroupUpdate(EXT, {"if_alias": None})
    with pytest.raises(StoreError, match="needs an observation"):
        await _store(lab, interfaces, key, [ext], partial)
    assert await lab.rows(interfaces) == []


@pytest.mark.db
async def test_new_row_without_its_required_group_rejected(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    q = await lab.query("IP-MIB::ipAddressTable", device=device)
    key = {"device_id": device, "address": "10.99.0.65", "source": "address_table"}
    with pytest.raises(StoreError, match="needs an observation"):
        await _store(lab, device_addresses, key, [GroupUpdate(ADDRESS_GROUP, {})], q)
    assert [r for r in await lab.rows(device_addresses) if str(r["address"]) == "10.99.0.65"] == []
    # On an existing row the same update merges (and changes nothing).
    await lab.store.store_addresses(q, device, [{"address": "10.99.0.65"}])
    before = dict((await lab.rows(device_addresses, source="address_table"))[0])
    await _store(lab, device_addresses, key, [GroupUpdate(ADDRESS_GROUP, {})], q)
    assert dict((await lab.rows(device_addresses, source="address_table"))[0]) == before
