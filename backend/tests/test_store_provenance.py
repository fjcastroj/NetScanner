# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Recording rules of the data-provenance spec (design D1, D4, D9)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store.errors import StoreError
from netscanner.store.merge import GroupUpdate
from netscanner.store.models import interfaces, neighbor_entries, snmp_queries
from netscanner.store.observations import BASE
from netscanner.store.registry import Origin
from netscanner.store.service import Store

from .conftest import T0, all_rows_text
from .store_lab import Lab

pytestmark = pytest.mark.db

H = timedelta(hours=1)


@pytest.fixture
def lab(store: Store, engine: AsyncEngine) -> Lab:
    return Lab(store, engine)


async def _device(lab: Lab, address: str = "10.99.0.11", name: str = "lab-sw-01") -> int:
    if lab._run is None:
        await lab.run()
    return await lab.device(address, name=name)


def kept(query_id: int, at=T0) -> dict:
    """A carried entry of an observed field without method, as stored."""
    return {
        "query_id": query_id,
        "seen_at": at.isoformat(),
        "origin": "observed",
        "method": None,
        "evidence": None,
    }


def _iface(table_rows: list) -> dict:
    assert len(table_rows) == 1
    return dict(table_rows[0])


async def test_datum_recorded_from_a_query(lab: Lab) -> None:
    run = await lab.run()
    device = await _device(lab)
    q = await lab.query("IF-MIB::ifTable", device=device, at=H)
    await lab.store.store_if_table(q, device, [{"if_index": 1, "if_descr": "port 1"}])
    row = _iface(await lab.rows(interfaces))
    assert (
        row["device_id"],
        row["base_origin"],
        row["base_first_query_id"],
        row["base_last_query_id"],
    ) == (
        device,
        "observed",
        q,
        q,
    )
    assert (row["base_first_seen_at"], row["base_last_seen_at"]) == (T0 + H, T0 + H)
    query = await lab.one(snmp_queries, id=q)
    assert (query["run_id"], query["mib_object"], query["device_id"]) == (
        run,
        "IF-MIB::ifTable",
        device,
    )


async def test_datum_without_a_source_rejected(lab: Lab) -> None:
    device = await _device(lab)
    with pytest.raises(StoreError, match="unknown query"):
        await lab.store.store_if_table(999_999, device, [{"if_index": 1}])
    with pytest.raises(StoreError, match="method and evidence"):
        GroupUpdate(BASE, {"if_descr": "x"}, Origin.INFERRED)
    with pytest.raises(StoreError, match="needs its sources"):
        GroupUpdate(BASE, {"if_descr": "x"}, Origin.OBSERVED, "ip-mac-ifindex")
    assert await lab.rows(interfaces) == []


async def test_datum_of_another_device_rejected(lab: Lab) -> None:
    sw1 = await _device(lab, "10.99.0.11", "lab-sw-01")
    sw2 = await _device(lab, "10.99.0.12", "lab-sw-02")
    q = await lab.query("IF-MIB::ifTable", device=sw1)
    with pytest.raises(StoreError, match="belongs to another device"):
        await lab.store.store_if_table(q, sw2, [{"if_index": 1}])
    assert await lab.rows(interfaces) == []


async def test_query_of_another_table_rejected(lab: Lab) -> None:
    device = await _device(lab)
    q = await lab.query("IF-MIB::ifXTable", device=device)
    with pytest.raises(StoreError, match="cannot store this datum"):
        await lab.store.store_if_table(q, device, [{"if_index": 1}])


async def test_same_entry_in_a_later_run(lab: Lab) -> None:
    device = await _device(lab)
    first = await lab.query("IF-MIB::ifTable", device=device)
    await lab.store.store_if_table(first, device, [{"if_index": 1, "if_descr": "old"}])
    later = await lab.query("IF-MIB::ifTable", device=device, run=await lab.run(), at=H)
    await lab.store.store_if_table(later, device, [{"if_index": 1, "if_descr": "new"}])
    row = _iface(await lab.rows(interfaces))
    assert (row["base_first_query_id"], row["base_first_seen_at"]) == (first, T0)
    assert (row["base_last_query_id"], row["base_last_seen_at"], row["if_descr"]) == (
        later,
        T0 + H,
        "new",
    )


async def test_late_result_from_an_older_query(lab: Lab) -> None:
    device = await _device(lab)
    older = await lab.query("IF-MIB::ifTable", device=device, at=-H)
    newer = await lab.query("IF-MIB::ifTable", device=device, at=H)
    await lab.store.store_if_table(newer, device, [{"if_index": 1, "if_descr": "new"}])
    await lab.store.store_if_table(older, device, [{"if_index": 1, "if_descr": "old"}])
    row = _iface(await lab.rows(interfaces))
    assert (row["base_first_query_id"], row["base_first_seen_at"]) == (older, T0 - H)
    assert (row["base_last_query_id"], row["base_last_seen_at"], row["if_descr"]) == (
        newer,
        T0 + H,
        "new",
    )
    assert row["base_last_complete_query_id"] == newer


async def test_same_query_stored_twice_is_idempotent(lab: Lab, engine: AsyncEngine) -> None:
    device = await _device(lab)
    base = await lab.query("IF-MIB::ifTable", device=device)
    ext = await lab.query(
        "IF-MIB::ifXTable", device=device, outcome="partial", error_category="transport_error", at=H
    )
    await lab.store.store_if_table(
        base, device, [{"if_index": 1, "if_descr": "a", "if_speed": 100}]
    )
    await lab.store.store_if_xtable(ext, device, [{"if_index": 1, "if_name": "lab-port-1"}])
    once = await all_rows_text(engine)
    await lab.store.store_if_table(
        base, device, [{"if_index": 1, "if_descr": "a", "if_speed": 100}]
    )
    await lab.store.store_if_xtable(ext, device, [{"if_index": 1, "if_name": "lab-port-1"}])
    assert await all_rows_text(engine) == once


async def test_equal_start_times_ordered_by_query_id(lab: Lab) -> None:
    devices = [await _device(lab, f"10.99.0.{11 + i}", f"lab-sw-0{i + 1}") for i in range(2)]
    stored = []
    for device, reverse in zip(devices, (False, True), strict=True):
        low = await lab.query("IF-MIB::ifTable", device=device, at=H)
        high = await lab.query("IF-MIB::ifTable", device=device, at=H)
        calls = [(low, "from-low"), (high, "from-high")]
        for q, descr in reversed(calls) if reverse else calls:
            await lab.store.store_if_table(q, device, [{"if_index": 1, "if_descr": descr}])
        row = dict((await lab.rows(interfaces, device_id=device))[0])
        assert (row["base_first_query_id"], row["base_last_query_id"]) == (low, high)
        stored.append(row["if_descr"])
    assert stored == ["from-high", "from-high"]


async def test_group_not_queried_is_untouched(lab: Lab) -> None:
    device = await _device(lab)
    ext = await lab.query("IF-MIB::ifXTable", device=device)
    await lab.store.store_if_xtable(
        ext, device, [{"if_index": 1, "if_name": "lab-port-1", "if_alias": "uplink"}]
    )
    before = _iface(await lab.rows(interfaces))
    base = await lab.query("IF-MIB::ifTable", device=device, at=H)
    await lab.store.store_if_table(base, device, [{"if_index": 1, "if_descr": "port 1"}])
    after = _iface(await lab.rows(interfaces))
    ext_columns = [
        k for k in after if k.startswith("ext_") or k in ("if_name", "if_alias", "if_high_speed")
    ]
    assert {k: after[k] for k in ext_columns} == {k: before[k] for k in ext_columns}
    assert after["base_last_query_id"] == base


async def test_field_absent_in_a_complete_query_becomes_empty(lab: Lab) -> None:
    device = await _device(lab)
    first = await lab.query("IF-MIB::ifXTable", device=device)
    full = {"if_index": 1, "if_name": "lab-port-1", "if_high_speed": 1000}
    await lab.store.store_if_xtable(first, device, [{**full, "if_alias": "uplink"}])
    complete = await lab.query("IF-MIB::ifXTable", device=device, at=H)
    await lab.store.store_if_xtable(complete, device, [{**full, "if_alias": None}])
    row = _iface(await lab.rows(interfaces))
    assert (row["if_alias"], row["ext_last_query_id"], row["ext_carried"]) == (None, complete, {})
    (view,) = await lab.store.read_interfaces(device)
    assert view.groups["ext"].field_state("if_alias") == "absent"


async def test_confirmed_absence_is_carried_like_a_value(lab: Lab) -> None:
    device = await _device(lab)
    complete = await lab.query("IF-MIB::ifXTable", device=device)
    await lab.store.store_if_xtable(
        complete,
        device,
        [{"if_index": 1, "if_name": "lab-port-1", "if_alias": None, "if_high_speed": 1000}],
    )
    partial = await lab.query(
        "IF-MIB::ifXTable", device=device, at=H, outcome="partial", error_category="transport_error"
    )
    await lab.store.store_if_xtable(partial, device, [{"if_index": 1, "if_name": "lab-port-1b"}])
    row = _iface(await lab.rows(interfaces))
    assert row["ext_carried"] == {
        "if_alias": kept(complete),
        "if_high_speed": kept(complete),
    }
    ext = (await lab.store.read_interfaces(device))[0].groups["ext"]
    assert ext.field_state("if_alias") == "absent"
    assert ext.field_source("if_alias").query_id == complete


async def test_fresh_row_from_a_partial_query(lab: Lab) -> None:
    device = await _device(lab)
    partial = await lab.query(
        "IF-MIB::ifXTable", device=device, outcome="partial", error_category="transport_error"
    )
    # if_alias reported absent by a partial query is not a confirmed absence.
    await lab.store.store_if_xtable(
        partial, device, [{"if_index": 1, "if_name": "lab-port-1", "if_alias": None}]
    )
    row = _iface(await lab.rows(interfaces))
    assert row["ext_carried"] == {
        "if_alias": {"retrieved": False},
        "if_high_speed": {"retrieved": False},
    }
    ext = (await lab.store.read_interfaces(device))[0].groups["ext"]
    assert [ext.field_state(f) for f in ("if_name", "if_alias", "if_high_speed")] == [
        "value",
        "unknown",
        "unknown",
    ]
    assert ext.field_source("if_alias") is None
    assert ext.field_source("if_name").query_id == partial

    # Still not retrieved by a later partial query: the entry stays as it is.
    later = await lab.query(
        "IF-MIB::ifXTable", device=device, at=H, outcome="partial", error_category="transport_error"
    )
    await lab.store.store_if_xtable(
        later, device, [{"if_index": 1, "if_name": "lab-port-1", "if_high_speed": 1000}]
    )
    row = _iface(await lab.rows(interfaces))
    assert row["ext_carried"] == {"if_alias": {"retrieved": False}}


async def test_partial_query_keeps_field_not_retrieved_with_its_own_query(lab: Lab) -> None:
    device = await _device(lab)
    first = await lab.query("IF-MIB::ifXTable", device=device)
    await lab.store.store_if_xtable(
        first,
        device,
        [{"if_index": 1, "if_name": "lab-port-1", "if_alias": "uplink", "if_high_speed": 1000}],
    )
    partial = await lab.query(
        "IF-MIB::ifXTable", device=device, at=H, outcome="partial", error_category="transport_error"
    )
    # The walk stopped after the names: alias and speed were not retrieved,
    # and a value reported absent by a partial query does not count as absence.
    await lab.store.store_if_xtable(
        partial, device, [{"if_index": 1, "if_name": "lab-port-1b", "if_high_speed": None}]
    )
    row = _iface(await lab.rows(interfaces))
    assert (row["if_name"], row["if_alias"], row["if_high_speed"]) == (
        "lab-port-1b",
        "uplink",
        1000,
    )
    assert row["ext_last_query_id"] == partial
    assert row["ext_last_complete_query_id"] == first
    assert row["ext_carried"] == {
        "if_alias": kept(first),
        "if_high_speed": kept(first),
    }

    second_partial = await lab.query(
        "IF-MIB::ifXTable",
        device=device,
        at=2 * H,
        outcome="partial",
        error_category="transport_error",
    )
    await lab.store.store_if_xtable(
        second_partial, device, [{"if_index": 1, "if_name": "lab-port-1c", "if_high_speed": 2000}]
    )
    row = _iface(await lab.rows(interfaces))
    # The alias still comes from the first query, not from the intermediate one;
    # the speed, retrieved by the second partial query, takes it as provenance.
    assert row["ext_carried"] == {"if_alias": kept(first)}
    ext = (await lab.store.read_interfaces(device))[0].groups["ext"]
    assert ext.field_source("if_alias").query_id == first
    assert ext.field_source("if_high_speed").query_id == second_partial

    whole = await lab.query("IF-MIB::ifXTable", device=device, at=3 * H)
    await lab.store.store_if_xtable(
        whole,
        device,
        [{"if_index": 1, "if_name": "lab-port-1", "if_alias": "core", "if_high_speed": 1000}],
    )
    row = _iface(await lab.rows(interfaces))
    assert (row["ext_carried"], row["ext_last_query_id"], row["ext_last_complete_query_id"]) == (
        {},
        whole,
        whole,
    )


async def test_neighbor_confirmed_without_reevaluating_its_mapping(lab: Lab) -> None:
    device = await _device(lab)
    ext = await lab.query("IF-MIB::ifXTable", device=device)
    await lab.store.store_if_xtable(ext, device, [{"if_index": 3, "if_name": "lab-port-3"}])
    rem = await lab.query("LLDP-MIB::lldpRemTable", device=device)
    await lab.store.store_neighbors(
        rem, device, [{"local_port_num": 3, "remote_index": 1, "remote_sys_name": "lab-sw-02"}]
    )
    loc = await lab.query("LLDP-MIB::lldpLocPortTable", device=device)
    await lab.store.map_local_ports(
        loc, device, [{"local_port_num": 3, "port_id_subtype": 5, "port_id": "lab-port-3"}]
    )
    later = await lab.query("LLDP-MIB::lldpRemTable", device=device, run=await lab.run(), at=H)
    await lab.store.store_neighbors(
        later, device, [{"local_port_num": 3, "remote_index": 1, "remote_sys_name": "lab-sw-02"}]
    )
    row = dict(await lab.one(neighbor_entries))
    assert (row["entry_last_seen_at"], row["entry_last_query_id"]) == (T0 + H, later)
    assert (row["local_map_last_seen_at"], row["local_map_last_query_id"]) == (T0, loc)
    assert row["local_interface_id"] is not None


async def test_inferred_evidence_keeps_its_snapshot(lab: Lab) -> None:
    device = await _device(lab)
    base = await lab.query("IF-MIB::ifTable", device=device)
    await lab.store.store_if_table(base, device, [{"if_index": 8, "if_descr": "port eight"}])
    rem = await lab.query("LLDP-MIB::lldpRemTable", device=device)
    await lab.store.store_neighbors(rem, device, [{"local_port_num": 2, "remote_index": 1}])
    loc = await lab.query("LLDP-MIB::lldpLocPortTable", device=device)
    await lab.store.map_local_ports(
        loc,
        device,
        [{"local_port_num": 2, "port_id_subtype": 7, "port_id": "2", "port_desc": "port eight"}],
    )
    renamed = await lab.query("IF-MIB::ifTable", device=device, at=H)
    await lab.store.store_if_table(renamed, device, [{"if_index": 8, "if_descr": "renamed"}])
    iface = _iface(await lab.rows(interfaces))
    assert iface["if_descr"] == "renamed"
    evidence = (await lab.one(neighbor_entries))["local_map_evidence"]
    record = evidence["inputs"][-1]
    assert record == {
        "kind": "record",
        "table": "interfaces",
        "id": iface["id"],
        "snapshot": {"lldp_loc_port_desc": "port eight", "if_descr": "port eight"},
    }
