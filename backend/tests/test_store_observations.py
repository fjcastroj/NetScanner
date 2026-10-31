# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Scenarios of the network-observations spec."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store.identity import Chassis
from netscanner.store.models import (
    device_addresses,
    devices,
    identity_conflicts,
    identity_resolutions,
    interfaces,
    ip_mac_entries,
    neighbor_entries,
    snmp_queries,
)
from netscanner.store.observations import IF_SPEED_MAX
from netscanner.store.service import Store

from .conftest import Canaries, all_rows_text
from .store_lab import Lab

pytestmark = pytest.mark.db

CHASSIS_A = Chassis(4, "02:00:00:00:00:01")
CHASSIS_B = Chassis(4, "02:00:00:00:00:02")


@pytest.fixture
def lab(store: Store, engine: AsyncEngine) -> Lab:
    return Lab(store, engine)


# --- Identity ---------------------------------------------------------------


async def test_identifiers_stored_as_observed(lab: Lab) -> None:
    await lab.run()
    device = await lab.device(chassis=CHASSIS_A)
    row = await lab.one(devices, id=device)
    assert (row["chassis_id_subtype"], row["chassis_id"], row["chassis_origin"]) == (
        4,
        "02:00:00:00:00:01",
        "observed",
    )
    lldp = await lab.one(snmp_queries, id=row["chassis_last_query_id"])
    assert (lldp["mib_object"], lldp["device_id"]) == ("LLDP-MIB::lldpLocalSystemData", device)
    assert (row["sys_object_id"], row["enterprise_number"], row["system_origin"]) == (
        "1.3.6.1.4.1.12356.101.1.1",
        12356,
        "observed",
    )
    assert row["system_method"] is None


async def test_same_chassis_through_another_address(lab: Lab) -> None:
    await lab.run()
    device = await lab.device("10.99.0.11", chassis=CHASSIS_A)
    lldp = await lab.query(
        "LLDP-MIB::lldpLocalSystemData", address="10.99.0.65", at=timedelta(minutes=1)
    )
    resolution = await lab.store.resolve_device(lldp, chassis=CHASSIS_A)
    assert (resolution.device_id, resolution.created, resolution.method) == (
        device,
        False,
        "chassis-id",
    )
    assert len(await lab.rows(devices)) == 1
    row = await lab.one(identity_resolutions, method="chassis-id", device_id=device)
    query_input, record_input = row["evidence"]["inputs"]
    assert query_input["snapshot"] == {"address": "10.99.0.65", "chassis_id": CHASSIS_A.key}
    assert record_input == {
        "kind": "record",
        "table": "devices",
        "id": device,
        "snapshot": {"addresses": ["10.99.0.11"], "chassis_id": CHASSIS_A.key},
    }
    addresses = {str(r["address"]) for r in await lab.rows(device_addresses, device_id=device)}
    assert addresses == {"10.99.0.11", "10.99.0.65"}


async def test_device_without_lldp_matched_by_address(lab: Lab) -> None:
    first = await lab.run()
    device = await lab.device("10.99.0.11")
    await lab.store.finish_run(first)
    await lab.run("rediscovery")
    system = await lab.query("SNMPv2-MIB::system", at=timedelta(days=1))
    resolution = await lab.store.resolve_device(system)
    assert (resolution.device_id, resolution.created, resolution.method) == (
        device,
        False,
        "address",
    )
    row = await lab.one(identity_resolutions, device_id=device)
    assert (row["method"], row["key_value"], row["status"], row["origin"]) == (
        "address",
        "10.99.0.11",
        "active",
        "inferred",
    )
    assert row["last_query_id"] == system


async def test_address_reported_by_another_chassis_is_a_conflict(lab: Lab) -> None:
    await lab.run()
    first = await lab.device("10.99.0.11", chassis=CHASSIS_A)
    lldp = await lab.query(
        "LLDP-MIB::lldpLocalSystemData", run=await lab.run(), at=timedelta(hours=1)
    )
    resolution = await lab.store.resolve_device(lldp, chassis=CHASSIS_B)
    assert resolution.created and resolution.device_id != first
    assert len(await lab.rows(devices)) == 2  # not merged
    conflict = await lab.one(identity_conflicts)
    assert (
        conflict["key_method"],
        conflict["key_value"],
        conflict["device_id"],
        conflict["other_device_id"],
    ) == (
        "address",
        "10.99.0.11",
        first,
        resolution.device_id,
    )
    assert conflict["needs_review"] and conflict["query_id"] == lldp
    assert conflict["evidence"]["inputs"][1]["snapshot"]["chassis_id"] == CHASSIS_A.key


async def test_same_chassis_with_incompatible_data_is_a_conflict(lab: Lab) -> None:
    await lab.run()
    first = await lab.device("10.99.0.11", chassis=CHASSIS_A)
    lldp = await lab.query("LLDP-MIB::lldpLocalSystemData", address="10.99.0.12")
    resolution = await lab.store.resolve_device(
        lldp, chassis=CHASSIS_A, sys_object_id="1.3.6.1.4.1.2636.1.1.1.2.1"
    )
    assert resolution.created and resolution.device_id != first
    conflict = await lab.one(identity_conflicts)
    assert (conflict["key_method"], conflict["key_value"]) == ("chassis-id", CHASSIS_A.key)
    statuses = {
        r["device_id"]: r["status"]
        for r in await lab.rows(identity_resolutions, method="chassis-id")
    }
    assert statuses == {first: "conflicted", resolution.device_id: "conflicted"}


# --- Attributes -------------------------------------------------------------


@pytest.mark.parametrize(
    ("oid", "vendor", "status"),
    [
        ("1.3.6.1.4.1.12356.101.1.1", "Fortinet", "known"),
        ("1.3.6.1.4.1.8072.3.2.10", None, "generic_agent"),
        ("1.3.6.1.4.1.99999.1", None, "not_in_registry"),
    ],
)
async def test_vendor_inferred_from_enterprise(
    lab: Lab, oid: str, vendor: str | None, status: str
) -> None:
    await lab.run()
    device = await lab.device()
    system = await lab.query("SNMPv2-MIB::system", at=timedelta(minutes=1), device=device)
    await lab.store.store_system(system, device, {"sys_object_id": oid})
    row = await lab.one(devices, id=device)
    number = int(oid.split(".")[6])
    assert (row["vendor_name"], row["vendor_status"], row["enterprise_number"]) == (
        vendor,
        status,
        number,
    )
    assert (row["vendor_origin"], row["vendor_method"]) == ("inferred", "enterprise-registry")
    assert row["vendor_evidence"]["inputs"] == [
        {
            "kind": "query",
            "id": system,
            "mib_object": "SNMPv2-MIB::system",
            "snapshot": {"enterprise_number": number},
        }
    ]


async def test_model_from_entity_mib_is_observed(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    q = await lab.query("ENTITY-MIB::entPhysicalTable", device=device)
    await lab.store.store_model(q, device, {"model": "LAB-1000F", "software_version": "7.2.5"})
    row = await lab.one(devices, id=device)
    assert (
        row["model"],
        row["software_version"],
        row["model_origin"],
        row["model_last_query_id"],
    ) == (
        "LAB-1000F",
        "7.2.5",
        "observed",
        q,
    )
    assert not await lab.store.infer_model_from_sysdescr(device)  # observed is not replaced


async def test_model_inferred_from_fragments_only(lab: Lab, canaries: Canaries) -> None:
    await lab.run()
    device = await lab.device()
    system = await lab.query("SNMPv2-MIB::system", at=timedelta(minutes=1), device=device)
    descr = f"LabOS version 7.2.5 build 1517 model LAB-1000F serial {canaries.secret_key}"
    await lab.store.store_system(system, device, {"sys_descr": descr})
    assert await lab.store.infer_model_from_sysdescr(device)
    row = await lab.one(devices, id=device)
    assert (row["model"], row["software_version"], row["model_origin"], row["model_method"]) == (
        "LAB-1000F",
        "7.2.5",
        "inferred",
        "sysdescr-model-pattern",
    )
    query_input, record_input = row["model_evidence"]["inputs"]
    assert query_input == {"kind": "query", "id": system, "mib_object": "SNMPv2-MIB::system"}
    assert record_input["table"] == "devices" and record_input["id"] == device
    assert record_input["snapshot"] == {
        "model_fragment": "model LAB-1000F",
        "version_fragment": "version 7.2.5",
    }
    assert canaries.secret_key not in str(row["model_evidence"])


async def test_no_model_inferred_without_a_match(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    system = await lab.query("SNMPv2-MIB::system", at=timedelta(minutes=1), device=device)
    await lab.store.store_system(system, device, {"sys_descr": "Lab switch, release 12"})
    assert not await lab.store.infer_model_from_sysdescr(device)
    assert (await lab.one(devices, id=device))["model_origin"] is None


# --- Addresses --------------------------------------------------------------


async def test_addresses_from_own_table_and_neighbor_advertisement(lab: Lab) -> None:
    await lab.run()
    device = await lab.device("10.99.0.11")
    if_q = await lab.query("IF-MIB::ifTable", rows=2, device=device)
    await lab.store.store_if_table(if_q, device, [{"if_index": 3}, {"if_index": 7}])
    addr_q = await lab.query("IP-MIB::ipAddressTable", rows=2, device=device)
    result = await lab.store.store_addresses(
        addr_q,
        device,
        [{"address": "10.99.0.11", "if_index": 3}, {"address": "10.99.0.65", "if_index": 7}],
    )
    assert result.stored == 2
    table = await lab.rows(device_addresses, source="address_table")
    by_address = {str(r["address"]): r for r in table}
    ifaces = {r["if_index"]: r["id"] for r in await lab.rows(interfaces)}
    for address, if_index in (("10.99.0.11", 3), ("10.99.0.65", 7)):
        row = by_address[address]
        assert (row["if_index"], row["interface_id"], row["last_query_id"]) == (
            if_index,
            ifaces[if_index],
            addr_q,
        )
        assert (row["origin"], row["method"]) == ("observed", "ipaddress-ifindex")
        assert [i["id"] for i in row["evidence"]["inputs"]] == [addr_q, if_q]

    rem = await lab.query("LLDP-MIB::lldpRemTable", device=device)
    await lab.store.store_neighbors(
        rem, device, [{"local_port_num": 3, "remote_index": 1, "remote_sys_name": "lab-sw-02"}]
    )
    man = await lab.query("LLDP-MIB::lldpRemManAddrTable", device=device)
    await lab.store.store_neighbor_man_addresses(
        man, device, [{"local_port_num": 3, "remote_index": 1, "address": "10.99.0.12"}]
    )
    assert [str(a) for a in (await lab.one(neighbor_entries))["man_addresses"]] == ["10.99.0.12"]
    assert "10.99.0.12" not in {str(r["address"]) for r in await lab.rows(device_addresses)}


# --- Interfaces -------------------------------------------------------------


async def test_device_without_ifxtable(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    q = await lab.query("IF-MIB::ifTable", device=device)
    await lab.store.store_if_table(
        q, device, [{"if_index": 1, "if_descr": "port 1", "if_speed": 1_000_000_000}]
    )
    await lab.query(
        "IF-MIB::ifXTable", device=device, outcome="not_available", rows=0, indicator="noSuchObject"
    )
    row = await lab.one(interfaces)
    assert (row["if_descr"], row["base_origin"], row["base_last_query_id"]) == (
        "port 1",
        "observed",
        q,
    )
    assert (row["if_name"], row["if_alias"], row["ext_origin"], row["ext_last_query_id"]) == (
        None,
        None,
        None,
        None,
    )
    assert (row["speed_bps"], row["speed_method"]) == (1_000_000_000, None)


@pytest.mark.parametrize("xtable_first", [False, True])
async def test_saturated_ifspeed_uses_ifhighspeed_with_both_sources(
    lab: Lab, xtable_first: bool
) -> None:
    await lab.run()
    device = await lab.device()
    base = await lab.query("IF-MIB::ifTable", device=device)
    ext = await lab.query("IF-MIB::ifXTable", device=device, at=timedelta(seconds=1))
    calls = [
        lambda: lab.store.store_if_table(base, device, [{"if_index": 1, "if_speed": IF_SPEED_MAX}]),
        lambda: lab.store.store_if_xtable(ext, device, [{"if_index": 1, "if_high_speed": 10_000}]),
    ]
    for call in reversed(calls) if xtable_first else calls:
        await call()
    row = await lab.one(interfaces)
    assert (row["speed_bps"], row["speed_origin"], row["speed_method"]) == (
        10_000_000_000,
        "observed",
        "ifhighspeed-when-ifspeed-saturated",
    )
    assert sorted(i["id"] for i in row["speed_evidence"]["inputs"]) == [base, ext]


# --- Neighbours -------------------------------------------------------------


async def test_neighbor_seen_from_one_side(lab: Lab) -> None:
    await lab.run()
    sw1 = await lab.device("10.99.0.11", name="lab-sw-01")
    sw2 = await lab.device("10.99.0.12", name="lab-sw-02")
    rem = await lab.query("LLDP-MIB::lldpRemTable", device=sw1)
    await lab.store.store_neighbors(
        rem,
        sw1,
        [
            {
                "local_port_num": 1,
                "remote_index": 4,
                "remote_chassis_id_subtype": 4,
                "remote_chassis_id": CHASSIS_B.value,
                "remote_port_id_subtype": 5,
                "remote_port_id": "lab-port-9",
                "remote_sys_name": "lab-sw-02",
                "time_mark": 1234,
            }
        ],
    )
    empty = await lab.query(
        "LLDP-MIB::lldpRemTable",
        address="10.99.0.12",
        device=sw2,
        outcome="empty",
        rows=0,
        indicator="end_of_subtree",
    )
    assert (await lab.store.store_neighbors(empty, sw2, [])).stored == 0
    row = await lab.one(neighbor_entries)
    assert (row["device_id"], row["protocol"], row["remote_sys_name"], row["entry_origin"]) == (
        sw1,
        "lldp",
        "lab-sw-02",
        "observed",
    )


async def test_management_address_outside_ranges_stored_without_querying(
    lab: Lab, engine: AsyncEngine
) -> None:
    await lab.run("discovery", {"allowed_ranges": ["10.99.0.0/24"]})
    device = await lab.device()
    man = await lab.query("LLDP-MIB::lldpRemManAddrTable", device=device)
    async with engine.connect() as conn:
        before = await conn.scalar(select(func.count()).select_from(snmp_queries))
    await lab.store.store_neighbor_man_addresses(
        man, device, [{"local_port_num": 2, "remote_index": 1, "address": "203.0.113.5"}]
    )
    async with engine.connect() as conn:
        assert await conn.scalar(select(func.count()).select_from(snmp_queries)) == before
    assert [str(a) for a in (await lab.one(neighbor_entries))["man_addresses"]] == ["203.0.113.5"]


async def test_management_addresses_have_their_own_query(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    rem = await lab.query("LLDP-MIB::lldpRemTable", device=device, at=timedelta(seconds=1))
    man = await lab.query("LLDP-MIB::lldpRemManAddrTable", device=device, at=timedelta(seconds=2))
    await lab.store.store_neighbors(
        rem, device, [{"local_port_num": 1, "remote_index": 1, "remote_sys_name": "lab-sw-02"}]
    )
    await lab.store.store_neighbor_man_addresses(
        man, device, [{"local_port_num": 1, "remote_index": 1, "address": "10.99.0.12"}]
    )
    row = await lab.one(neighbor_entries)
    assert (row["entry_last_query_id"], row["man_addr_last_query_id"]) == (rem, man)
    assert row["entry_last_seen_at"] < row["man_addr_last_seen_at"]


async def _neighbor_with_interfaces(lab: Lab) -> tuple[int, int, int]:
    await lab.run()
    device = await lab.device()
    base = await lab.query("IF-MIB::ifTable", device=device)
    await lab.store.store_if_table(
        base, device, [{"if_index": 10, "if_descr": "port ten"}, {"if_index": 11}]
    )
    ext = await lab.query("IF-MIB::ifXTable", device=device)
    await lab.store.store_if_xtable(
        ext,
        device,
        [{"if_index": 10, "if_name": "lab-port-10"}, {"if_index": 11, "if_name": "lab-port-11"}],
    )
    rem = await lab.query("LLDP-MIB::lldpRemTable", device=device)
    await lab.store.store_neighbors(
        rem,
        device,
        [
            {"local_port_num": 3, "remote_index": 1},
            {"local_port_num": 4, "remote_index": 1},
            {"local_port_num": 11, "remote_index": 1},
            {"local_port_num": 5, "remote_index": 1},
        ],
    )
    return device, ext, base


async def test_local_port_mapping_rules(lab: Lab) -> None:
    device, ext, _ = await _neighbor_with_interfaces(lab)
    loc = await lab.query("LLDP-MIB::lldpLocPortTable", device=device)
    result = await lab.store.map_local_ports(
        loc,
        device,
        [
            {"local_port_num": 3, "port_id_subtype": 5, "port_id": "lab-port-10"},
            {"local_port_num": 4, "port_id_subtype": 7, "port_id": "x", "port_desc": "port ten"},
            {"local_port_num": 11, "port_id_subtype": 7, "port_id": "x"},
            {"local_port_num": 5, "port_id_subtype": 7, "port_id": "unknown"},
        ],
    )
    assert result.stored == 4
    entries = {r["local_port_num"]: r for r in await lab.rows(neighbor_entries)}
    ifaces = {r["if_index"]: r["id"] for r in await lab.rows(interfaces)}

    by_name = entries[3]
    assert (
        by_name["local_interface_id"],
        by_name["local_map_origin"],
        by_name["local_map_method"],
    ) == (
        ifaces[10],
        "observed",
        "lldp-portid-ifname",
    )
    assert [i["id"] for i in by_name["local_map_evidence"]["inputs"]] == [loc, ext]

    by_descr, by_number = entries[4], entries[11]
    assert (
        by_descr["local_interface_id"],
        by_descr["local_map_origin"],
        by_descr["local_map_method"],
    ) == (
        ifaces[10],
        "inferred",
        "lldp-port-description-match",
    )
    assert (by_number["local_interface_id"], by_number["local_map_method"]) == (
        ifaces[11],
        "lldp-portnum-equals-ifindex",
    )
    assert by_number["local_map_evidence"]["inputs"][-1]["snapshot"] == {
        "lldp_loc_port_num": 11,
        "if_index": 11,
    }

    unmapped = entries[5]
    assert (
        unmapped["local_interface_id"],
        unmapped["local_map_failure"],
        unmapped["local_map_method"],
    ) == (
        None,
        "no-rule-matched",
        None,
    )
    assert unmapped["local_map_last_query_id"] == loc


async def test_cdp_entry_mapped_by_its_ifindex(lab: Lab) -> None:
    device, _, base = await _neighbor_with_interfaces(lab)
    cdp = await lab.query("CISCO-CDP-MIB::cdpCacheTable", device=device)
    await lab.store.store_neighbors(
        cdp, device, [{"local_port_num": 10, "remote_index": 1, "remote_chassis_id": "lab-sw-03"}]
    )
    row = await lab.one(neighbor_entries, protocol="cdp")
    assert (row["local_map_method"], row["local_map_origin"]) == ("cdp-cache-ifindex", "observed")
    assert [i["id"] for i in row["local_map_evidence"]["inputs"]] == [cdp, base]


# --- IP-MAC -----------------------------------------------------------------


async def test_ip_mac_entries_from_both_tables(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    base = await lab.query("IF-MIB::ifTable", device=device)
    await lab.store.store_if_table(base, device, [{"if_index": 3}])
    physical = await lab.query("IP-MIB::ipNetToPhysicalTable", device=device, rows=3)
    result = await lab.store.store_ip_mac(
        physical,
        device,
        [
            {
                "if_index": 3,
                "ip_address": "10.99.0.20",
                "mac_address": "02:00:00:00:00:20",
                "entry_type": 3,
            },
            {
                "if_index": 3,
                "ip_address": "2001:db8::20",
                "mac_address": "02:00:00:00:00:20",
                "entry_type": "dynamic",
            },
            {
                "if_index": 3,
                "ip_address": "10.99.0.21",
                "mac_address": "02:00:00:00:00:21",
                "entry_type": 2,
            },
        ],
    )
    assert (result.stored, result.skipped, result.rejected) == (2, 1, 0)
    media_device = await lab.device("10.99.0.12", name="lab-rt-01")
    media = await lab.query("IP-MIB::ipNetToMediaTable", address="10.99.0.12", device=media_device)
    await lab.store.store_ip_mac(
        media,
        media_device,
        [
            {
                "if_index": 9,
                "ip_address": "10.99.0.30",
                "mac_address": b"\x02\x00\x00\x00\x00\x30",
                "entry_type": 4,
            }
        ],
    )

    rows = await lab.rows(ip_mac_entries)
    assert {str(r["ip_address"]) for r in rows} == {"10.99.0.20", "2001:db8::20", "10.99.0.30"}
    sources = {
        str(r["ip_address"]): (await lab.one(snmp_queries, id=r["last_query_id"]))["mib_object"]
        for r in rows
    }
    assert sources["10.99.0.20"] == sources["2001:db8::20"] == "IP-MIB::ipNetToPhysicalTable"
    assert sources["10.99.0.30"] == "IP-MIB::ipNetToMediaTable"
    linked = next(r for r in rows if str(r["ip_address"]) == "10.99.0.20")
    assert (linked["interface_id"], linked["method"]) == (
        (await lab.one(interfaces))["id"],
        "ip-mac-ifindex",
    )
    unlinked = next(r for r in rows if str(r["ip_address"]) == "10.99.0.30")
    assert (unlinked["interface_id"], unlinked["method"], unlinked["entry_type"]) == (
        None,
        None,
        "static",
    )


# --- Validation (RNF-04) ----------------------------------------------------


async def test_batch_with_one_bad_row(lab: Lab, engine: AsyncEngine, canaries: Canaries) -> None:
    await lab.run()
    device = await lab.device()
    q = await lab.query("IF-MIB::ifTable", device=device, rows=100)
    rows = [{"if_index": i, "phys_address": f"02:00:00:00:00:{i:02x}"} for i in range(1, 101)]
    rows[41]["phys_address"] = f"zz:{canaries.secret_key}"
    result = await lab.store.store_if_table(q, device, rows)
    assert (result.stored, result.rejected) == (99, 1)
    query = await lab.one(snmp_queries, id=q)
    assert (query["outcome"], query["rejected_count"]) == ("ok", 1)
    stored = await lab.rows(interfaces)
    assert len(stored) == 99 and 42 not in {r["if_index"] for r in stored}
    # Not complete: it is never used to declare an interface absent.
    assert {r["base_last_complete_query_id"] for r in stored} == {None}
    canaries.assert_absent(await all_rows_text(engine))


@pytest.mark.parametrize(
    "row",
    [
        {"if_index": 0},
        {"if_index": 2**31},
        {"if_index": 1, "if_descr": "x" * 1025},
        {"if_index": 1, "if_speed": -1},
        {"if_index": "one"},
        "not a row",
    ],
)
async def test_malformed_rows_rejected(lab: Lab, row: object) -> None:
    await lab.run()
    device = await lab.device()
    q = await lab.query("IF-MIB::ifTable", device=device, rows=1)
    assert (await lab.store.store_if_table(q, device, [row])).rejected == 1
    assert await lab.rows(interfaces) == []


async def test_six_byte_rule_for_physical_addresses(lab: Lab) -> None:
    await lab.run()
    device = await lab.device()
    q = await lab.query("IF-MIB::ifTable", device=device, rows=3)
    await lab.store.store_if_table(
        q,
        device,
        [
            {"if_index": 1, "phys_address": ""},
            {"if_index": 2, "phys_address": "0200.0000.0001"},
            {"if_index": 3, "phys_address": b"\x02\x00\x00\x00\x00\x00\x00\x01"},
        ],
    )
    assert [r["phys_address"] for r in await lab.rows(interfaces)] == [
        None,
        "02:00:00:00:00:01",
        None,
    ]
