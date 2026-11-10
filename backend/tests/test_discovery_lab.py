# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Discovery runs over the simulated lab (task 5.6, device-discovery spec).

The fixture of design D4 serves each lab device from its own snmpsim under
the lab community; unmapped lab addresses go to a silent scripted agent and
203.0.113.10, outside the scope, to a canary agent that must never receive a
datagram.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.config import Settings
from netscanner.snmp.walker import SnmpLimits
from netscanner.store.runs import RunLimits

from .conftest import DiscoveryLab
from .discovery_run import Network, Run, discover
from .snmp_agent import Behaviour, ScriptedAgent

pytestmark = [pytest.mark.db, pytest.mark.lab]

SRX, SW1, SW2, SILENT, EXTERNAL = (
    "10.99.0.13",
    "10.99.0.2",
    "10.99.0.3",
    "10.99.0.9",
    "203.0.113.10",
)
LAB_CREDENTIAL = {"version": "2c", "community": "netscanner-lab"}
REASONS = {
    "out_of_scope", "excluded", "special_address", "already_known", "max_depth",
    "limit_reached", "no_response", "auth_failed", "query_error",
}  # fmt: skip


@dataclass
class Lab:
    network: Network
    silent: ScriptedAgent
    canary: ScriptedAgent
    engine: AsyncEngine
    secret_key: str

    async def discover(self, **kwargs: object) -> Run:
        kwargs.setdefault("credential", LAB_CREDENTIAL)
        return await discover(self.engine, self.secret_key, self.network, **kwargs)  # type: ignore[arg-type]


@pytest.fixture
async def lab(
    discovery_lab: DiscoveryLab, engine: AsyncEngine, store_settings: Settings
) -> AsyncIterator[Lab]:
    silent = ScriptedAgent({}, community="netscanner-lab", behaviour=Behaviour(stop_after=0))
    canary = ScriptedAgent({}, community="netscanner-lab")
    async with silent, canary:
        network = Network({**discovery_lab.ports, EXTERNAL: canary.port}, default=silent.port)
        yield Lab(network, silent, canary, engine, store_settings.secret_key.get_secret_value())
        assert canary.requests == 0  # outside the scope: never a datagram


async def scalar(engine: AsyncEngine, sql: str, **params: object) -> object:
    async with engine.connect() as conn:
        return await conn.scalar(text(sql), params)


def assert_one_device_or_reason(devices: list[dict]) -> None:
    for d in devices:
        assert (d["device_id"] is None) != (d["skip_reason"] is None), d
        if d["skip_reason"] is not None:
            assert d["skip_reason"] in REASONS


async def assert_report_matches(run: Run) -> dict:
    report = await run.report()
    devices = await run.devices()
    assert report["reached"] == len(devices)
    assert report["devices"] == len({d["device_id"] for d in devices if d["device_id"]})
    reasons: dict[str, int] = {}
    for d in devices:
        if d["skip_reason"]:
            reasons[d["skip_reason"]] = reasons.get(d["skip_reason"], 0) + 1
    assert report["reasons"] == reasons
    by_way: dict[str, int] = {}
    for d in devices:
        by_way[d["reached_via"]] = by_way.get(d["reached_via"], 0) + 1
    assert report["reached_by"] == by_way
    queries = await run.queries()
    assert sum(o["count"] for o in report["outcomes"]) == len(queries)
    summary = (await run.run())["summary"]
    assert summary["reported_datagrams"] == sum(q["request_count"] for q in queries)
    return report


async def test_end_to_end_lab_run(lab: Lab) -> None:
    started = time.monotonic()
    run = await lab.discover(seeds=[SRX, SW1, SILENT], max_depth=1)
    elapsed = time.monotonic() - started
    assert run.status == "completed"
    found = await run.by_address()
    assert found[SRX]["device_id"] and found[SRX]["reached_via"] == "seed"
    assert found[SW1]["device_id"] and found[SW1]["reached_via"] == "seed"
    assert found[SW2]["device_id"] and found[SW2]["reached_via"] == "lldp"
    assert (
        found[SW2]["depth"] == 1 and found[SW2]["found_from_device_id"] == found[SW1]["device_id"]
    )
    assert found[EXTERNAL]["skip_reason"] == "out_of_scope"
    assert found[SILENT]["skip_reason"] == "no_response"
    assert len({found[a]["device_id"] for a in (SRX, SW1, SW2)}) == 3
    assert_one_device_or_reason(await run.devices())
    report = await assert_report_matches(run)
    assert report["reasons"] == {"no_response": 1, "out_of_scope": 1}
    assert report["devices"] == report["new_devices"] == 3

    # srx-01: its 259 interfaces, its addresses and its IP-MAC entries.
    srx = found[SRX]["device_id"]
    count = "SELECT count(*) FROM {} WHERE device_id = :d"
    assert await scalar(lab.engine, count.format("interfaces"), d=srx) == 259
    assert await scalar(lab.engine, count.format("device_addresses"), d=srx) > 0
    assert await scalar(lab.engine, count.format("ip_mac_entries"), d=srx) > 0
    # srx-01 has no ENTITY-MIB and no "model" keyword: the Juniper rule infers its model.
    # lab-sw-01's synthetic sysDescr is not in the captured format: nothing is inferred.
    model = "SELECT model, software_version, model_origin FROM devices WHERE id = :d"
    async with lab.engine.connect() as conn:
        srx_model = (await conn.execute(text(model), {"d": srx})).mappings().one()
        sw1_model = (
            (await conn.execute(text(model), {"d": found[SW1]["device_id"]})).mappings().one()
        )
    assert dict(srx_model) == {
        "model": "srx1500", "software_version": "19.4R3.11", "model_origin": "inferred"
    }  # fmt: skip
    assert sw1_model["model"] is None
    # lab-sw-02: IP-MAC fallback, its entries recording ipNetToMediaTable as their source.
    sources = await scalar(
        lab.engine,
        "SELECT array_agg(DISTINCT q.mib_object) FROM ip_mac_entries e"
        " JOIN snmp_queries q ON q.id = e.last_query_id WHERE e.device_id = :d",
        d=found[SW2]["device_id"],
    )
    assert sources == ["IP-MIB::ipNetToMediaTable"]
    # Every query of a reached device is recorded with its outcome.
    queries = await run.queries()
    for address in (SRX, SW1, SW2):
        objects = {q["mib_object"] for q in queries if q["target_address"] == address}
        assert {"SNMPv2-MIB::system", "IF-MIB::ifTable", "LLDP-MIB::lldpRemTable"} <= objects
    print("\nlab end-to-end run", f"{elapsed:.1f} s", report, await run.devices(), sep="\n")


async def test_max_depth_zero_records_neighbour_without_query(lab: Lab) -> None:
    run = await lab.discover(seeds=[SW1], max_depth=0)
    assert run.status == "completed"
    found = await run.by_address()
    assert found[SW2]["skip_reason"] == "max_depth" and found[SW2]["first_query_id"] is None
    assert not [q for q in await run.queries() if q["target_address"] == SW2]
    assert_one_device_or_reason(await run.devices())
    await assert_report_matches(run)


async def test_excluded_neighbour_is_not_queried(lab: Lab) -> None:
    run = await lab.discover(seeds=[SW1], max_depth=1, exclusions=["10.99.0.3/32"])
    assert run.status == "completed"
    found = await run.by_address()
    assert found[SW2]["skip_reason"] == "excluded"
    assert not [q for q in await run.queries() if q["target_address"] == SW2]
    assert_one_device_or_reason(await run.devices())
    await assert_report_matches(run)


async def test_ip_mac_following_with_small_timeout(lab: Lab) -> None:
    # lab-sw-01's IP-MAC table lists srx-01, lab-sw-02 and the silent address.
    limits = SnmpLimits(timeout=0.2, retries=0)
    started = time.monotonic()
    run = await lab.discover(seeds=[SW1], max_depth=1, follow_ip_mac=True, snmp_limits=limits)
    elapsed = time.monotonic() - started
    assert run.status == "completed"
    found = await run.by_address()
    assert found[SW2]["device_id"] and found[SW2]["reached_via"] == "lldp"  # LLDP comes first
    assert found[SRX]["device_id"] and found[SRX]["reached_via"] == "ip-mac"
    assert (
        found[SRX]["depth"] == 1 and found[SRX]["found_from_device_id"] == found[SW1]["device_id"]
    )
    assert (
        found[SILENT]["skip_reason"] == "no_response" and found[SILENT]["reached_via"] == "ip-mac"
    )
    assert found[EXTERNAL]["skip_reason"] == "out_of_scope"
    # srx-01's IP-MAC entries are candidates at depth 2 and none is queried: those in
    # the lab range are all srx-01's own addresses (already_known); the others are
    # outside the lab-only scope, checked before the depth (design D8).
    devices = await run.devices()
    from_srx = [d for d in devices if d["found_from_device_id"] == found[SRX]["device_id"]]
    assert from_srx and all(d["depth"] == 2 and d["first_query_id"] is None for d in from_srx)
    lab_range = [d for d in from_srx if d["target_address"].startswith("10.99.0.")]
    assert lab_range and {d["skip_reason"] for d in lab_range} == {"already_known"}
    assert {d["skip_reason"] for d in from_srx} == {"already_known", "out_of_scope"}
    assert_one_device_or_reason(devices)
    report = await assert_report_matches(run)
    assert report["devices"] == 3
    silent = [q for q in await run.queries() if q["outcome"] == "no_response"]
    assert [q["target_address"] for q in silent] == [SILENT]
    assert lab.silent.requests == 1  # one attempt at 0.2 s, no retries
    print(
        "\nIP-MAC following run",
        f"total {elapsed:.1f} s, run {report['duration_seconds']:.1f} s",
        f"{len(devices)} candidates, {len(silent)} timed out at 0.2 s",
        f"silent agent received {lab.silent.requests} datagrams",
        report["reasons"],
        report["summary"],
        sep="\n",
    )


async def test_max_candidates_counts_addresses_not_recorded(lab: Lab) -> None:
    limits = RunLimits(max_candidates=5, max_devices=256, max_datagrams=50000)
    run = await lab.discover(
        seeds=[SRX], max_depth=1, follow_ip_mac=True, limits=limits,
        snmp_limits=SnmpLimits(timeout=0.2, retries=0),
    )  # fmt: skip
    assert run.status == "completed"
    devices = await run.devices()
    assert len(devices) == 5
    summary = (await run.run())["summary"]
    assert summary["limits_reached"] == ["max_candidates"]
    assert summary["candidates_not_recorded"] > 0
    assert_one_device_or_reason(devices)
    await assert_report_matches(run)


async def test_max_devices_gives_limit_reached(lab: Lab) -> None:
    limits = RunLimits(max_candidates=4096, max_devices=1, max_datagrams=50000)
    run = await lab.discover(seeds=[SW1], max_depth=1, limits=limits)
    assert run.status == "completed"
    found = await run.by_address()
    assert found[SW1]["device_id"]
    assert found[SW2]["skip_reason"] == "limit_reached"
    assert not [q for q in await run.queries() if q["target_address"] == SW2]
    summary = (await run.run())["summary"]
    assert summary["limits_reached"] == ["max_devices"] and summary["devices_queried"] == 1
    assert_one_device_or_reason(await run.devices())
    await assert_report_matches(run)


async def test_max_datagrams_gives_limit_reached(lab: Lab) -> None:
    limits = RunLimits(max_candidates=4096, max_devices=256, max_datagrams=40)
    run = await lab.discover(seeds=[SW1, SW2], max_depth=1, limits=limits)
    assert run.status == "completed"
    summary = (await run.run())["summary"]
    assert summary["limits_reached"] == ["max_datagrams"]
    assert summary["budget_consumed"] <= 40
    assert summary["reported_datagrams"] == summary["budget_consumed"]  # v2c: no engine discovery
    queries = await run.queries()
    assert any(q["error_category"] == "request_limit" for q in queries)
    devices = await run.devices()
    assert_one_device_or_reason(devices)
    await assert_report_matches(run)
    print("\nmax_datagrams run", summary, devices, sep="\n")
