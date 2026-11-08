# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Contract suite of the SNMP client (design D14), parameterised by implementation.

Everything here is library independent: outcomes, completeness, columns
reported and error categories, against the scripted agent (what snmpsim
cannot do) and against the snmpsim lab. Every implementation of the client
interface must pass it unchanged.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
from pysnmp.proto import rfc1902, rfc1905

from netscanner.snmp import (
    SnmpClient,
    SnmpLimits,
    SnmpV2cCredential,
    SnmpV3Credential,
    Target,
    get_table,
)
from netscanner.snmp.tables import parse_oid

from .conftest import LAB_DATA, SnmpLab
from .snmp_agent import Behaviour, ScriptedAgent, table

ClientFactory = Callable[[SnmpLimits], SnmpClient]
FAST = SnmpLimits(timeout=0.3, retries=0, max_repetitions=10)

IF_TABLE = get_table("IF-MIB::ifTable")
ENTITY = get_table("ENTITY-MIB::entPhysicalTable")
LLDP_REM = get_table("LLDP-MIB::lldpRemTable")


def implementations() -> list[str]:
    """PySNMP always; the Net-SNMP comparison implementation when its tools exist."""
    from .netsnmp_client import available

    return ["pysnmp", "netsnmp"] if available() else ["pysnmp"]


@pytest.fixture(params=implementations())
def make_client(request: pytest.FixtureRequest) -> ClientFactory:
    if request.param == "pysnmp":
        from netscanner.snmp.pysnmp_client import PySnmpClient

        return PySnmpClient
    if request.param == "netsnmp":
        from .netsnmp_client import NetSnmpClient

        return NetSnmpClient
    raise AssertionError(request.param)


def if_rows(n: int, *, columns: tuple[int, ...] = (1, 2)) -> dict:
    values = {
        1: [rfc1902.Integer32(i) for i in range(1, n + 1)],
        2: [rfc1902.OctetString(f"port{i}") for i in range(1, n + 1)],
    }
    values[8] = [rfc1902.Integer32(1)] * n
    return table("1.3.6.1.2.1.2.2.1", {c: values[c] for c in columns})


def target(agent: ScriptedAgent) -> Target:
    return Target(agent.host, SnmpV2cCredential(community=agent.community), port=agent.port)


# --- Classification (design D4) ---------------------------------------------


async def test_table_with_rows_is_ok(make_client: ClientFactory) -> None:
    async with ScriptedAgent(if_rows(12)) as agent:
        result = await make_client(FAST).walk_table(target(agent), IF_TABLE)
    assert (result.outcome, result.complete, result.row_count) == ("ok", True, 12)
    assert result.rows[(3,)] == {"ifIndex": 3, "ifDescr": b"port3"}
    assert result.request_count >= 3 and result.indicator is None


async def test_object_not_implemented_is_not_available(make_client: ClientFactory) -> None:
    async with ScriptedAgent(if_rows(2)) as agent:
        result = await make_client(FAST).walk_table(target(agent), ENTITY)
    assert (result.outcome, result.indicator, result.complete, result.row_count) == (
        "not_available",
        "noSuchObject",
        True,
        0,
    )


async def test_supported_but_empty_table(make_client: ClientFactory) -> None:
    lldp_columns = {LLDP_REM.column_oid(c) for c in LLDP_REM.columns}
    async with ScriptedAgent(if_rows(2), object_types=lldp_columns) as agent:
        result = await make_client(FAST).walk_table(target(agent), LLDP_REM)
    assert (result.outcome, result.indicator, result.row_count) == ("empty", "noSuchInstance", 0)


@pytest.mark.parametrize(
    ("answer", "indicator"),
    [(rfc1905.endOfMibView, "endOfMibView"), (rfc1902.Integer32(7), "value_returned")],
)
async def test_ambiguous_probe_answer_is_recorded(
    make_client: ClientFactory, answer: object, indicator: str
) -> None:
    probe = ENTITY.column_oid(ENTITY.probe)
    behaviour = Behaviour(get_override={probe: answer})
    async with ScriptedAgent(if_rows(2), behaviour=behaviour) as agent:
        result = await make_client(FAST).walk_table(target(agent), ENTITY)
    assert (result.outcome, result.indicator) == ("empty", indicator)


async def test_the_table_node_is_never_queried(make_client: ClientFactory) -> None:
    node = IF_TABLE.oid[:-1]  # ifTable, whose GET answers noSuchObject on real devices
    behaviour = Behaviour(
        get_override={node: rfc1905.noSuchObject, IF_TABLE.oid: rfc1905.noSuchObject}
    )
    async with ScriptedAgent(if_rows(1, columns=(1,)), behaviour=behaviour) as agent:
        result = await make_client(FAST).walk_table(
            target(agent), get_table("LLDP-MIB::lldpLocPortTable")
        )
    # No rows: classified by the probe column only, never by a table node.
    assert result.indicator == "noSuchObject" and result.request_count == 2


# --- Failures (RF-06) -------------------------------------------------------


async def test_silent_agent_is_no_response(make_client: ClientFactory) -> None:
    async with ScriptedAgent(if_rows(5), behaviour=Behaviour(stop_after=0)) as agent:
        result = await make_client(FAST).walk_table(target(agent), IF_TABLE)
    assert (result.outcome, result.error_category, result.complete) == ("no_response", None, False)


async def test_timeout_mid_walk_is_partial(make_client: ClientFactory) -> None:
    limits = SnmpLimits(timeout=0.3, retries=0, max_repetitions=5)
    async with ScriptedAgent(if_rows(40, columns=(2,)), behaviour=Behaviour(stop_after=2)) as agent:
        result = await make_client(limits).walk_table(target(agent), IF_TABLE)
    assert (result.outcome, result.error_category, result.complete) == ("partial", "timeout", False)
    assert result.row_count == 10  # two responses of five rows each were kept


@pytest.mark.parametrize(("after", "outcome"), [(1, "partial"), (0, "error")])
async def test_non_increasing_oids(make_client: ClientFactory, after: int, outcome: str) -> None:
    async with ScriptedAgent(
        if_rows(30, columns=(2,)), behaviour=Behaviour(non_increasing_after=after)
    ) as agent:
        result = await make_client(FAST).walk_table(target(agent), IF_TABLE)
    assert (result.outcome, result.error_category, result.complete) == (
        outcome,
        "non_increasing_oid",
        False,
    )
    assert (result.row_count > 0) is (outcome == "partial")


@pytest.mark.parametrize("status", ["genErr", "authorizationError"])
async def test_error_status(make_client: ClientFactory, status: str) -> None:
    async with ScriptedAgent(if_rows(3), behaviour=Behaviour(error_status=status)) as agent:
        result = await make_client(FAST).walk_table(target(agent), IF_TABLE)
    assert (result.outcome, result.error_category) == ("error", f"error_status:{status}")


async def test_error_status_after_rows_is_partial(make_client: ClientFactory) -> None:
    limits = SnmpLimits(timeout=0.3, retries=0, max_repetitions=5)
    async with ScriptedAgent(
        if_rows(30, columns=(2,)), behaviour=Behaviour(error_status="genErr", error_after=1)
    ) as agent:
        result = await make_client(limits).walk_table(target(agent), IF_TABLE)
    assert (result.outcome, result.error_category, result.row_count) == (
        "partial",
        "error_status:genErr",
        5,
    )


async def test_garbage_datagram_does_not_stop_the_process(make_client: ClientFactory) -> None:
    client = make_client(FAST)
    async with ScriptedAgent(if_rows(3), behaviour=Behaviour(garbage=True)) as agent:
        result = await client.walk_table(target(agent), IF_TABLE)
        assert result.outcome in ("error", "no_response")
        agent.behaviour = Behaviour()
        again = await client.walk_table(target(agent), IF_TABLE)
    assert again.outcome == "ok"


async def test_row_limit_is_partial(make_client: ClientFactory) -> None:
    limits = SnmpLimits(timeout=0.3, retries=0, max_repetitions=10, max_rows=5)
    async with ScriptedAgent(if_rows(20)) as agent:
        result = await make_client(limits).walk_table(target(agent), IF_TABLE)
    assert (result.outcome, result.error_category, result.row_count) == ("partial", "row_limit", 5)


async def test_get_outcomes(make_client: ClientFactory) -> None:
    data = if_rows(2)
    async with ScriptedAgent(data) as agent:
        client = make_client(FAST)
        result = await client.get(
            target(agent),
            [parse_oid("1.3.6.1.2.1.2.2.1.2.1"), ENTITY.column_oid("entPhysicalDescr")],
        )
        assert result.outcome == "ok"
        assert result.values == {parse_oid("1.3.6.1.2.1.2.2.1.2.1"): b"port1"}
        assert result.indicators == {ENTITY.column_oid("entPhysicalDescr"): "noSuchObject"}
        agent.behaviour = Behaviour(stop_after=0)
        assert (
            await client.get(target(agent), [parse_oid("1.3.6.1.2.1.2.2.1.2.1")])
        ).outcome == "no_response"


# --- Load (RNF-06) ----------------------------------------------------------


async def test_one_request_in_flight_per_device(make_client: ClientFactory) -> None:
    client = make_client(SnmpLimits(timeout=2, retries=0, max_repetitions=5))
    async with ScriptedAgent(if_rows(12, columns=(2,)), behaviour=Behaviour(delay=0.02)) as agent:
        results = await asyncio.gather(
            *(client.walk_table(target(agent), IF_TABLE) for _ in range(4))
        )
    assert {r.outcome for r in results} == {"ok"}
    assert agent.max_in_flight == 1 and agent.requests >= 4 * 3


async def test_devices_are_queried_in_parallel_up_to_the_limit(make_client: ClientFactory) -> None:
    client = make_client(SnmpLimits(timeout=2, retries=0, max_repetitions=50, max_devices=2))
    agents = [
        ScriptedAgent(if_rows(2, columns=(2,)), behaviour=Behaviour(delay=0.15)) for _ in range(4)
    ]
    for agent in agents:
        await agent.start()
    peak = 0

    async def sample() -> None:
        nonlocal peak
        while True:
            peak = max(peak, sum(1 for a in agents if a.in_flight))
            await asyncio.sleep(0.005)

    sampler = asyncio.create_task(sample())
    try:
        results = await asyncio.gather(*(client.walk_table(target(a), IF_TABLE) for a in agents))
    finally:
        sampler.cancel()
        for agent in agents:
            agent.close()
    assert {r.outcome for r in results} == {"ok"}
    assert peak == 2  # never more devices at once than the limit


# --- Results contract (store semantics) -------------------------------------


async def test_column_missing_in_a_complete_walk_is_absent(make_client: ClientFactory) -> None:
    data = if_rows(3, columns=(1, 2, 8))
    del data[parse_oid("1.3.6.1.2.1.2.2.1.2.2")]  # row 2 has no ifDescr
    async with ScriptedAgent(data) as agent:
        result = await make_client(FAST).walk_table(
            target(agent), IF_TABLE, ["ifIndex", "ifDescr", "ifOperStatus"]
        )
    assert result.complete
    assert result.reported((2,)) == {"ifIndex": 2, "ifDescr": None, "ifOperStatus": 1}


async def test_column_not_reached_in_a_partial_walk_is_not_reported(
    make_client: ClientFactory,
) -> None:
    limits = SnmpLimits(timeout=0.3, retries=0, max_repetitions=10)
    async with ScriptedAgent(
        if_rows(10, columns=(1, 2, 8)), behaviour=Behaviour(stop_after=2)
    ) as agent:
        result = await make_client(limits).walk_table(target(agent), IF_TABLE)
    assert not result.complete and result.outcome == "partial"
    for index in result.rows:
        assert "ifOperStatus" not in result.reported(index)
    assert result.reported((1,)) == {"ifIndex": 1, "ifDescr": b"port1"}


# --- Against the snmpsim lab (design D10) -----------------------------------


def lab_target(lab: SnmpLab, device: str) -> Target:
    return Target(lab.host, SnmpV2cCredential(community=device), port=lab.port)


def rows_in_data(device: str, table_oid: str) -> int:
    prefix = table_oid + "."
    n = len(table_oid.split("."))
    indexes = set()
    for line in (LAB_DATA / f"{device}.snmprec").read_text(encoding="utf-8").splitlines():
        oid = line.split("|", 1)[0]
        if oid.startswith(prefix):
            indexes.add(tuple(oid.split(".")[n + 1 :]))
    return len(indexes)


LAB = SnmpLimits(timeout=2, retries=1)


@pytest.mark.lab
@pytest.mark.parametrize(
    "mib_object",
    [
        "IF-MIB::ifTable",
        "IF-MIB::ifXTable",
        "IP-MIB::ipAddrTable",
        "IP-MIB::ipAddressTable",
        "IP-MIB::ipNetToMediaTable",
        "IP-MIB::ipNetToPhysicalTable",
    ],
)
async def test_srx01_tables_ok_with_row_counts(
    make_client: ClientFactory, snmp_lab: SnmpLab, mib_object: str
) -> None:
    spec = get_table(mib_object)
    result = await make_client(LAB).walk_table(lab_target(snmp_lab, "srx-01"), spec)
    assert (result.outcome, result.complete) == ("ok", True)
    assert result.row_count == rows_in_data("srx-01", ".".join(map(str, spec.oid)))


@pytest.mark.lab
async def test_lab_supported_but_empty_table(make_client: ClientFactory, snmp_lab: SnmpLab) -> None:
    result = await make_client(LAB).walk_table(lab_target(snmp_lab, "srx-01"), LLDP_REM)
    assert (result.outcome, result.indicator, result.row_count) == ("empty", "noSuchInstance", 0)


@pytest.mark.lab
async def test_lab_snmpv3_authpriv(make_client: ClientFactory, snmp_lab: SnmpLab) -> None:
    credential = SnmpV3Credential(
        user=snmp_lab.v3_user,
        level="authPriv",
        auth_protocol="SHA-256",
        auth_key=snmp_lab.v3_auth_key,
        priv_protocol="AES-128",
        priv_key=snmp_lab.v3_priv_key,
    )
    lab_v3 = Target(snmp_lab.host, credential, port=snmp_lab.port, context="lab-sw-01")
    result = await make_client(LAB).walk_table(lab_v3, get_table("SNMPv2-MIB::system"))
    assert result.outcome == "ok" and result.rows[(0,)]["sysName"] == b"lab-sw-01"


@pytest.mark.lab
async def test_lab_columns_only_walk(make_client: ClientFactory, snmp_lab: SnmpLab) -> None:
    result = await make_client(LAB).walk_table(
        lab_target(snmp_lab, "srx-01"), get_table("IF-MIB::ifXTable"), ["ifName", "ifHighSpeed"]
    )
    assert result.outcome == "ok" and result.row_count == 259
    assert {c for row in result.rows.values() for c in row} == {"ifName", "ifHighSpeed"}


@pytest.mark.lab
async def test_lab_row_limit(make_client: ClientFactory, snmp_lab: SnmpLab) -> None:
    limits = SnmpLimits(timeout=2, retries=1, max_rows=100)
    result = await make_client(limits).walk_table(lab_target(snmp_lab, "srx-01"), IF_TABLE)
    assert (result.outcome, result.error_category, result.row_count) == (
        "partial",
        "row_limit",
        100,
    )


@pytest.mark.lab
async def test_lab_switches_answer(make_client: ClientFactory, snmp_lab: SnmpLab) -> None:
    client = make_client(LAB)
    sw1 = await client.walk_table(
        lab_target(snmp_lab, "lab-sw-01"), get_table("Q-BRIDGE-MIB::dot1qTpFdbTable")
    )
    assert sw1.outcome == "ok" and sw1.row_count == rows_in_data(
        "lab-sw-01", "1.3.6.1.2.1.17.7.1.2.2.1"
    )
    no_x = await client.walk_table(lab_target(snmp_lab, "lab-sw-02"), get_table("IF-MIB::ifXTable"))
    assert (no_x.outcome, no_x.indicator) == (
        "empty",
        "noSuchInstance",
    )  # snmpsim cannot say noSuchObject
