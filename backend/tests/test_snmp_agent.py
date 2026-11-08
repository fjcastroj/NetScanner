# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""The scripted test agent itself, queried with raw PySNMP calls (not our client)."""

from __future__ import annotations

import asyncio

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_cmd,
    get_cmd,
    next_cmd,
)
from pysnmp.proto import rfc1902, rfc1905

from .snmp_agent import Behaviour, ScriptedAgent, oid, table

IF_TABLE = "1.3.6.1.2.1.2.2.1"
DATA = {
    oid("1.3.6.1.2.1.1.5.0"): rfc1902.OctetString("lab-agent-01"),
    **table(IF_TABLE, {2: [rfc1902.OctetString(f"port{i}") for i in (1, 2, 3)]}),
}


async def _call(agent: ScriptedAgent, kind: str, *oids: str, community: str = "scripted"):
    engine = SnmpEngine()
    try:
        udp = await UdpTransportTarget.create((agent.host, agent.port), timeout=0.5, retries=0)
        auth = CommunityData(community, mpModel=1)  # noqa: S508 - SNMPv2c agent under test
        objects = [ObjectType(ObjectIdentity(o)) for o in oids]
        if kind == "get":
            return await get_cmd(engine, auth, udp, ContextData(), *objects, lookupMib=False)
        if kind == "next":
            return await next_cmd(engine, auth, udp, ContextData(), *objects, lookupMib=False)
        return await bulk_cmd(engine, auth, udp, ContextData(), 0, 10, *objects, lookupMib=False)
    finally:
        engine.close_dispatcher()


async def test_get_values_and_exceptions() -> None:
    async with ScriptedAgent(DATA) as agent:
        _, status, _, vbs = await _call(
            agent,
            "get",
            "1.3.6.1.2.1.1.5.0",
            f"{IF_TABLE}.2.9",
            f"{IF_TABLE}.2",
            "1.3.6.1.2.1.47.1.1.1.1.13",
        )
    assert int(status) == 0
    assert str(vbs[0][1]) == "lab-agent-01"
    # Unknown instance of a known object type, column without index, unknown object type.
    assert isinstance(vbs[1][1], rfc1905.NoSuchInstance)
    assert isinstance(vbs[2][1], rfc1905.NoSuchInstance)
    assert isinstance(vbs[3][1], rfc1905.NoSuchObject)


async def test_getnext_and_getbulk_walk_in_order() -> None:
    async with ScriptedAgent(DATA) as agent:
        _, _, _, vbs = await _call(agent, "next", IF_TABLE)
        assert tuple(vbs[0][0]) == oid(f"{IF_TABLE}.2.1")
        _, _, _, vbs = await _call(agent, "bulk", f"{IF_TABLE}.2.1")
    names = [tuple(vb[0]) for vb in vbs]
    assert names[:2] == [oid(f"{IF_TABLE}.2.2"), oid(f"{IF_TABLE}.2.3")]
    assert isinstance(vbs[-1][1], rfc1905.EndOfMibView)


async def test_wrong_community_gets_silence() -> None:
    async with ScriptedAgent(DATA) as agent:
        indication, *_ = await _call(agent, "get", "1.3.6.1.2.1.1.5.0", community="other")
    assert "timeout" in str(indication).lower()


async def test_stop_after_n_responses() -> None:
    async with ScriptedAgent(DATA, behaviour=Behaviour(stop_after=1)) as agent:
        first, *_ = await _call(agent, "get", "1.3.6.1.2.1.1.5.0")
        second, *_ = await _call(agent, "get", "1.3.6.1.2.1.1.5.0")
    assert first is None and second is not None


async def test_error_status_after_n_responses() -> None:
    async with ScriptedAgent(
        DATA, behaviour=Behaviour(error_status="genErr", error_after=1)
    ) as agent:
        _, ok, *_ = await _call(agent, "get", "1.3.6.1.2.1.1.5.0")
        _, status, *_ = await _call(agent, "get", "1.3.6.1.2.1.1.5.0")
    assert int(ok) == 0 and status.prettyPrint() == "genErr"


async def test_non_increasing_oids() -> None:
    async with ScriptedAgent(DATA, behaviour=Behaviour(non_increasing_after=0)) as agent:
        _, _, _, vbs = await _call(agent, "bulk", f"{IF_TABLE}.2.1")
    assert tuple(vbs[0][0]) == oid(f"{IF_TABLE}.2.1")


async def test_garbage_datagram() -> None:
    async with ScriptedAgent(DATA, behaviour=Behaviour(garbage=True)) as agent:
        indication, *_ = await _call(agent, "get", "1.3.6.1.2.1.1.5.0")
    assert indication is not None  # the client gets no valid answer


async def test_delay_and_in_flight_count() -> None:
    async with ScriptedAgent(DATA, behaviour=Behaviour(delay=0.1)) as agent:
        await asyncio.gather(*(_call(agent, "get", "1.3.6.1.2.1.1.5.0") for _ in range(3)))
    assert agent.requests == 3 and agent.max_in_flight == 3
