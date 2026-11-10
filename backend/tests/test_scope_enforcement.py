# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Scope enforcement below the SNMP client (snmp-scope spec, design D2, D3).

A test transport mapping (``endpoint_for``) sends lab addresses to scripted
agents on loopback ports. The scope is always checked on the logical address.
"""

from __future__ import annotations

import logging
import secrets

import pytest
from pysnmp.proto import rfc1902

from netscanner.credential_store import CredentialUnreadable
from netscanner.scope import Rejection, ScopePolicy
from netscanner.snmp import ScopeViolation, SnmpLimits, SnmpV2cCredential, get_table
from netscanner.snmp.pysnmp_client import PySnmpClient
from netscanner.snmp.tables import parse_oid

from .snmp_agent import Behaviour, ScriptedAgent, table
from .snmp_targets import RESOLVER, StaticResolver, authorized

LAB = ("10.99.0.0/24",)
IF_TABLE = get_table("IF-MIB::ifTable")
LLDP_REM = get_table("LLDP-MIB::lldpRemTable")
SILENT = SnmpLimits(timeout=0.2, retries=2, max_repetitions=10)
DATA = table("1.3.6.1.2.1.2.2.1", {2: [rfc1902.OctetString("port")] * 3})


def mapping_to(agent: ScriptedAgent, seen: list[tuple[str, int]]):
    def endpoint_for(address: str, port: int) -> tuple[str, int]:
        seen.append((address, port))
        return agent.host, agent.port

    return endpoint_for


async def test_retries_and_probe_go_to_the_same_address(monkeypatch: pytest.MonkeyPatch) -> None:
    checked: list[str] = []
    original = ScopePolicy.contains

    def spy(self: ScopePolicy, address: object) -> bool:
        checked.append(str(address))
        return original(self, address)

    monkeypatch.setattr(ScopePolicy, "contains", spy)
    seen: list[tuple[str, int]] = []
    lldp_columns = {LLDP_REM.column_oid(c) for c in LLDP_REM.columns}
    # The first request is lost and retried, then the empty walk is probed.
    async with ScriptedAgent(
        DATA, object_types=lldp_columns, behaviour=Behaviour(ignore_first=1)
    ) as agent:
        target = authorized("10.99.0.50", 161, agent.community, allowed=LAB)
        client = PySnmpClient(RESOLVER, SnmpLimits(timeout=0.3, retries=1), mapping_to(agent, seen))
        result = await client.walk_table(target, LLDP_REM)
    assert (result.outcome, result.request_count, agent.requests) == ("empty", 3, 3)
    # One device session, one mapping of the logical address, and the scope
    # checked on that address before each of the three datagrams.
    assert seen == [("10.99.0.50", 161)]
    assert checked == ["10.99.0.50"] * 3


async def test_silent_agent_retries_to_the_same_endpoint() -> None:
    seen: list[tuple[str, int]] = []
    async with ScriptedAgent(DATA, behaviour=Behaviour(stop_after=0)) as agent:
        target = authorized("10.99.0.51", 161, agent.community, allowed=LAB)
        result = await PySnmpClient(RESOLVER, SILENT, mapping_to(agent, seen)).get(
            target, [parse_oid("1.3.6.1.2.1.1.5.0")]
        )
    assert (result.outcome, agent.requests) == ("no_response", 3)
    assert seen == [("10.99.0.51", 161)]


async def test_out_of_scope_address_receives_no_datagram(caplog: pytest.LogCaptureFixture) -> None:
    canary = "canary-community-" + secrets.token_hex(8)
    caplog.set_level(logging.DEBUG)
    policy = ScopePolicy.build(LAB, credential_id=RESOLVER.add(SnmpV2cCredential(community=canary)))
    async with ScriptedAgent(DATA, community=canary) as agent:
        # The policy refuses the address: there is no target to give the client.
        assert policy.authorize("203.0.113.10") == Rejection("out_of_scope")
        # Even with a mapping that would send everything to the agent, the
        # client accepts no other kind of target.
        client = PySnmpClient(RESOLVER, SILENT, lambda a, p: (agent.host, agent.port))
        with pytest.raises(TypeError, match="only targets authorised"):
            await client.get("203.0.113.10", [parse_oid("1.3.6.1.2.1.1.5.0")])  # type: ignore[arg-type]
        assert agent.requests == 0
    assert canary not in caplog.text


async def test_target_outside_its_frozen_policy_is_never_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with ScriptedAgent(DATA) as agent:
        target = authorized("10.99.0.52", 161, agent.community, allowed=LAB)
        client = PySnmpClient(RESOLVER, SILENT, lambda a, p: (agent.host, agent.port))
        # Defence in depth: if the policy no longer contained the address (a
        # bug elsewhere), the adapter refuses before the first datagram.
        monkeypatch.setattr(ScopePolicy, "contains", lambda self, address: False)
        with pytest.raises(ScopeViolation):
            await client.walk_table(target, IF_TABLE)
        assert agent.requests == 0


async def test_unreadable_credential_sends_no_datagram() -> None:
    empty = StaticResolver()  # knows no credential
    async with ScriptedAgent(DATA) as agent:
        target = authorized("10.99.0.53", 161, agent.community, allowed=LAB)
        client = PySnmpClient(empty, SILENT, lambda a, p: (agent.host, agent.port))
        with pytest.raises(CredentialUnreadable):
            await client.walk_table(target, IF_TABLE)
        assert agent.requests == 0
