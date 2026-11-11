# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Discovery runs against scripted agents (tasks 3.2, 5.5, 5.7).

Each scripted agent stands behind a lab address through the test mapping
(design D3, D4). Every run goes through the real path: encrypted credential,
pending run, claim, the runner's checks, the engine, ``PySnmpClient`` and
``CredentialResolver``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets

import pytest
from pysnmp.proto import rfc1902
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.config import Settings
from netscanner.core.logging_setup import configure_logging
from netscanner.credential_store import CredentialService
from netscanner.scope import DiscoveryCeilings
from netscanner.snmp.walker import SnmpLimits
from netscanner.store.runs import RunLimits, RunParameters
from netscanner.store.service import Store

from .conftest import Canaries, DiscoveryLab, SnmpLab, all_rows_text
from .discovery_run import Network, claim_and_run, create_run, discover, save_credential
from .snmp_agent import Behaviour, ScriptedAgent, oid, table

pytestmark = pytest.mark.db

A, B, C, SILENT = "10.99.0.21", "10.99.0.22", "10.99.0.23", "10.99.0.9"
COMMUNITY = "scripted-" + secrets.token_hex(4)
FAST = SnmpLimits(timeout=0.3, retries=0)

CDP_CACHE = "1.3.6.1.4.1.9.9.23.1.2.1.1"


def device(
    name: str, descr: str = "Scripted switch model SW-100 version 2.1", interfaces: int = 2
) -> dict:
    """A small device: system group and ifTable; every other table is not implemented."""
    data: dict = {
        oid("1.3.6.1.2.1.1.1.0"): rfc1902.OctetString(descr),
        oid("1.3.6.1.2.1.1.2.0"): rfc1902.ObjectIdentifier("1.3.6.1.4.1.99999.1"),
        oid("1.3.6.1.2.1.1.3.0"): rfc1902.TimeTicks(12345),
        oid("1.3.6.1.2.1.1.5.0"): rfc1902.OctetString(name),
    }
    n = range(1, interfaces + 1)
    data.update(
        table(
            "1.3.6.1.2.1.2.2.1",
            {
                1: [rfc1902.Integer32(i) for i in n],
                2: [rfc1902.OctetString(f"port{i}") for i in n],
                3: [rfc1902.Integer32(6) for _ in n],
                7: [rfc1902.Integer32(1) for _ in n],
                8: [rfc1902.Integer32(1) for _ in n],
            },
        )
    )
    return data


def cdp_neighbour(if_index: int, device_index: int, address: str, name: str) -> dict:
    def entry(column: int) -> tuple[int, ...]:
        return (*oid(CDP_CACHE), column, if_index, device_index)

    return {
        entry(3): rfc1902.Integer32(1),
        entry(4): rfc1902.OctetString(bytes(int(p) for p in address.split("."))),
        entry(6): rfc1902.OctetString(name),
        entry(7): rfc1902.OctetString("Gi0/1"),
    }


def credential(community: str = COMMUNITY) -> dict:
    return {"version": "2c", "community": community}


async def rows(engine: AsyncEngine, sql: str, **params: object) -> list[dict]:
    async with engine.connect() as conn:
        return [dict(r) for r in (await conn.execute(text(sql), params)).mappings()]


@pytest.fixture
def secret_key(store_settings: Settings) -> str:
    return store_settings.secret_key.get_secret_value()


@pytest.fixture
async def silent() -> ScriptedAgent:
    agent = ScriptedAgent({}, community=COMMUNITY, behaviour=Behaviour(stop_after=0))
    async with agent:
        yield agent


def agent(data: dict, behaviour: Behaviour | None = None) -> ScriptedAgent:
    return ScriptedAgent(data, community=COMMUNITY, behaviour=behaviour or Behaviour())


# --- 5.5: scripted agents -----------------------------------------------------


async def test_entity_mib_not_implemented_gives_sysdescr_inference(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    async with agent(device("sw-a")) as a:
        network = Network({A: a.port}, default=silent.port)
        run = await discover(
            engine, secret_key, network, credential=credential(), seeds=[A], snmp_limits=FAST
        )
    assert run.status == "completed"
    queries = {q["mib_object"]: q for q in await run.queries()}
    entity = queries["ENTITY-MIB::entPhysicalTable"]
    assert (entity["outcome"], entity["indicator"]) == ("not_available", "noSuchObject")
    # Discovery of that device continued after it.
    assert queries["IP-MIB::ipNetToMediaTable"]["outcome"] == "not_available"
    found = (await run.by_address())[A]
    [dev] = await rows(
        engine, "SELECT model, software_version, model_origin FROM devices WHERE id = :d",
        d=found["device_id"],
    )  # fmt: skip
    assert dev == {"model": "SW-100", "software_version": "2.1", "model_origin": "inferred"}


async def test_cdp_neighbour_becomes_candidate(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    data = device("sw-a") | cdp_neighbour(1, 7, B, "sw-b") | cdp_neighbour(2, 8, "192.0.2.5", "x")
    async with agent(data) as a, agent(device("sw-b")) as b:
        network = Network({A: a.port, B: b.port}, default=silent.port)
        run = await discover(
            engine, secret_key, network, credential=credential(), seeds=[A], snmp_limits=FAST
        )
    assert run.status == "completed"
    found = await run.by_address()
    assert found[B]["reached_via"] == "cdp" and found[B]["depth"] == 1
    assert found[B]["device_id"] and found[B]["found_from_device_id"] == found[A]["device_id"]
    assert found["192.0.2.5"]["skip_reason"] == "out_of_scope"
    cache = await rows(
        engine,
        "SELECT remote_sys_name, remote_port_id, local_port_num FROM neighbor_entries"
        " WHERE device_id = :d AND protocol = 'cdp' ORDER BY local_port_num",
        d=found[A]["device_id"],
    )
    assert cache[0] == {"remote_sys_name": "sw-b", "remote_port_id": "Gi0/1", "local_port_num": 1}


async def test_device_stopping_mid_run_gives_partial_and_run_continues(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    # ifTable of 300 rows needs many requests: the agent goes silent in the middle.
    stopping = agent(device("sw-a", interfaces=300), Behaviour(stop_after=12))
    async with stopping as a, agent(device("sw-c")) as c:
        network = Network({A: a.port, C: c.port}, default=silent.port)
        run = await discover(
            engine, secret_key, network, credential=credential(), seeds=[A, C], snmp_limits=FAST
        )
    assert run.status == "completed"
    queries = await run.queries()
    mine = [q for q in queries if q["target_address"] == A]
    if_table = next(q for q in mine if q["mib_object"] == "IF-MIB::ifTable")
    assert (if_table["outcome"], if_table["error_category"]) == ("partial", "timeout")
    assert 0 < if_table["row_count"] < 300
    after = mine[mine.index(if_table) + 1 :]
    assert after and all(q["outcome"] == "no_response" for q in after)
    found = await run.by_address()
    assert found[A]["device_id"] and found[C]["device_id"]  # the run went on with the other
    [count] = await rows(
        engine, "SELECT count(*) AS n FROM interfaces WHERE device_id = :d", d=found[A]["device_id"]
    )
    assert count["n"] == if_table["row_count"]


async def test_error_status_on_system_group_gives_query_error(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    failing = agent(device("sw-a"), Behaviour(error_status="genErr"))
    async with failing as a, agent(device("sw-c")) as c:
        network = Network({A: a.port, C: c.port}, default=silent.port)
        run = await discover(
            engine, secret_key, network, credential=credential(), seeds=[A, C], snmp_limits=FAST
        )
    assert run.status == "completed"
    found = await run.by_address()
    assert found[A]["skip_reason"] == "query_error" and found[A]["device_id"] is None
    [system] = [q for q in await run.queries() if q["target_address"] == A]
    assert (system["outcome"], system["error_category"]) == ("error", "error_status:genErr")
    assert found[C]["device_id"]


async def test_device_error_lists_address_stage_and_class_only(
    engine: AsyncEngine,
    secret_key: str,
    silent: ScriptedAgent,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # An exception after the system group answered, whose message and arguments
    # carry a canary (as a value read from the device could).
    canary = "device-canary-" + secrets.token_hex(8)

    def failing_rows(result: object) -> list[dict]:
        raise LookupError(f"unexpected row {canary}", canary)

    from netscanner.discovery import mapping

    monkeypatch.setattr(mapping, "if_table_rows", failing_rows)
    caplog.set_level(logging.DEBUG)
    async with agent(device("sw-a")) as a, agent(device("sw-c")) as c:
        network = Network({A: a.port, C: c.port}, default=silent.port)
        run = await discover(
            engine, secret_key, network, credential=credential(), seeds=[A, C], snmp_limits=FAST
        )
    assert run.status == "completed"
    record = await run.run()
    errors = sorted(record["summary"]["device_errors"], key=lambda e: e["target_address"])
    assert errors == [
        {"target_address": A, "stage": "IF-MIB::ifTable", "exception": "LookupError"},
        {"target_address": C, "stage": "IF-MIB::ifTable", "exception": "LookupError"},
    ]
    found = await run.by_address()
    assert found[A]["device_id"] and found[C]["device_id"]  # each keeps what was stored
    for output in (
        caplog.text, capsys.readouterr().err, json.dumps(record["summary"]),
        json.dumps(await run.report(), default=str), await all_rows_text(engine),
    ):  # fmt: skip
        assert canary not in output
        assert "Traceback" not in output


@pytest.mark.lab
async def test_snmpv3_report_gives_auth_failed_for_that_device_only(
    engine: AsyncEngine,
    secret_key: str,
    silent: ScriptedAgent,
    discovery_lab: DiscoveryLab,
    snmp_lab: SnmpLab,
) -> None:
    # The scripted agent speaks SNMPv2c only: the SNMPv3 report comes from snmpsim.
    # 10.99.0.3 is served by the other lab process, whose user has different keys.
    v3 = {
        "version": "3", "user": discovery_lab.v3_user, "level": "authPriv",
        "auth_protocol": "SHA-256", "auth_key": discovery_lab.v3_auth_key,
        "priv_protocol": "AES-128", "priv_key": discovery_lab.v3_priv_key,
    }  # fmt: skip
    ports = {"10.99.0.2": discovery_lab.ports["10.99.0.2"], "10.99.0.3": snmp_lab.port}
    network = Network(ports, default=silent.port)
    run = await discover(
        engine, secret_key, network, credential=v3, seeds=["10.99.0.2"], max_depth=1,
        v3_context=discovery_lab.community, snmp_limits=SnmpLimits(timeout=2, retries=0),
    )  # fmt: skip
    assert run.status == "completed"
    found = await run.by_address()
    assert found["10.99.0.2"]["device_id"]
    assert found["10.99.0.3"]["skip_reason"] == "auth_failed"
    [system] = [q for q in await run.queries() if q["target_address"] == "10.99.0.3"]
    assert system["outcome"] == "error" and system["error_category"].startswith("v3_report:")
    assert system["snmp_version"] == "3"
    summary = (await run.run())["summary"]
    # SNMPv3: one engine-discovery datagram per call on top of the reported ones.
    calls = len(await run.queries())
    assert summary["budget_consumed"] == summary["reported_datagrams"] + calls


# --- Run start checks (D6, D7) and task 3.2 ---------------------------------------


async def test_empty_scope_fails_before_any_datagram(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    async with agent(device("sw-a")) as a:
        network = Network({A: a.port}, default=silent.port)
        run = await discover(
            engine, secret_key, network, credential=credential(), seeds=[A], allowed=[]
        )
        assert a.requests == 0
    record = await run.run()
    assert (record["status"], record["error_category"]) == ("failed", "empty_scope")
    assert await run.devices() == [] and await run.queries() == []


async def test_real_looking_range_runs_without_the_lab_guard(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    # add-admin-authentication D9: the lab-only guard is gone; every other rule stays.
    advertising = device("sw-a") | cdp_neighbour(1, 7, "192.0.2.20", "sw-x")
    async with agent(advertising) as a, agent(device("sw-x")) as outside:
        network = Network({"192.0.2.10": a.port, "192.0.2.20": outside.port}, default=silent.port)
        run = await discover(
            engine, secret_key, network, credential=credential(), seeds=["192.0.2.10"],
            allowed=["192.0.2.0/24"], exclusions=["192.0.2.20/32"], snmp_limits=FAST,
        )  # fmt: skip
        assert a.requests > 0 and outside.requests == 0
    assert run.status == "completed"
    found = await run.by_address()
    assert found["192.0.2.10"]["device_id"]
    assert found["192.0.2.20"]["skip_reason"] == "excluded"


async def test_limits_above_ceiling_at_run_start_fail_before_any_datagram(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    # The stored limits were valid when the run was created; the ceiling is lower now.
    lowered = DiscoveryCeilings(
        max_depth=5, max_candidates=4096, max_devices=256, max_datagrams=100
    )
    async with agent(device("sw-a")) as a:
        network = Network({A: a.port}, default=silent.port)
        run = await discover(
            engine, secret_key, network, credential=credential(), seeds=[A], ceilings=lowered,
            limits=RunLimits(max_candidates=4096, max_devices=256, max_datagrams=50000),
        )  # fmt: skip
        assert a.requests == 0
    record = await run.run()
    assert (record["status"], record["error_category"]) == ("failed", "limits_not_allowed")
    assert await run.queries() == []


async def test_run_without_frozen_limits_fails_before_any_datagram(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    # Not created by the API (it always freezes limits): no server ceiling is used instead.
    store = Store(engine)
    credential_id = await save_credential(engine, secret_key, credential())
    params = RunParameters(
        seeds=[A], allowed_ranges=["10.99.0.0/24"], max_depth=1,  # type: ignore[list-item]
        credential_id=credential_id,
    )  # fmt: skip
    assert params.limits is None
    created = await store.create_run("discovery", params)
    async with agent(device("sw-a")) as a:
        network = Network({A: a.port}, default=silent.port)
        run = await claim_and_run(engine, secret_key, network, created)
        assert a.requests == silent.requests == 0
    record = await run.run()
    assert (record["status"], record["error_category"]) == ("failed", "limits_not_allowed")
    assert await run.devices() == [] and await run.queries() == []


@pytest.mark.parametrize("damage", ["key_mismatch", "corrupted_ciphertext"])
async def test_unreadable_credential_fails_run_before_any_datagram(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent, damage: str
) -> None:
    store = Store(engine)
    credential_id = await save_credential(engine, secret_key, credential())
    async with engine.begin() as conn:
        if damage == "key_mismatch":
            # Stored under another secret key: detected by key identifier, nothing decrypted.
            await conn.execute(text("UPDATE snmp_credentials SET key_id = :k"), {"k": "0" * 32})
        else:
            # Same key identifier, ciphertext damaged: detected when decrypting.
            await conn.execute(text("UPDATE snmp_credentials SET secret = :s"), {"s": b"damaged"})
    async with agent(device("sw-a")) as a, agent(device("sw-b")) as b:
        network = Network({A: a.port, B: b.port}, default=silent.port)
        created = await create_run(store, seeds=[A, B], credential_id=credential_id)
        run = await claim_and_run(engine, secret_key, network, created)
        assert a.requests == b.requests == silent.requests == 0
    record = await run.run()
    assert (record["status"], record["error_category"]) == ("failed", "credential_unreadable")
    assert await run.queries() == []


async def test_credential_replaced_during_run_keeps_the_runs_credential(
    engine: AsyncEngine, secret_key: str, silent: ScriptedAgent
) -> None:
    # The agent answers the old community only, slowly enough to replace it mid-run.
    async with agent(device("sw-a", interfaces=40), Behaviour(delay=0.05)) as a:
        network = Network({A: a.port}, default=silent.port)
        store = Store(engine)
        old_id = await save_credential(engine, secret_key, credential())
        created = await create_run(store, seeds=[A], credential_id=old_id)
        running = asyncio.create_task(claim_and_run(engine, secret_key, network, created))
        while a.responses < 3:  # noqa: ASYNC110 - polls the agent's counter
            await asyncio.sleep(0.02)
        new_id = await CredentialService(engine, secret_key).save(credential("replacement-x9"))
        # Inactive but used by the running run: kept until the run ends.
        ids = await rows(engine, "SELECT id, active FROM snmp_credentials ORDER BY id")
        assert ids == [{"id": old_id, "active": False}, {"id": new_id, "active": True}]
        run = await running
    assert run.status == "completed"
    found = (await run.by_address())[A]
    assert found["device_id"]
    queries = await run.queries()
    assert all(q["outcome"] != "no_response" for q in queries)  # the old community kept working
    # At the end of the run the replaced credential is deleted.
    ids = await rows(engine, "SELECT id, active FROM snmp_credentials ORDER BY id")
    assert ids == [{"id": new_id, "active": True}]


# --- 5.7: canary over a whole run -----------------------------------------------


async def test_canary_credentials_never_leave_a_whole_run(
    engine: AsyncEngine,
    store_settings: Settings,
    secret_key: str,
    canaries: Canaries,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    community = "canary-" + secrets.token_hex(12)
    configure_logging("DEBUG", [*store_settings.secret_values(), *canaries.all()])
    caplog.set_level(logging.DEBUG)
    good = ScriptedAgent(device("sw-a"), community=community)
    failing = ScriptedAgent(
        device("sw-b"), community=community, behaviour=Behaviour(error_status="genErr")
    )
    quiet = ScriptedAgent({}, community=community, behaviour=Behaviour(stop_after=0))
    stopping = ScriptedAgent(
        device("sw-c", interfaces=300), community=community, behaviour=Behaviour(stop_after=12)
    )
    async with good as a, failing as b, quiet as q, stopping as c:
        network = Network({A: a.port, B: b.port, C: c.port}, default=q.port)
        run = await discover(
            engine, secret_key, network, credential=credential(community),
            seeds=[A, B, C, SILENT], snmp_limits=FAST, snapshot=True,
        )  # fmt: skip
    assert run.status == "completed"
    outcomes = {q["outcome"] for q in await run.queries()}
    assert {"ok", "error", "no_response", "partial"} <= outcomes  # timeouts and errors included
    record = await run.run()
    texts = [
        capsys.readouterr().err,
        caplog.text,
        json.dumps(record["parameters"]),
        json.dumps(record["summary"]),
        json.dumps(await run.queries(), default=str),
        json.dumps(await run.report(), default=str),
        json.dumps(await run.store.get_snapshot(run.run_id), default=str),
        await all_rows_text(engine),
    ]
    for output in texts:
        assert community not in output
        canaries.assert_absent(output)
        assert secret_key not in output


# --- 5.4: collector loop -------------------------------------------------------


async def test_claim_skips_a_run_locked_by_another_collector(engine: AsyncEngine) -> None:
    store = Store(engine)
    run_id = await create_run(store, seeds=[A], credential_id=None)
    async with engine.connect() as other:
        async with other.begin():
            # Another collector holds the run's row (it is claiming it).
            await other.execute(
                text("SELECT id FROM collection_runs WHERE id = :r FOR UPDATE"), {"r": run_id}
            )
            assert await store.claim_pending_run() is None
    assert await store.claim_pending_run() == run_id
    assert (await rows(engine, "SELECT status FROM collection_runs"))[0]["status"] == "running"
    assert await store.claim_pending_run() is None  # nothing pending any more


async def test_collector_marks_interrupted_runs_then_runs_the_next(
    engine: AsyncEngine,
    store_settings: Settings,
    secret_key: str,
    silent: ScriptedAgent,
    canaries: Canaries,
) -> None:
    from netscanner.collector.service import run_collector
    from netscanner.core.db import create_engine

    from .discovery_run import lab_client

    store = Store(engine)
    credential_id = await save_credential(engine, secret_key, credential())
    left = await create_run(store, seeds=[A], credential_id=credential_id)
    assert await store.claim_pending_run() == left  # a previous collector died mid-run
    async with agent(device("sw-a")) as a:
        network = Network({A: a.port}, default=silent.port)
        settings = store_settings.model_copy(update={"collector_poll_interval": 0.1})
        collector_engine = create_engine(settings)
        client, _ = lab_client(collector_engine, secret_key, network, snmp_limits=FAST)
        stop = asyncio.Event()
        task = asyncio.create_task(
            run_collector(settings, stop, engine=collector_engine, client=client)
        )
        try:
            for _ in range(100):
                status = await rows(engine, "SELECT id, status FROM collection_runs ORDER BY id")
                if status and status[0]["status"] == "interrupted":
                    break
                await asyncio.sleep(0.05)
            assert status[0] == {"id": left, "status": "interrupted"}
            nxt = await create_run(store, seeds=[A], credential_id=credential_id)
            for _ in range(200):
                status = await rows(engine, "SELECT id, status FROM collection_runs ORDER BY id")
                if status[-1]["status"] in ("completed", "failed"):
                    break
                await asyncio.sleep(0.05)
            assert status[-1] == {"id": nxt, "status": "completed"}
        finally:
            stop.set()
            await asyncio.wait_for(task, timeout=10)
    found = await rows(engine, "SELECT device_id FROM run_devices WHERE run_id = :r", r=nxt)
    assert found[0]["device_id"]
