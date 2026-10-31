# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Collection runs, query outcomes and devices reached (collection-records spec)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store import runs
from netscanner.store.errors import RunStateError, StoreError
from netscanner.store.models import collection_runs, devices, run_devices, snmp_queries
from netscanner.store.service import Store

from .conftest import T0, Canaries, Clock, all_rows_text

pytestmark = pytest.mark.db


def query(run_id: int, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "run_id": run_id,
        "target_address": "10.99.0.11",
        "mib_object": "LLDP-MIB::lldpRemTable",
        "operation": "walk",
        "outcome": "ok",
        "row_count": 3,
        "request_count": 2,
        "started_at": T0,
        "duration_ms": 120,
    }
    values.update(overrides)
    return values


async def run_row(engine: AsyncEngine, run_id: int) -> dict:
    async with engine.connect() as conn:
        row = (
            await conn.execute(select(collection_runs).where(collection_runs.c.id == run_id))
        ).one()
    return dict(row._mapping)


async def query_row(engine: AsyncEngine, query_id: int) -> dict:
    async with engine.connect() as conn:
        row = (await conn.execute(select(snmp_queries).where(snmp_queries.c.id == query_id))).one()
    return dict(row._mapping)


async def new_device(engine: AsyncEngine) -> int:
    async with engine.begin() as conn:
        return await conn.scalar(insert(devices).values().returning(devices.c.id))


# --- Runs -------------------------------------------------------------------


async def test_run_lifecycle(store: Store, engine: AsyncEngine, clock: Clock) -> None:
    run = await store.create_run("discovery", {})
    assert (await run_row(engine, run))["status"] == "pending"
    started = clock.advance(timedelta(seconds=5))
    await store.start_run(run)
    finished = clock.advance(timedelta(minutes=2))
    await store.finish_run(run, summary={"devices": 3})
    row = await run_row(engine, run)
    assert (row["status"], row["requested_at"], row["started_at"], row["finished_at"]) == (
        "completed",
        T0,
        started,
        finished,
    )
    assert row["summary"] == {"devices": 3}


async def test_failed_run_stores_category_only(store: Store, engine: AsyncEngine) -> None:
    run = await store.create_run("polling", {})
    await store.start_run(run)
    await store.finish_run(run, "failed", error_category="database-error")
    row = await run_row(engine, run)
    assert (row["status"], row["error_category"]) == ("failed", "database-error")
    with pytest.raises(StoreError, match="unknown error category"):
        run2 = await store.create_run("polling", {})
        await store.start_run(run2)
        await store.finish_run(run2, "failed", error_category="Traceback (most recent call last)")


async def test_invalid_transitions_rejected(store: Store) -> None:
    run = await store.create_run("discovery", {})
    with pytest.raises(RunStateError, match="is not running"):
        await store.finish_run(run)
    await store.start_run(run)
    with pytest.raises(RunStateError, match="is not pending"):
        await store.start_run(run)


async def test_runs_left_running_are_interrupted(
    store: Store, engine: AsyncEngine, clock: Clock
) -> None:
    left = [await store.create_run("discovery", {}) for _ in range(2)]
    for run in left:
        await store.start_run(run)
    done = await store.create_run("polling", {})
    await store.start_run(done)
    await store.finish_run(done)
    pending = await store.create_run("polling", {})
    detected = clock.advance(timedelta(hours=1))
    assert await store.mark_interrupted_runs() == left
    for run in left:
        row = await run_row(engine, run)
        assert (row["status"], row["finished_at"]) == ("interrupted", detected)
    assert (await run_row(engine, done))["status"] == "completed"
    assert (await run_row(engine, pending))["status"] == "pending"


async def test_parameters_stored_without_secrets(store: Store, engine: AsyncEngine) -> None:
    params = {
        "seeds": ["10.99.0.11"],
        "allowed_ranges": ["10.99.0.0/24"],
        "exclusions": ["10.99.0.128/25"],
        "max_depth": 3,
        "credential_id": 7,
    }
    run = await store.create_run("discovery", params)
    stored = (await run_row(engine, run))["parameters"]
    assert {k: stored[k] for k in params} == params
    assert "community" not in stored


async def test_parameters_with_a_secret_rejected(
    store: Store, engine: AsyncEngine, canaries: Canaries
) -> None:
    with pytest.raises(StoreError) as info:
        await store.create_run(
            "discovery", {"seeds": ["10.99.0.11"], "community": canaries.secret_key}
        )
    assert "community" in str(info.value)
    canaries.assert_absent(str(info.value))
    async with engine.connect() as conn:
        assert await conn.scalar(select(func.count()).select_from(collection_runs)) == 0


# --- Queries ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "complete"),
    [
        ({"outcome": "ok", "row_count": 3}, True),
        ({"outcome": "empty", "row_count": 0, "indicator": "end_of_subtree"}, True),
        ({"outcome": "not_available", "row_count": 0, "indicator": "noSuchObject"}, False),
        ({"outcome": "no_response", "row_count": 0, "request_count": 3}, False),
        ({"outcome": "partial", "row_count": 2, "error_category": "transport-error"}, False),
        ({"outcome": "error", "row_count": 0, "error_category": "snmp-error-status"}, False),
    ],
)
async def test_query_outcome_stored(
    store: Store, engine: AsyncEngine, overrides: dict[str, object], complete: bool
) -> None:
    run = await store.create_run("discovery", {})
    query_id = await store.record_query(query(run, **overrides))
    row = await query_row(engine, query_id)
    for key, value in overrides.items():
        assert row[key] == value
    assert str(row["target_address"]) == "10.99.0.11"
    assert row["mib_object"] == "LLDP-MIB::lldpRemTable"
    assert (row["started_at"], row["duration_ms"]) == (T0, 120)
    async with engine.connect() as conn:
        assert (await runs.get_query(conn, query_id)).complete is complete


async def test_no_response_stored_without_diagnosis(store: Store, engine: AsyncEngine) -> None:
    run = await store.create_run("discovery", {})
    query_id = await store.record_query(query(run, outcome="no_response", row_count=0))
    row = await query_row(engine, query_id)
    assert (row["indicator"], row["error_category"]) == (None, None)
    for diagnosis in ({"indicator": "noSuchObject"}, {"error_category": "transport-error"}):
        with pytest.raises(StoreError):
            await store.record_query(query(run, outcome="no_response", row_count=0, **diagnosis))


@pytest.mark.parametrize(
    "overrides",
    [
        {"outcome": "empty", "row_count": 0},
        {"outcome": "not_available", "row_count": 0},
        {"outcome": "error"},
        {"mib_object": "FAKE-MIB::fakeTable"},
        {"outcome": "unknown"},
        {"target_address": "10.99.0.300"},
    ],
)
async def test_invalid_query_records_rejected(store: Store, overrides: dict[str, object]) -> None:
    run = await store.create_run("discovery", {})
    with pytest.raises(StoreError, match="invalid query record"):
        await store.record_query(query(run, **overrides))


async def test_query_with_rejected_rows_not_complete(store: Store, engine: AsyncEngine) -> None:
    run = await store.create_run("discovery", {})
    query_id = await store.record_query(query(run, mib_object="IF-MIB::ifTable", row_count=100))
    async with engine.begin() as conn:
        info = await runs.add_rejected(conn, query_id, 1)
        again = await runs.add_rejected(conn, query_id, 1)
    assert (info.outcome, info.rejected_count, info.complete) == ("ok", 1, False)
    assert again.rejected_count == 1


async def test_error_with_sensitive_text_stores_only_its_category(
    store: Store, engine: AsyncEngine, canaries: Canaries
) -> None:
    run = await store.create_run("discovery", {})
    exc = RuntimeError(
        f"connect lab-sw-01 community={canaries.secret_key} key={canaries.db_password}"
    )
    query_id = await store.record_query(query(run, outcome="error", row_count=0), error=exc)
    assert (await query_row(engine, query_id))["error_category"] == "internal-error"
    timeout = await store.record_query(
        query(run, outcome="partial", row_count=1), error=TimeoutError(canaries.secret_key)
    )
    assert (await query_row(engine, timeout))["error_category"] == "transport-error"
    canaries.assert_absent(await all_rows_text(engine))


# --- Devices reached --------------------------------------------------------


async def test_device_assigned_to_queries_of_its_address(store: Store, engine: AsyncEngine) -> None:
    run = await store.create_run("discovery", {})
    q1 = await store.record_query(query(run, mib_object="SNMPv2-MIB::system"))
    q2 = await store.record_query(query(run, mib_object="IF-MIB::ifTable"))
    other = await store.record_query(query(run, target_address="10.99.0.12"))
    await store.record_run_device(run, "10.99.0.11", "seed", 0, first_query_id=q1)
    device = await new_device(engine)
    await store.assign_device(run, "10.99.0.11", device)
    assert [(await query_row(engine, q))["device_id"] for q in (q1, q2, other)] == [
        device,
        device,
        None,
    ]
    async with engine.connect() as conn:
        reached = (await conn.execute(select(run_devices))).one()
    assert (reached.device_id, reached.answered, reached.first_query_id) == (device, True, q1)


async def test_second_run_records_every_known_device(store: Store, engine: AsyncEngine) -> None:
    known = [await new_device(engine) for _ in range(10)]
    for _ in range(2):
        run = await store.create_run("rediscovery", {})
        for i, device in enumerate(known):
            await store.record_run_device(
                run,
                f"10.99.0.{11 + i}",
                "seed" if i == 0 else "lldp",
                1,
                answered=True,
                device_id=device,
            )
    async with engine.connect() as conn:
        counts = await conn.execute(
            select(run_devices.c.run_id, func.count())
            .group_by(run_devices.c.run_id)
            .order_by(run_devices.c.run_id)
        )
        assert [count for _, count in counts] == [10, 10]


async def test_candidate_without_answer_recorded(store: Store, engine: AsyncEngine) -> None:
    run = await store.create_run("discovery", {})
    q = await store.record_query(
        query(
            run,
            target_address="10.99.0.40",
            mib_object="SNMPv2-MIB::system",
            outcome="no_response",
            row_count=0,
        )
    )
    await store.record_run_device(run, "10.99.0.40", "ip-mac", 2, first_query_id=q)
    # Reached again through another path: first way, lowest depth and first query kept.
    await store.record_run_device(run, "10.99.0.40", "lldp", 1)
    async with engine.connect() as conn:
        reached = (await conn.execute(select(run_devices))).one()
    assert (
        reached.device_id,
        reached.answered,
        reached.reached_via,
        reached.depth,
        reached.first_query_id,
    ) == (
        None,
        False,
        "ip-mac",
        1,
        q,
    )
