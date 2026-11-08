# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Schema of the provenance model: migration and database constraints (design D1, D4, D7)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import insert, inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.db import create_engine
from netscanner.migrate import alembic_config, upgrade
from netscanner.store.models import collection_runs, devices, interfaces, metadata, snmp_queries

from .conftest import TestDatabase, fresh_database

pytestmark = pytest.mark.db

T0 = datetime(2026, 10, 6, 9, 0, tzinfo=UTC)


async def _tables(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        return set(await conn.run_sync(lambda c: inspect(c).get_table_names()))


def test_migrated_schema_matches_models(test_db: TestDatabase) -> None:
    async def diff(settings) -> list:
        engine = create_engine(settings)
        try:
            async with engine.connect() as conn:
                return await conn.run_sync(
                    lambda c: compare_metadata(
                        MigrationContext.configure(c, opts={"compare_type": True}), metadata
                    )
                )
        finally:
            await engine.dispose()

    with fresh_database(test_db) as settings:
        assert upgrade(settings) == 0
        assert asyncio.run(diff(settings)) == []


def test_upgrade_and_downgrade_run_cleanly(test_db: TestDatabase) -> None:
    async def tables(settings) -> set[str]:
        engine = create_engine(settings)
        try:
            return await _tables(engine)
        finally:
            await engine.dispose()

    with fresh_database(test_db) as settings:
        assert upgrade(settings) == 0
        assert {t.name for t in metadata.sorted_tables} <= asyncio.run(tables(settings))
        command.downgrade(alembic_config(settings), "0001")
        assert asyncio.run(tables(settings)) == {"alembic_version"}
        assert upgrade(settings) == 0
        assert {t.name for t in metadata.sorted_tables} <= asyncio.run(tables(settings))


# --- Constraints ------------------------------------------------------------


async def _base(engine: AsyncEngine) -> dict[str, int]:
    """One run, two devices and one query to each device."""
    async with engine.begin() as conn:
        run = await conn.scalar(
            insert(collection_runs)
            .values(kind="discovery", status="pending", requested_at=T0, parameters={})
            .returning(collection_runs.c.id)
        )
        ids = {"run": run}
        for name in ("dev1", "dev2"):
            ids[name] = await conn.scalar(insert(devices).values().returning(devices.c.id))
        for name, dev in (("q1", "dev1"), ("q2", "dev2")):
            ids[name] = await conn.scalar(
                insert(snmp_queries)
                .values(
                    run_id=run,
                    target_address="10.99.0.11" if dev == "dev1" else "10.99.0.12",
                    device_id=ids[dev],
                    mib_object="IF-MIB::ifTable",
                    operation="walk",
                    snmp_version="2c",
                    outcome="ok",
                    row_count=1,
                    request_count=1,
                    started_at=T0,
                    duration_ms=10,
                )
                .returning(snmp_queries.c.id)
            )
    return ids


def _interface(ids: dict[str, int], **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "device_id": ids["dev1"],
        "if_index": 1,
        "base_origin": "observed",
        "base_first_seen_at": T0,
        "base_first_query_id": ids["q1"],
        "base_last_seen_at": T0,
        "base_last_query_id": ids["q1"],
    }
    row.update(overrides)
    return row


async def _insert_interface(engine: AsyncEngine, row: dict[str, object]) -> None:
    async with engine.begin() as conn:
        await conn.execute(insert(interfaces).values(**row))


SNAPSHOT_EVIDENCE = {
    "method": "lldp-port-description-match",
    "method_version": 1,
    "inputs": [{"kind": "record", "table": "interfaces", "id": 1, "snapshot": {"if_descr": "x"}}],
}


async def test_valid_observed_row_accepted(engine: AsyncEngine) -> None:
    ids = await _base(engine)
    await _insert_interface(engine, _interface(ids))


async def test_valid_inferred_row_accepted(engine: AsyncEngine) -> None:
    ids = await _base(engine)
    await _insert_interface(
        engine,
        _interface(
            ids,
            base_origin="inferred",
            base_method="lldp-port-description-match",
            base_evidence=SNAPSHOT_EVIDENCE,
        ),
    )


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"base_origin": "inferred"}, "base_inferred"),
        (
            {"base_origin": "inferred", "base_method": "lldp-port-description-match"},
            "base_inferred",
        ),
        (
            {
                "base_origin": "inferred",
                "base_method": "lldp-port-description-match",
                "base_evidence": {**SNAPSHOT_EVIDENCE, "inputs": [{"kind": "query", "id": 1}]},
            },
            "base_inferred",
        ),
        ({"base_evidence": SNAPSHOT_EVIDENCE}, "base_evidence_method"),
        ({"base_last_seen_at": T0 - timedelta(seconds=1)}, "base_seen_order"),
        ({"base_origin": "guessed"}, "base_origin"),
        ({"base_first_query_id": None, "base_first_seen_at": None}, "base_all_or_none"),
        ({"ext_method": "lldp-portid-ifname"}, "ext_all_or_none"),
        ({"if_index": 0}, "if_index"),
    ],
)
async def test_invalid_provenance_rejected(
    engine: AsyncEngine, overrides: dict[str, object], constraint: str
) -> None:
    ids = await _base(engine)
    with pytest.raises(IntegrityError, match=f"ck_interfaces_{constraint}"):
        await _insert_interface(engine, _interface(ids, **overrides))


async def test_observation_referencing_query_of_another_device_rejected(
    engine: AsyncEngine,
) -> None:
    ids = await _base(engine)
    with pytest.raises(IntegrityError, match="fk_interfaces_base_last_query"):
        await _insert_interface(engine, _interface(ids, base_last_query_id=ids["q2"]))


async def test_device_group_referencing_query_of_another_device_rejected(
    engine: AsyncEngine,
) -> None:
    ids = await _base(engine)
    async with engine.begin() as conn:
        with pytest.raises(IntegrityError, match="fk_devices_system_first_query"):
            await conn.execute(
                devices.update()
                .where(devices.c.id == ids["dev1"])
                .values(
                    system_origin="observed",
                    system_first_seen_at=T0,
                    system_first_query_id=ids["q2"],
                    system_last_seen_at=T0,
                    system_last_query_id=ids["q1"],
                )
            )


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("UPDATE snmp_queries SET target_address = CAST(:v AS text)::inet", "inet"),
        ("UPDATE interfaces SET phys_address = CAST(:v AS text)::macaddr", "macaddr"),
    ],
)
async def test_invalid_address_types_rejected(
    engine: AsyncEngine, statement: str, message: str
) -> None:
    ids = await _base(engine)
    await _insert_interface(engine, _interface(ids))
    async with engine.begin() as conn:
        with pytest.raises(DBAPIError, match=f"invalid input syntax for type {message}"):
            await conn.execute(text(statement), {"v": "10.99.0.300" if message == "inet" else "zz"})


async def test_query_outcome_rules(engine: AsyncEngine) -> None:
    ids = await _base(engine)
    cases = [
        ({"outcome": "empty"}, "indicator_required"),
        ({"outcome": "error"}, "error_category"),
        ({"outcome": "no_response", "row_count": 0, "indicator": "noSuchObject"}, "no_diagnosis"),
        ({"outcome": "ok", "error_category": "decode_error"}, "error_only_on_failure"),
        ({"rejected_count": 2}, "counts"),
    ]
    for values, constraint in cases:
        async with engine.begin() as conn:
            with pytest.raises(IntegrityError, match=f"ck_snmp_queries_{constraint}"):
                await conn.execute(
                    snmp_queries.update().where(snmp_queries.c.id == ids["q1"]).values(**values)
                )
