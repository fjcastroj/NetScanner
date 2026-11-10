# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Collection runs, query records and the devices reached by each run (design D6, D8).

Functions take an ``AsyncConnection`` inside the caller's transaction;
``netscanner.store.service.Store`` wraps them with transactions. Errors are
stored as categories from the registry, never as exception text.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    IPvAnyNetwork,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy import case, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncConnection

from netscanner.store import registry
from netscanner.store.errors import RunStateError, StoreError
from netscanner.store.models import collection_runs, run_devices, snmp_queries
from netscanner.store.registry import (
    COMPLETE_OUTCOMES,
    INDICATOR_OUTCOMES,
    Indicator,
    Operation,
    Outcome,
    SnmpVersion,
)

RunKind = Literal["discovery", "rediscovery", "polling"]
ReachedVia = Literal["seed", "lldp", "cdp", "ip-mac"]
SkipReason = Literal[
    "out_of_scope",
    "excluded",
    "special_address",
    "already_known",
    "max_depth",
    "limit_reached",
    "no_response",
    "auth_failed",
    "query_error",
]
SKIP_REASONS = frozenset(SkipReason.__args__)


def safe_validation_message(exc: ValidationError) -> str:
    """Locations and error types only: inputs may contain secrets or device data."""
    parts = sorted(
        {
            f"{'.'.join(map(str, e['loc'])) or 'value'}: {e['type']}"
            for e in exc.errors(include_input=False, include_url=False, include_context=False)
        }
    )
    return "; ".join(parts)


# --- Runs -------------------------------------------------------------------


class RunLimits(BaseModel):
    """Operational limits of one run, copied from the settings (design D6)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_candidates: int = Field(ge=1)
    max_devices: int = Field(ge=1)
    max_datagrams: int = Field(ge=1)


class RunParameters(BaseModel):
    """Parameters copied into the run record. There is no field for any secret:
    the credential is referenced by its identifier, and unknown fields (such as
    a community) are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seeds: list[IPvAnyAddress] = Field(default_factory=list, max_length=1024)
    allowed_ranges: list[IPvAnyNetwork] = Field(default_factory=list, max_length=1024)
    exclusions: list[IPvAnyNetwork] = Field(default_factory=list, max_length=1024)
    max_depth: int | None = Field(default=None, ge=0, le=32)
    credential_id: int | None = Field(default=None, gt=0)
    device_ids: list[int] = Field(default_factory=list, max_length=100_000)
    # Ask finish_run to store an evaluation snapshot (design D11).
    snapshot: bool = False
    # add-discovery-and-basic-inventory: defaults keep earlier runs parseable.
    follow_ip_mac: bool = False
    limits: RunLimits | None = None


def parse_parameters(value: RunParameters | dict) -> RunParameters:
    if isinstance(value, RunParameters):
        return value
    try:
        return RunParameters.model_validate(value)
    except ValidationError as exc:
        raise StoreError(f"invalid run parameters: {safe_validation_message(exc)}") from None


async def create_run(
    conn: AsyncConnection, kind: RunKind, parameters: RunParameters | dict, now: datetime
) -> int:
    if kind not in ("discovery", "rediscovery", "polling"):
        raise StoreError(f"unknown run kind: {kind!r}")
    params = parse_parameters(parameters)
    return await conn.scalar(
        insert(collection_runs)
        .values(
            kind=kind,
            status="pending",
            requested_at=now,
            parameters=params.model_dump(mode="json"),
        )
        .returning(collection_runs.c.id)
    )


async def _transition(
    conn: AsyncConnection, run_id: int, allowed: tuple[str, ...], **values: object
) -> None:
    result = await conn.execute(
        update(collection_runs)
        .where(collection_runs.c.id == run_id, collection_runs.c.status.in_(allowed))
        .values(**values)
        .returning(collection_runs.c.id)
    )
    if result.first() is None:
        raise RunStateError(f"run {run_id} is not {' or '.join(allowed)}")


async def start_run(conn: AsyncConnection, run_id: int, now: datetime) -> None:
    await _transition(conn, run_id, ("pending",), status="running", started_at=now)


async def claim_pending_run(
    conn: AsyncConnection, now: datetime, kinds: tuple[str, ...] = ("discovery",)
) -> int | None:
    """Start the oldest pending run of ``kinds``; ``None`` if there is none.

    ``FOR UPDATE SKIP LOCKED``: two collectors never claim the same run.
    """
    run_id = await conn.scalar(
        select(collection_runs.c.id)
        .where(collection_runs.c.status == "pending", collection_runs.c.kind.in_(kinds))
        .order_by(collection_runs.c.requested_at, collection_runs.c.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if run_id is not None:
        await start_run(conn, run_id, now)
    return run_id


async def close_run(
    conn: AsyncConnection,
    run_id: int,
    status: Literal["completed", "failed"],
    now: datetime,
    error_category: str | None = None,
    summary: dict | None = None,
) -> None:
    if status not in ("completed", "failed"):
        raise StoreError(f"a run is finished as completed or failed, not {status!r}")
    if error_category is not None:
        registry.check_error_category(error_category)
    await _transition(
        conn,
        run_id,
        ("running",),
        status=status,
        finished_at=now,
        error_category=error_category,
        summary=summary,
    )


async def mark_interrupted_runs(conn: AsyncConnection, now: datetime) -> list[int]:
    """Runs left running by a previous process are marked interrupted at ``now``."""
    result = await conn.execute(
        update(collection_runs)
        .where(collection_runs.c.status == "running")
        .values(status="interrupted", finished_at=now)
        .returning(collection_runs.c.id)
    )
    return sorted(result.scalars())


async def run_parameters(conn: AsyncConnection, run_id: int) -> RunParameters:
    value = await conn.scalar(
        select(collection_runs.c.parameters).where(collection_runs.c.id == run_id)
    )
    if value is None:
        raise StoreError(f"unknown run {run_id}")
    return RunParameters.model_validate(value)


# --- Queries ----------------------------------------------------------------


class QueryRecord(BaseModel):
    """One SNMP query and its outcome (RF-06)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: int = Field(gt=0)
    target_address: IPvAnyAddress
    device_id: int | None = Field(default=None, gt=0)
    mib_object: str
    operation: Operation
    snmp_version: SnmpVersion = SnmpVersion.V2C
    outcome: Outcome
    indicator: Indicator | None = None
    error_category: str | None = None
    row_count: int = Field(default=0, ge=0)
    request_count: int = Field(default=1, ge=0)
    started_at: AwareDatetime
    duration_ms: int = Field(ge=0)

    @field_validator("mib_object")
    @classmethod
    def _mib_object(cls, value: str) -> str:
        return registry.check_mib_object(value)

    @field_validator("error_category")
    @classmethod
    def _category(cls, value: str | None) -> str | None:
        return None if value is None else registry.check_error_category(value)

    @model_validator(mode="after")
    def _outcome_rules(self) -> Self:
        if self.outcome in INDICATOR_OUTCOMES and self.indicator is None:
            raise ValueError(f"outcome {self.outcome} needs the indicator it is based on")
        if self.outcome is Outcome.ERROR and self.error_category is None:
            raise ValueError("outcome error needs an error category")
        if self.error_category is not None and self.outcome not in (Outcome.ERROR, Outcome.PARTIAL):
            raise ValueError("only error and partial outcomes have an error category")
        if self.outcome is Outcome.NO_RESPONSE and (self.indicator or self.row_count):
            # SNMPv2c cannot tell a wrong community from a filter or a dead host.
            raise ValueError("no_response is stored without any diagnosis or rows")
        return self


def error_category_for(exc: BaseException) -> str:
    """Category of an exception raised while querying; its text is never stored."""
    if isinstance(exc, UnicodeError):
        return "decode_error"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, OSError):
        return "transport_error"
    if isinstance(exc, ValueError):
        return "validation_error"
    return "internal_error"


@dataclass(frozen=True)
class QueryInfo:
    """What the persistence layer needs to know about a stored query."""

    id: int
    run_id: int
    device_id: int | None
    target_address: IPv4Address | IPv6Address
    mib_object: str
    outcome: str
    rejected_count: int
    started_at: datetime

    @property
    def complete(self) -> bool:
        return is_complete(self.outcome, self.rejected_count)

    @property
    def order(self) -> tuple[datetime, int]:
        """Queries are compared by start time, then by id (design D9)."""
        return (self.started_at, self.id)


def is_complete(outcome: str, rejected_count: int) -> bool:
    """Complete: outcome ok or empty and no rejected rows (design D6)."""
    return outcome in COMPLETE_OUTCOMES and rejected_count == 0


async def record_query(
    conn: AsyncConnection, record: QueryRecord | dict, error: BaseException | None = None
) -> int:
    """Store one query. ``error``, if given, is reduced to its category."""
    if isinstance(record, dict):
        if error is not None and record.get("error_category") is None:
            record = {**record, "error_category": error_category_for(error)}
        try:
            record = QueryRecord.model_validate(record)
        except ValidationError as exc:
            raise StoreError(f"invalid query record: {safe_validation_message(exc)}") from None
    elif error is not None and record.error_category is None:
        record = record.model_copy(update={"error_category": error_category_for(error)})
    values = record.model_dump(mode="json")
    values["started_at"] = record.started_at
    return await conn.scalar(insert(snmp_queries).values(**values).returning(snmp_queries.c.id))


async def get_query(conn: AsyncConnection, query_id: int, *, lock: bool = False) -> QueryInfo:
    stmt = select(
        snmp_queries.c.id,
        snmp_queries.c.run_id,
        snmp_queries.c.device_id,
        snmp_queries.c.target_address,
        snmp_queries.c.mib_object,
        snmp_queries.c.outcome,
        snmp_queries.c.rejected_count,
        snmp_queries.c.started_at,
    ).where(snmp_queries.c.id == query_id)
    if lock:
        stmt = stmt.with_for_update()
    row = (await conn.execute(stmt)).first()
    if row is None:
        raise StoreError(f"unknown query {query_id}")
    return QueryInfo(**row._mapping)


async def add_rejected(conn: AsyncConnection, query_id: int, rejected: int) -> QueryInfo:
    """Record the rows of a query rejected by validation.

    A query's rows are stored in one call, so storing them again sets the same
    count instead of adding to it.
    """
    if rejected:
        await conn.execute(
            update(snmp_queries)
            .where(snmp_queries.c.id == query_id)
            .values(rejected_count=func.greatest(snmp_queries.c.rejected_count, rejected))
        )
    return await get_query(conn, query_id)


# --- Devices reached --------------------------------------------------------


async def record_run_device(
    conn: AsyncConnection,
    run_id: int,
    target_address: str | IPv4Address | IPv6Address,
    reached_via: ReachedVia,
    depth: int,
    *,
    first_query_id: int | None = None,
    answered: bool = False,
    device_id: int | None = None,
    skip_reason: SkipReason | None = None,
    found_from_device_id: int | None = None,
) -> int:
    """Record a device or candidate address reached by a run, new or known.

    The first record of an address keeps how and from which device it was
    found. A reason given replaces the stored one; recording a query sent to
    the address (``first_query_id`` or ``answered``) without a reason clears
    it, so a queried candidate never keeps a reason it no longer has.
    """
    if reached_via not in ("seed", "lldp", "cdp", "ip-mac"):
        raise StoreError(f"unknown way to reach a device: {reached_via!r}")
    if depth < 0:
        raise StoreError("depth must not be negative")
    if skip_reason is not None and skip_reason not in SKIP_REASONS:
        raise StoreError("unknown reason for a candidate not queried")
    if skip_reason is not None and device_id is not None:
        raise StoreError("a candidate has either a device or a reason, not both")
    stmt = insert(run_devices).values(
        run_id=run_id,
        target_address=str(target_address),
        reached_via=reached_via,
        depth=depth,
        first_query_id=first_query_id,
        answered=answered,
        device_id=device_id,
        skip_reason=skip_reason,
        found_from_device_id=found_from_device_id,
    )
    queried = stmt.excluded.first_query_id.is_not(None) | stmt.excluded.answered
    stmt = stmt.on_conflict_do_update(
        index_elements=["run_id", "target_address"],
        set_={
            "depth": func.least(run_devices.c.depth, stmt.excluded.depth),
            "first_query_id": func.coalesce(
                run_devices.c.first_query_id, stmt.excluded.first_query_id
            ),
            "answered": run_devices.c.answered | stmt.excluded.answered,
            "device_id": func.coalesce(stmt.excluded.device_id, run_devices.c.device_id),
            "skip_reason": case(
                (stmt.excluded.skip_reason.is_not(None), stmt.excluded.skip_reason),
                (queried | stmt.excluded.device_id.is_not(None), None),
                else_=run_devices.c.skip_reason,
            ),
            "found_from_device_id": func.coalesce(
                run_devices.c.found_from_device_id, stmt.excluded.found_from_device_id
            ),
        },
    )
    return await conn.scalar(stmt.returning(run_devices.c.id))


async def assign_device(
    conn: AsyncConnection,
    run_id: int,
    target_address: str | IPv4Address | IPv6Address,
    device_id: int,
) -> None:
    """Once a device is resolved, attach it to the run's queries sent to that address."""
    address = str(target_address)
    await conn.execute(
        update(snmp_queries)
        .where(
            snmp_queries.c.run_id == run_id,
            snmp_queries.c.target_address == address,
            snmp_queries.c.device_id.is_(None),
        )
        .values(device_id=device_id)
    )
    await conn.execute(
        update(run_devices)
        .where(run_devices.c.run_id == run_id, run_devices.c.target_address == address)
        .values(device_id=device_id, answered=True, skip_reason=None)
    )


RUN_COLUMNS = (
    "id",
    "kind",
    "status",
    "requested_at",
    "started_at",
    "finished_at",
    "error_category",
)


async def list_runs(
    conn: AsyncConnection, limit: int, offset: int
) -> tuple[int, list[dict[str, Any]]]:
    """A page of runs, newest first, and the total number of runs."""
    total = await conn.scalar(select(func.count()).select_from(collection_runs))
    columns = [collection_runs.c[name] for name in RUN_COLUMNS]
    rows = await conn.execute(
        select(*columns)
        .order_by(collection_runs.c.requested_at.desc(), collection_runs.c.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return total or 0, [dict(r._mapping) for r in rows]


async def get_run(conn: AsyncConnection, run_id: int) -> dict[str, Any] | None:
    """One run with its parameters and summary, or ``None``."""
    columns = [collection_runs.c[name] for name in RUN_COLUMNS]
    row = (
        await conn.execute(
            select(*columns, collection_runs.c.parameters, collection_runs.c.summary).where(
                collection_runs.c.id == run_id
            )
        )
    ).first()
    return None if row is None else dict(row._mapping)


async def count_queries(conn: AsyncConnection, run_id: int) -> int:
    """SNMP queries recorded for a run so far."""
    return (
        await conn.scalar(
            select(func.count()).select_from(snmp_queries).where(snmp_queries.c.run_id == run_id)
        )
        or 0
    )
