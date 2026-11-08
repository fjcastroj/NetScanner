# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Walk strategy, outcome classification and load control (design D3 to D6).

Library independent: an implementation only provides a :class:`Transport`
that sends one GET or one GETBULK and reports what came back. Every rule about
walks, outcomes, categories, row limits, one request in flight per device, the
global device limit and secret masking lives here once.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from netscanner.core.config import Settings
from netscanner.core.logging_setup import secrets_in_use
from netscanner.snmp.results import GetResult, SnmpException, SnmpValue, TableResult, Target
from netscanner.snmp.tables import Oid, TableSpec
from netscanner.store.registry import Indicator, Outcome

# --- Transport --------------------------------------------------------------


class ResponseKind(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    ERROR_STATUS = "error_status"
    V3_REPORT = "v3_report"
    DECODE_ERROR = "decode_error"
    TRANSPORT_ERROR = "transport_error"


@dataclass(frozen=True)
class Response:
    kind: ResponseKind
    varbinds: list[tuple[Oid, SnmpValue | SnmpException]] = field(default_factory=list)
    # Error status name or USM report counter, from a fixed vocabulary.
    detail: str | None = None

    def category(self) -> str:
        if self.kind in (ResponseKind.ERROR_STATUS, ResponseKind.V3_REPORT):
            return f"{self.kind}:{self.detail}"
        return str(self.kind)


class Transport(Protocol):
    async def get(self, oids: Sequence[Oid]) -> Response: ...

    async def bulk(self, oid: Oid, max_repetitions: int) -> Response: ...


TransportFactory = Callable[[Target, "SnmpLimits"], AbstractAsyncContextManager[Transport]]


# --- Limits -----------------------------------------------------------------


@dataclass(frozen=True)
class SnmpLimits:
    """Load limits (design D5); out-of-range values are refused, naming the setting."""

    timeout: float = 3.0
    retries: int = 1
    max_repetitions: int = 25
    max_rows: int = 200_000
    max_devices: int = 8

    def __post_init__(self) -> None:
        checks = {
            "NETSCANNER_SNMP_TIMEOUT": 0 < self.timeout <= 60,
            "NETSCANNER_SNMP_RETRIES": 0 <= self.retries <= 5,
            "NETSCANNER_SNMP_MAX_REPETITIONS": 1 <= self.max_repetitions <= 50,
            "NETSCANNER_SNMP_MAX_ROWS": 1 <= self.max_rows <= 10_000_000,
            "NETSCANNER_SNMP_MAX_DEVICES": 1 <= self.max_devices <= 256,
        }
        for name, ok in checks.items():
            if not ok:
                raise ValueError(f"{name} is out of range")

    @classmethod
    def from_settings(cls, settings: Settings) -> SnmpLimits:
        return cls(
            timeout=settings.snmp_timeout,
            retries=settings.snmp_retries,
            max_repetitions=settings.snmp_max_repetitions,
            max_rows=settings.snmp_max_rows,
            max_devices=settings.snmp_max_devices,
        )


# --- Walk -------------------------------------------------------------------


class _Counter:
    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.requests = 0

    async def get(self, oids: Sequence[Oid]) -> Response:
        self.requests += 1
        return await _guard(self.transport.get(oids))

    async def bulk(self, oid: Oid, repetitions: int) -> Response:
        self.requests += 1
        return await _guard(self.transport.bulk(oid, repetitions))


async def _guard(call: object) -> Response:
    """A failing transport becomes a response; its exception text is never kept."""
    try:
        return await call  # type: ignore[misc]
    except Exception:  # any failure of the library is a query error
        return Response(ResponseKind.TRANSPORT_ERROR)


@dataclass
class _Stop:
    category: str
    answered_before: bool  # some earlier request of this walk was answered


async def _walk_subtree(
    t: _Counter,
    subtree: Oid,
    limits: SnmpLimits,
    on_varbind: Callable[[Oid, SnmpValue], bool],
) -> tuple[bool, _Stop | None]:
    """Walk one subtree with GETBULK. Returns (answered, stop reason or None).

    ``on_varbind`` stores one value and returns False when the row limit is hit.
    """
    # Every OID returned must be greater than the one before it, starting
    # with the OID of the request itself.
    current = last = subtree
    answered = False
    while True:
        response = await t.bulk(current, limits.max_repetitions)
        if response.kind is not ResponseKind.OK:
            return answered, _Stop(response.category(), answered)
        answered = True
        if not response.varbinds:
            return answered, None
        for oid, value in response.varbinds:
            if value is SnmpException.END_OF_MIB_VIEW or oid[: len(subtree)] != subtree:
                return answered, None
            if oid <= last:
                return answered, _Stop("non_increasing_oid", True)
            last = oid
            if isinstance(value, SnmpException):
                continue  # not expected inside a walk; nothing to store
            if not on_varbind(oid, value):
                return answered, _Stop("row_limit", True)
        current = last


async def walk_table(
    transport: Transport, table: TableSpec, columns: Sequence[str] | None, limits: SnmpLimits
) -> TableResult:
    started_at, start = datetime.now(UTC), time.monotonic()
    requested = tuple(columns) if columns else tuple(table.columns)
    unknown = set(requested) - set(table.columns)
    if unknown:
        raise ValueError(f"unknown columns of {table.mib_object}: {sorted(unknown)}")
    t = _Counter(transport)
    rows: dict[Oid, dict[str, SnmpValue]] = {}
    wanted = set(requested)

    def store(column: str, index: Oid, value: SnmpValue) -> bool:
        if index not in rows:
            if len(rows) >= limits.max_rows:
                return False
            rows[index] = {}
        rows[index][column] = value
        return True

    def whole_table(oid: Oid, value: SnmpValue) -> bool:
        column = table.column_name(oid[len(table.oid)]) if len(oid) > len(table.oid) else None
        if column is None or column not in wanted:
            return True  # a column outside the registry is ignored
        return store(column, oid[len(table.oid) + 1 :], value)

    answered, stop = False, None
    if columns is None and not table.by_columns:
        answered, stop = await _walk_subtree(t, table.oid, limits, whole_table)
    else:
        for column in requested:
            subtree = table.column_oid(column)

            def one_column(
                oid: Oid, value: SnmpValue, column: str = column, n: int = len(subtree)
            ) -> bool:
                return store(column, oid[n:], value)

            got, stop = await _walk_subtree(t, subtree, limits, one_column)
            answered = answered or got
            if stop is not None:
                break  # later columns are not reached

    def result(outcome: Outcome, complete: bool, **extra: object) -> TableResult:
        return TableResult(
            mib_object=table.mib_object,
            outcome=outcome,
            complete=complete,
            columns=requested,
            rows=rows,
            request_count=t.requests,
            started_at=started_at,
            duration_ms=round((time.monotonic() - start) * 1000),
            **extra,
        )

    if rows:
        if stop is None:
            return result(Outcome.OK, True)
        return result(Outcome.PARTIAL, False, error_category=stop.category)
    if stop is not None:
        if stop.category == "timeout" and not stop.answered_before and not answered:
            return result(Outcome.NO_RESPONSE, False)  # silence: no claim about the cause
        return result(Outcome.ERROR, False, error_category=stop.category)
    # No rows and a normal end: classify with the probe column, never the table node.
    probe = await t.get([table.column_oid(table.probe)])
    if probe.kind is not ResponseKind.OK:
        return result(Outcome.ERROR, False, error_category=probe.category())
    answer = probe.varbinds[0][1] if probe.varbinds else None
    if answer is SnmpException.NO_SUCH_OBJECT:
        return result(Outcome.NOT_AVAILABLE, True, indicator=str(Indicator.NO_SUCH_OBJECT))
    if answer is SnmpException.NO_SUCH_INSTANCE:
        return result(Outcome.EMPTY, True, indicator=str(Indicator.NO_SUCH_INSTANCE))
    if answer is SnmpException.END_OF_MIB_VIEW:
        return result(Outcome.EMPTY, True, indicator=str(Indicator.END_OF_MIB_VIEW))
    return result(Outcome.EMPTY, True, indicator=str(Indicator.VALUE_RETURNED))


async def get(transport: Transport, oids: Sequence[Oid]) -> GetResult:
    started_at, start = datetime.now(UTC), time.monotonic()
    t = _Counter(transport)
    response = await t.get(list(oids))

    def done(outcome: Outcome, **extra: object) -> GetResult:
        return GetResult(
            outcome=outcome,
            request_count=t.requests,
            started_at=started_at,
            duration_ms=round((time.monotonic() - start) * 1000),
            **extra,
        )

    if response.kind is ResponseKind.TIMEOUT:
        return done(Outcome.NO_RESPONSE)
    if response.kind is not ResponseKind.OK:
        return done(Outcome.ERROR, error_category=response.category())
    values, indicators = {}, {}
    for oid, value in response.varbinds:
        if isinstance(value, SnmpException):
            indicators[oid] = value
        else:
            values[oid] = value
    return done(Outcome.OK, values=values, indicators=indicators)


# --- Bounded client ---------------------------------------------------------


class BoundedClient:
    """An :class:`SnmpClient` over any transport, with the load limits of D5.

    One request in flight per device (a lock per address and port held for
    the whole operation), at most ``max_devices`` devices at a time, and the
    target's secrets masked in every log record while the operation runs.
    """

    def __init__(
        self, transport_factory: TransportFactory, limits: SnmpLimits | None = None
    ) -> None:
        self.limits = limits or SnmpLimits()
        self._transport_factory = transport_factory
        self._devices = asyncio.Semaphore(self.limits.max_devices)
        self._locks: dict[tuple[str, int], asyncio.Lock] = {}

    @asynccontextmanager
    async def _transport(self, target: Target) -> AsyncIterator[Transport]:
        lock = self._locks.setdefault(target.device_key, asyncio.Lock())
        async with lock, self._devices:
            with secrets_in_use(target.credential.secrets()):
                async with self._transport_factory(target, self.limits) as transport:
                    yield transport

    async def get(self, target: Target, oids: Sequence[Oid]) -> GetResult:
        async with self._transport(target) as transport:
            return await get(transport, oids)

    async def walk_table(
        self, target: Target, table: TableSpec, columns: Sequence[str] | None = None
    ) -> TableResult:
        async with self._transport(target) as transport:
            return await walk_table(transport, table, columns, self.limits)
