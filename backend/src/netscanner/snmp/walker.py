# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Walk strategy, outcome classification and load control (design D3 to D6).

Library independent: an implementation only provides a :class:`Transport`
that sends one GET or one GETBULK, once, and reports what came back. Every
rule lives here once, so both implementations behave the same:
- walks, outcomes and categories;
- retries (add-discovery-and-basic-inventory, D6), so every datagram can be
  counted;
- the datagram budget, shared by the concurrent calls of a run;
- the scope check repeated before every datagram (D2);
- row limits, one request in flight per device and the global device limit;
- the credential of a device session, resolved and released around it.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from netscanner.core.config import Settings
from netscanner.scope.policy import AuthorizedTarget
from netscanner.snmp.credentials import SnmpV2cCredential, SnmpV3Credential
from netscanner.snmp.results import GetResult, SnmpException, SnmpValue, TableResult
from netscanner.snmp.tables import Oid, TableSpec
from netscanner.store.registry import Indicator, Outcome

Credential = SnmpV2cCredential | SnmpV3Credential

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
    """Sends one request, once: retries belong to the walker."""

    async def get(self, oids: Sequence[Oid]) -> Response: ...

    async def bulk(self, oid: Oid, max_repetitions: int) -> Response: ...


@dataclass(frozen=True)
class Endpoint:
    """Where the datagrams of one device session go, and with what."""

    host: str
    port: int
    credential: Credential
    context: str  # SNMPv3 context name; empty for real devices

    def __repr__(self) -> str:  # no credential, not even masked
        return f"Endpoint({self.host}:{self.port})"


TransportFactory = Callable[[Endpoint, "SnmpLimits"], AbstractAsyncContextManager[Transport]]
EndpointFor = Callable[[str, int], tuple[str, int]]


class CredentialSource(Protocol):
    """What the adapter needs from ``netscanner.credential_store.CredentialResolver``."""

    async def resolve(self, credential_id: int | None) -> Credential: ...

    def release(self, credential: Credential) -> None: ...


class ScopeViolation(RuntimeError):
    """A datagram to an address the run's policy does not allow: never sent."""


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


# --- Budget -----------------------------------------------------------------


class BudgetPool:
    """A datagram budget shared by concurrent calls (design D6).

    A call reserves the attempts of a request before sending it and returns
    the unused ones when it ends, so concurrent devices never exceed the
    total. ``total=None`` means unlimited.
    """

    def __init__(self, total: int | None) -> None:
        self.total = total
        self.reserved = 0
        self.consumed = 0

    def reserve(self, n: int) -> bool:
        if self.total is not None and self.total - self.consumed - self.reserved < n:
            return False
        self.reserved += n
        return True

    def use(self, n: int = 1) -> None:
        self.reserved -= n
        self.consumed += n

    def release(self, n: int) -> None:
        self.reserved -= n

    @property
    def exhausted(self) -> bool:
        return self.total is not None and self.total - self.consumed - self.reserved <= 0


def as_pool(budget: int | BudgetPool | None) -> BudgetPool:
    return budget if isinstance(budget, BudgetPool) else BudgetPool(budget)


# --- Walk -------------------------------------------------------------------


class _Session:
    """One client call: counts datagrams, retries timeouts, checks budget and scope.

    ``datagrams`` are what the walker sends and observes (reported). The budget
    consumed (``budget_used``) also counts ``extra``: one datagram per SNMPv3
    call for the library's engine discovery, which the walker cannot see.
    """

    def __init__(
        self,
        transport: Transport,
        target: AuthorizedTarget,
        limits: SnmpLimits,
        pool: BudgetPool,
        extra: int = 0,
    ) -> None:
        self.transport = transport
        self.target = target
        self.attempts = limits.retries + 1
        self.pool = pool
        self.extra_pending = extra
        self.held = 0
        self.datagrams = 0
        self.budget_used = 0

    def covers(self, requests: int) -> bool:
        """Reserve, if needed, every attempt of ``requests`` more requests."""
        missing = self.attempts * requests + self.extra_pending - self.held
        if missing <= 0:
            return True
        if not self.pool.reserve(missing):
            return False
        self.held += missing
        return True

    def close(self) -> None:
        """Return the reserved datagrams this call did not use."""
        self.pool.release(self.held)
        self.held = 0

    def _consume(self) -> None:
        self.held -= 1
        self.pool.use(1)
        self.budget_used += 1

    async def _send(self, call: Callable[[], Awaitable[Response]]) -> Response:
        if not self.covers(1):  # callers check first; this keeps the pool exact
            raise RuntimeError("request sent without budget")
        if self.extra_pending:
            self._consume()  # the SNMPv3 engine discovery of this call
            self.extra_pending = 0
        response = Response(ResponseKind.TIMEOUT)
        for _ in range(self.attempts):
            # Defence in depth: the frozen policy is asked again before every datagram.
            if not self.target.policy.contains(self.target.address):
                raise ScopeViolation("the target is outside its run's scope")
            self._consume()
            self.datagrams += 1
            response = await _guard(call())
            if response.kind is not ResponseKind.TIMEOUT:
                return response
        return response

    async def get(self, oids: Sequence[Oid]) -> Response:
        return await self._send(lambda: self.transport.get(oids))

    async def bulk(self, oid: Oid, repetitions: int) -> Response:
        return await self._send(lambda: self.transport.bulk(oid, repetitions))


async def _guard(call: Awaitable[Response]) -> Response:
    """A failing transport becomes a response; its exception text is never kept."""
    try:
        return await call
    except Exception:  # any failure of the library is a query error
        return Response(ResponseKind.TRANSPORT_ERROR)


@dataclass
class _Stop:
    category: str


async def _walk_subtree(
    t: _Session,
    subtree: Oid,
    limits: SnmpLimits,
    on_varbind: Callable[[Oid, SnmpValue], bool],
    may_send: Callable[[], bool],
) -> tuple[bool, _Stop | None]:
    """Walk one subtree with GETBULK. Returns (answered, stop reason or None).

    ``on_varbind`` stores one value and returns False when the row limit is hit;
    ``may_send`` says whether the budget covers the next request.
    """
    # Every OID returned must be greater than the one before it, starting
    # with the OID of the request itself.
    current = last = subtree
    answered = False
    while True:
        if not may_send():
            return answered, _Stop("request_limit")
        response = await t.bulk(current, limits.max_repetitions)
        if response.kind is not ResponseKind.OK:
            return answered, _Stop(response.category())
        answered = True
        if not response.varbinds:
            return answered, None
        for oid, value in response.varbinds:
            if value is SnmpException.END_OF_MIB_VIEW or oid[: len(subtree)] != subtree:
                return answered, None
            if oid <= last:
                return answered, _Stop("non_increasing_oid")
            last = oid
            if isinstance(value, SnmpException):
                continue  # not expected inside a walk; nothing to store
            if not on_varbind(oid, value):
                return answered, _Stop("row_limit")
        current = last


async def walk_table(
    transport: Transport,
    target: AuthorizedTarget,
    table: TableSpec,
    columns: Sequence[str] | None,
    limits: SnmpLimits,
    budget: int | BudgetPool | None = None,
    extra: int = 0,
) -> TableResult:
    """Walk a table; with a budget, send a request only when all its attempts are covered.

    Until the walk has rows, the budget must also cover one request for every
    subtree still to walk and the attempts of the probe, so a walk that gets
    no rows can normally be classified. With rows, a request not covered ends
    the walk as ``partial``/``request_limit``; without rows (a subtree needing
    more requests than reserved) as ``error``/``request_limit``.
    """
    started_at, start = datetime.now(UTC), time.monotonic()
    requested = tuple(columns) if columns else tuple(table.columns)
    unknown = set(requested) - set(table.columns)
    if unknown:
        raise ValueError(f"unknown columns of {table.mib_object}: {sorted(unknown)}")
    t = _Session(transport, target, limits, as_pool(budget), extra)
    try:
        return await _walk(t, table, columns, requested, limits, started_at, start)
    finally:
        t.close()


async def _walk(
    t: _Session,
    table: TableSpec,
    columns: Sequence[str] | None,
    requested: tuple[str, ...],
    limits: SnmpLimits,
    started_at: datetime,
    start: float,
) -> TableResult:
    rows: dict[Oid, dict[str, SnmpValue]] = {}
    wanted = set(requested)

    def result(outcome: Outcome | None, complete: bool, **extra: object) -> TableResult:
        return TableResult(
            mib_object=table.mib_object,
            outcome=outcome,
            complete=complete,
            columns=requested,
            rows=rows,
            request_count=t.datagrams,
            budget_used=t.budget_used,
            started_at=started_at,
            duration_ms=round((time.monotonic() - start) * 1000),
            **extra,
        )

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

    whole = columns is None and not table.by_columns
    subtrees = [table.oid] if whole else [table.column_oid(c) for c in requested]
    if not t.covers(len(subtrees) + 1):
        return result(None, False)  # nothing sent, nothing to record

    answered, stop = False, None
    for i, subtree in enumerate(subtrees):
        left = len(subtrees) - i

        def may_send(left: int = left) -> bool:
            return t.covers(1) if rows else t.covers(left + 1)

        if whole:
            on_varbind = whole_table
        else:

            def on_varbind(
                oid: Oid, value: SnmpValue, column: str = requested[i], n: int = len(subtree)
            ) -> bool:
                return store(column, oid[n:], value)

        got, stop = await _walk_subtree(t, subtree, limits, on_varbind, may_send)
        answered = answered or got
        if stop is not None:
            break  # later subtrees are not reached

    if rows:
        if stop is None:
            return result(Outcome.OK, True)
        return result(Outcome.PARTIAL, False, error_category=stop.category)
    if stop is not None:
        if stop.category == "timeout" and not answered:
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


async def get(
    transport: Transport,
    target: AuthorizedTarget,
    oids: Sequence[Oid],
    limits: SnmpLimits,
    budget: int | BudgetPool | None = None,
    extra: int = 0,
) -> GetResult:
    started_at, start = datetime.now(UTC), time.monotonic()
    t = _Session(transport, target, limits, as_pool(budget), extra)
    try:
        return await _get(t, oids, started_at, start)
    finally:
        t.close()


async def _get(t: _Session, oids: Sequence[Oid], started_at: datetime, start: float) -> GetResult:
    def done(outcome: Outcome | None, **extra: object) -> GetResult:
        return GetResult(
            outcome=outcome,
            request_count=t.datagrams,
            budget_used=t.budget_used,
            started_at=started_at,
            duration_ms=round((time.monotonic() - start) * 1000),
            **extra,
        )

    if not t.covers(1):
        return done(None)  # nothing sent, nothing to record
    response = await t.get(list(oids))
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

    - One request in flight per device: a lock per address and port, held
      for the whole operation.
    - At most ``max_devices`` devices at a time.
    - The run's credential, resolved by identifier when a device session
      opens and released when it ends.

    ``endpoint_for`` and ``v3_context`` exist for tests only (design D3); the
    composition roots never pass them. The scope is always checked on the
    target's logical address, before any mapping.
    """

    def __init__(
        self,
        transport_factory: TransportFactory,
        resolver: CredentialSource,
        limits: SnmpLimits | None = None,
        endpoint_for: EndpointFor | None = None,
        v3_context: str = "",
    ) -> None:
        self.limits = limits or SnmpLimits()
        self._transport_factory = transport_factory
        self._resolver = resolver
        self._endpoint_for = endpoint_for
        self._v3_context = v3_context
        self._devices = asyncio.Semaphore(self.limits.max_devices)
        self._locks: dict[tuple[str, int], asyncio.Lock] = {}

    @asynccontextmanager
    async def _transport(self, target: AuthorizedTarget) -> AsyncIterator[tuple[Transport, int]]:
        if not isinstance(target, AuthorizedTarget):
            raise TypeError("the SNMP client accepts only targets authorised by a scope policy")
        lock = self._locks.setdefault(target.device_key, asyncio.Lock())
        async with lock, self._devices:
            # Raises CredentialUnreadable before any datagram if it cannot be used.
            credential = await self._resolver.resolve(target.credential_id)
            try:
                address = str(target.address)
                if self._endpoint_for is None:
                    host, port = address, target.port
                else:
                    host, port = self._endpoint_for(address, target.port)
                endpoint = Endpoint(host, port, credential, self._v3_context)
                # One extra datagram per SNMPv3 call: the library's engine discovery.
                extra = 1 if isinstance(credential, SnmpV3Credential) else 0
                async with self._transport_factory(endpoint, self.limits) as transport:
                    yield transport, extra
            finally:
                self._resolver.release(credential)

    async def get(
        self,
        target: AuthorizedTarget,
        oids: Sequence[Oid],
        budget: int | BudgetPool | None = None,
    ) -> GetResult:
        async with self._transport(target) as (transport, extra):
            return await get(transport, target, oids, self.limits, budget, extra)

    async def walk_table(
        self,
        target: AuthorizedTarget,
        table: TableSpec,
        columns: Sequence[str] | None = None,
        budget: int | BudgetPool | None = None,
    ) -> TableResult:
        async with self._transport(target) as (transport, extra):
            return await walk_table(transport, target, table, columns, self.limits, budget, extra)
