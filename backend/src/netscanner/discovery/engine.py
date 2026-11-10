# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Discovery run engine (design D8; device-discovery spec, RF-03 to RF-05).

Breadth first, one depth level at a time; level 0 is the seeds. Each
candidate address is checked in this order:
1. already in this run (``already_known``);
2. the scope policy (``special_address``, ``excluded``, ``out_of_scope``);
3. depth (``max_depth``);
4. a limit reached (``limit_reached``);
5. the system group query (``no_response``, ``auth_failed``, ``query_error``).

Devices of a level run concurrently under the client's device limit and
share the run's datagram budget pool. Per device the tables follow the order
of D8, with their fallbacks; an exception while processing one device is
isolated and the run continues. The run summary lists it with the target
address, the stage it happened in and the exception's class name only: its
message, arguments and traceback may carry values read from the device and
are never stored nor logged. Unreadable credentials, scope violations and
database failures are not isolated: they end the run (design D7).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from netscanner.credential_store import CredentialUnreadable
from netscanner.discovery import cdp, mapping
from netscanner.scope import AuthorizedTarget, Rejection, ScopePolicy
from netscanner.scope.policy import canonical
from netscanner.snmp import (
    BudgetPool,
    GetResult,
    ScopeViolation,
    SnmpClient,
    TableResult,
    get_table,
)
from netscanner.store.identity import Chassis
from netscanner.store.registry import Outcome
from netscanner.store.runs import RunLimits, RunParameters
from netscanner.store.service import Store

log = logging.getLogger("netscanner.discovery")

# Outcomes after which the alternative table is queried (design D8).
FALLBACK_OUTCOMES = (Outcome.NOT_AVAILABLE, Outcome.EMPTY)
# Outcomes whose rows are stored; the others store nothing (design D9).
STORED_OUTCOMES = (Outcome.OK, Outcome.PARTIAL)
# Failures that end the run instead of one device.
FATAL = (CredentialUnreadable, ScopeViolation, SQLAlchemyError)
SNMP_VERSIONS = {"v2c": "2c", "v3": "3"}
IP_MAC_INVALID = 2
SYSTEM = "SNMPv2-MIB::system"
DATAGRAM_NOTE = (
    "reported_datagrams counts the SNMP requests the client sent and observed, retries and "
    "probes included; budget_consumed adds one datagram per SNMPv3 call for the library's "
    "engine discovery, which the client cannot observe, so the limit covers the real traffic"
)


@dataclass(frozen=True)
class Candidate:
    address: str
    reached_via: str
    depth: int
    found_from: int | None = None


@dataclass
class _Found:
    """What one reached device contributes: its own addresses and next candidates."""

    own_addresses: set[str] = field(default_factory=set)
    candidates: list[tuple[str, str]] = field(default_factory=list)  # (address, way)


@dataclass
class _DeviceState:
    """Progress of one device: its identifier once resolved and the current stage."""

    device_id: int | None = None
    stage: str = SYSTEM


class _Stop(Exception):
    """The datagram budget ended: the device's remaining tables are not queried."""


class DiscoveryEngine:
    def __init__(
        self,
        store: Store,
        client: SnmpClient,
        run_id: int,
        params: RunParameters,
        policy: ScopePolicy,
        limits: RunLimits,
        credential_version: str,
    ) -> None:
        self.store = store
        self.client = client
        self.run_id = run_id
        self.params = params
        self.policy = policy
        self.limits = limits
        self.max_depth = params.max_depth if params.max_depth is not None else 0
        self.snmp_version = SNMP_VERSIONS.get(credential_version, credential_version)
        self.pool = BudgetPool(limits.max_datagrams)
        self.reported_datagrams = 0
        self.candidates: set[str] = set()  # recorded in run_devices
        self.not_recorded: set[str] = set()  # distinct addresses beyond max_candidates
        self.reached_addresses: set[str] = set()  # read from devices reached in this run
        self.devices_queried = 0
        self.limits_reached: list[str] = []
        self.device_errors: list[dict[str, str]] = []

    # --- run ----------------------------------------------------------------

    async def run(self) -> dict[str, Any]:
        level = [Candidate(str(seed), "seed", 0) for seed in self.params.seeds]
        depth = 0
        while level:
            queued = []
            for candidate in level:
                item = await self._register(candidate)
                if item is not None:
                    queued.append(item)
            results = await _all(self._device(item) for item in queued)
            level = []
            for result in results:
                if result is None:
                    continue
                device_id, found = result
                self.reached_addresses |= found.own_addresses
                level += [Candidate(a, way, depth + 1, device_id) for a, way in found.candidates]
            depth += 1
        return self.summary()

    def summary(self) -> dict[str, Any]:
        return {
            "limits_reached": list(self.limits_reached),
            "candidates_not_recorded": len(self.not_recorded),
            "devices_queried": self.devices_queried,
            "reported_datagrams": self.reported_datagrams,
            "budget_consumed": self.pool.consumed,
            "datagrams_note": DATAGRAM_NOTE,
            "device_errors": [dict(e) for e in self.device_errors],
        }

    # --- candidates -----------------------------------------------------------

    def _limit(self, name: str) -> None:
        if name not in self.limits_reached:
            self.limits_reached.append(name)

    async def _record(self, c: Candidate, **kwargs: Any) -> None:
        await self.store.record_run_device(
            self.run_id,
            c.address,
            c.reached_via,  # type: ignore[arg-type]
            c.depth,
            found_from_device_id=c.found_from,
            **kwargs,
        )

    async def _register(self, c: Candidate) -> tuple[Candidate, AuthorizedTarget] | None:
        """Record a candidate with its reason; return it with its target if it may be queried."""
        address = str(canonical(c.address))
        c = Candidate(address, c.reached_via, c.depth, c.found_from)
        if address in self.candidates:
            return None  # already a target of this run: its first record stays
        if len(self.candidates) >= self.limits.max_candidates:
            self.not_recorded.add(address)
            self._limit("max_candidates")
            return None
        self.candidates.add(address)
        if address in self.reached_addresses:
            await self._record(c, skip_reason="already_known")
            return None
        decision = self.policy.authorize(address)
        if isinstance(decision, Rejection):
            await self._record(c, skip_reason=decision.reason)
            return None
        if c.depth > self.max_depth:
            await self._record(c, skip_reason="max_depth")
            return None
        if any(name != "max_candidates" for name in self.limits_reached):
            await self._record(c, skip_reason="limit_reached")
            return None
        await self._record(c)
        return c, decision

    # --- one device -------------------------------------------------------------

    async def _device(self, item: tuple[Candidate, AuthorizedTarget]) -> tuple[int, _Found] | None:
        c, target = item
        if self.devices_queried >= self.limits.max_devices:
            self._limit("max_devices")
            await self._record(c, skip_reason="limit_reached")
            return None
        self.devices_queried += 1
        oids = list(mapping.SYSTEM_OIDS.values())
        try:
            system = await self.client.get(target, oids, budget=self.pool)
        except FATAL:
            raise
        except Exception as exc:
            # Client failure on the system group: query_error, category on the query.
            query_id = await self.store.record_query(self._failed_system(c.address), error=exc)
            await self._record(c, first_query_id=query_id, skip_reason="query_error")
            return None
        self.reported_datagrams += system.request_count
        if not system.sent:
            self.devices_queried -= 1  # its first request was not sent
            self._limit("max_datagrams")
            await self._record(c, skip_reason="limit_reached")
            return None
        system_q = await self._query(c.address, None, SYSTEM, "get", system)
        if system.outcome is not Outcome.OK:
            await self._record(c, first_query_id=system_q, skip_reason=_system_reason(system))
            return None
        await self._record(c, first_query_id=system_q, answered=True)
        found = _Found(own_addresses={c.address})
        state = _DeviceState()
        try:
            await self._collect(c, target, system, system_q, found, state)
        except FATAL:
            raise
        except _Stop:
            pass
        except Exception as exc:
            # Isolated: the device keeps what was stored and the run continues.
            # Only the class name is kept: the message may carry device values.
            error = {
                "target_address": c.address,
                "stage": state.stage,
                "exception": type(exc).__name__,
            }
            self.device_errors.append(error)
            log.warning(
                "discovery of %s stopped at %s (%s)", c.address, state.stage, error["exception"]
            )
        return None if state.device_id is None else (state.device_id, found)

    def _failed_system(self, address: str) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target_address": address,
            "mib_object": SYSTEM,
            "operation": "get",
            "snmp_version": self.snmp_version,
            "outcome": "error",
            "request_count": 0,
            "started_at": datetime.now(UTC),
            "duration_ms": 0,
        }

    async def _query(
        self,
        address: str,
        device_id: int | None,
        mib_object: str,
        operation: str,
        result: TableResult | GetResult,
    ) -> int:
        rows = result.row_count if isinstance(result, TableResult) else len(result.values)
        record: dict[str, Any] = {
            "run_id": self.run_id,
            "target_address": address,
            "device_id": device_id,
            "mib_object": mib_object,
            "operation": operation,
            "snmp_version": self.snmp_version,
            "outcome": str(result.outcome),
            "row_count": 0 if result.outcome is Outcome.NO_RESPONSE else rows,
            "request_count": result.request_count,
            "started_at": result.started_at,
            "duration_ms": result.duration_ms,
        }
        if isinstance(result, TableResult) and result.outcome in FALLBACK_OUTCOMES:
            record["indicator"] = result.indicator
        if result.outcome in (Outcome.ERROR, Outcome.PARTIAL):
            record["error_category"] = result.error_category
        return await self.store.record_query(record)

    async def _walk(
        self,
        c: Candidate,
        target: AuthorizedTarget,
        state: _DeviceState,
        mib_object: str,
    ) -> tuple[TableResult, int]:
        state.stage = mib_object
        device_id = state.device_id
        table = get_table(mib_object)
        result = await self.client.walk_table(target, table, budget=self.pool)
        self.reported_datagrams += result.request_count
        if not result.sent:
            self._limit("max_datagrams")
            raise _Stop
        return result, await self._query(c.address, device_id, mib_object, "walk", result)

    def _after(self, result: TableResult) -> None:
        """A walk cut by the budget stops the device's remaining tables (design D6)."""
        if result.error_category == "request_limit":
            self._limit("max_datagrams")
            raise _Stop

    async def _collect(
        self,
        c: Candidate,
        target: AuthorizedTarget,
        system: GetResult,
        system_q: int,
        found: _Found,
        state: _DeviceState,
    ) -> None:
        store = self.store

        # System group and lldpLocalSystemData, then the device identity.
        lldp_local, lldp_q = await self._walk(c, target, state, "LLDP-MIB::lldpLocalSystemData")
        state.stage = "identification"
        row = mapping.system_row(system)
        chassis = (
            mapping.lldp_chassis(lldp_local) if lldp_local.outcome in STORED_OUTCOMES else None
        )
        if chassis is not None:
            resolution = await store.resolve_device(
                lldp_q, chassis=Chassis(*chassis), sys_object_id=row.get("sys_object_id")
            )
        else:
            resolution = await store.resolve_device(system_q)
        device = state.device_id = resolution.device_id
        await store.assign_device(self.run_id, c.address, device)
        state.stage = SYSTEM
        await store.store_system(system_q, device, row)
        self._after(lldp_local)

        async def stored(
            mib_object: str,
            store_fn: Callable[[int, int, list[dict]], Awaitable[Any]],
            rows_fn: Callable[[TableResult], Iterable[dict[str, Any]]],
        ) -> tuple[TableResult, int, list[dict[str, Any]]]:
            result, query_id = await self._walk(c, target, state, mib_object)
            rows = list(rows_fn(result)) if result.outcome in STORED_OUTCOMES else []
            if result.outcome in STORED_OUTCOMES:
                await store_fn(query_id, device, rows)
            self._after(result)
            return result, query_id, rows

        # Addresses: ipAddressTable; ipAddrTable if the first is not available or empty.
        result, _, rows = await stored(
            "IP-MIB::ipAddressTable", store.store_addresses, mapping.ip_address_table_rows
        )
        if result.outcome in FALLBACK_OUTCOMES:
            _, _, rows = await stored(
                "IP-MIB::ipAddrTable", store.store_addresses, mapping.ip_addr_table_rows
            )
        found.own_addresses |= {str(canonical(r["address"])) for r in rows}

        await stored("IF-MIB::ifTable", store.store_if_table, mapping.if_table_rows)
        await stored("IF-MIB::ifXTable", store.store_if_xtable, mapping.if_xtable_rows)

        # ENTITY-MIB model columns; not available or no chassis row: sysDescr inference.
        entity, entity_q = await self._walk(c, target, state, "ENTITY-MIB::entPhysicalTable")
        model = mapping.chassis_model(entity) if entity.outcome in STORED_OUTCOMES else None
        if model is not None:
            await store.store_model(entity_q, device, model)
        else:
            state.stage = "model_inference"
            await store.infer_model_from_sysdescr(device)
        self._after(entity)

        # LLDP: local ports, remote table, management addresses; the port mapping
        # applies to the remote entries, so it runs once they are stored.
        local_ports, local_q = await self._walk(c, target, state, "LLDP-MIB::lldpLocPortTable")
        self._after(local_ports)
        await stored("LLDP-MIB::lldpRemTable", store.store_neighbors, mapping.remote_rows)
        _, _, managed = await stored(
            "LLDP-MIB::lldpRemManAddrTable",
            store.store_neighbor_man_addresses,
            mapping.management_address_rows,
        )
        found.candidates += [(r["address"], "lldp") for r in managed]
        if local_ports.outcome in STORED_OUTCOMES:
            state.stage = "LLDP-MIB::lldpLocPortTable"
            ports = list(mapping.local_port_rows(local_ports))
            await store.map_local_ports(local_q, device, ports)

        # CDP cache (its own module).
        cache, _, _ = await stored(
            "CISCO-CDP-MIB::cdpCacheTable", store.store_neighbors, cdp.neighbor_rows
        )
        if cache.outcome in STORED_OUTCOMES:
            found.candidates += [(a, "cdp") for a in cdp.addresses(cache)]

        # IP-MAC: ipNetToPhysicalTable; ipNetToMediaTable if the first is not available or empty.
        result, _, rows = await stored(
            "IP-MIB::ipNetToPhysicalTable", store.store_ip_mac, mapping.ip_net_to_physical_rows
        )
        if result.outcome in FALLBACK_OUTCOMES:
            _, _, rows = await stored(
                "IP-MIB::ipNetToMediaTable", store.store_ip_mac, mapping.ip_net_to_media_rows
            )
        if self.params.follow_ip_mac:
            found.candidates += [
                (r["ip_address"], "ip-mac") for r in rows if r.get("entry_type") != IP_MAC_INVALID
            ]


def _system_reason(result: GetResult) -> str:
    if result.outcome is Outcome.NO_RESPONSE:
        return "no_response"
    if (result.error_category or "").startswith("v3_report:"):
        return "auth_failed"
    return "query_error"


async def _all(calls: Iterable[Awaitable[Any]]) -> list[Any]:
    """Run concurrently; the first fatal failure cancels the others and is raised."""
    try:
        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(call) for call in calls]  # type: ignore[arg-type]
    except BaseExceptionGroup as failed:
        raise failed.exceptions[0] from None
    return [task.result() for task in tasks]
