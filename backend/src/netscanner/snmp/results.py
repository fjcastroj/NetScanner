# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Values and results of the SNMP client (design D1).

Targets are :class:`netscanner.scope.AuthorizedTarget`, created only by the
run's scope policy (add-discovery-and-basic-inventory, design D2).

Results report only what was received. For a complete walk a requested column
missing from a row is reported absent (``None``); for an incomplete walk the
columns not received are not reported, so callers can apply the store's
contract (omitted means not retrieved, ``None`` means absent only when the
query is complete).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from netscanner.scope.policy import AuthorizedTarget
from netscanner.snmp.tables import Oid, TableSpec
from netscanner.store.registry import Outcome

if TYPE_CHECKING:
    from netscanner.snmp.walker import BudgetPool


class SnmpException(StrEnum):
    """SNMPv2 exception values returned in place of a value."""

    NO_SUCH_OBJECT = "noSuchObject"
    NO_SUCH_INSTANCE = "noSuchInstance"
    END_OF_MIB_VIEW = "endOfMibView"


# OCTET STRING, Opaque and BITS as bytes; IpAddress and OIDs as text; numbers as int.
SnmpValue = int | bytes | str


@dataclass(frozen=True)
class GetResult:
    # None: the datagram budget did not cover the request, so nothing was sent.
    outcome: Outcome | None
    values: dict[Oid, SnmpValue] = field(default_factory=dict)
    indicators: dict[Oid, SnmpException] = field(default_factory=dict)
    error_category: str | None = None
    # Datagrams sent: every attempt, retries included (reported datagrams).
    request_count: int = 0
    # Budget consumed: request_count plus one per SNMPv3 call (engine discovery).
    budget_used: int = 0
    started_at: datetime | None = None
    duration_ms: int = 0

    @property
    def sent(self) -> bool:
        return self.outcome is not None


@dataclass(frozen=True)
class TableResult:
    mib_object: str
    # None: the datagram budget did not cover the walk, so nothing was sent.
    outcome: Outcome | None
    complete: bool
    columns: tuple[str, ...]
    rows: dict[Oid, dict[str, SnmpValue]] = field(default_factory=dict)
    indicator: str | None = None
    error_category: str | None = None
    # Datagrams sent: every attempt, retries and the probe included (reported).
    request_count: int = 0
    # Budget consumed: request_count plus one per SNMPv3 call (engine discovery).
    budget_used: int = 0
    started_at: datetime | None = None
    duration_ms: int = 0

    @property
    def sent(self) -> bool:
        return self.outcome is not None

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def reported(self, index: Oid) -> dict[str, SnmpValue | None]:
        """The fields of one row in the store's contract.

        Complete walk: every requested column, ``None`` when the row lacks it.
        Incomplete walk: only the columns received.
        """
        row = self.rows.get(index, {})
        if self.complete:
            return {column: row.get(column) for column in self.columns}
        return dict(row)


class SnmpClient(Protocol):
    """The only way NetScanner talks to devices (read-only by construction)."""

    async def get(
        self, target: AuthorizedTarget, oids: Sequence[Oid], budget: int | BudgetPool | None = None
    ) -> GetResult: ...

    async def walk_table(
        self,
        target: AuthorizedTarget,
        table: TableSpec,
        columns: Sequence[str] | None = None,
        budget: int | BudgetPool | None = None,
    ) -> TableResult: ...
