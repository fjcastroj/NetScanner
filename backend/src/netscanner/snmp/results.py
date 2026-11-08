# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Targets, values and results of the SNMP client (design D1).

Results report only what was received. For a complete walk a requested column
missing from a row is reported absent (``None``); for an incomplete walk the
columns not received are not reported, so callers can apply the store's
contract (omitted means not retrieved, ``None`` means absent only when the
query is complete).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from netscanner.snmp.credentials import SnmpV2cCredential, SnmpV3Credential, parse_credential
from netscanner.snmp.tables import Oid, TableSpec
from netscanner.store.registry import Outcome


class SnmpException(StrEnum):
    """SNMPv2 exception values returned in place of a value."""

    NO_SUCH_OBJECT = "noSuchObject"
    NO_SUCH_INSTANCE = "noSuchInstance"
    END_OF_MIB_VIEW = "endOfMibView"


# OCTET STRING, Opaque and BITS as bytes; IpAddress and OIDs as text; numbers as int.
SnmpValue = int | bytes | str


@dataclass(frozen=True)
class Target:
    """A device to query: address, port, credential and SNMPv3 context."""

    address: str
    credential: SnmpV2cCredential | SnmpV3Credential
    port: int = 161
    context: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", str(ipaddress.ip_address(self.address)))
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        object.__setattr__(self, "credential", parse_credential(self.credential))

    @property
    def device_key(self) -> tuple[str, int]:
        return (self.address, self.port)

    def __repr__(self) -> str:  # no credential, not even masked
        return f"Target({self.address}:{self.port}, SNMPv{self.credential.version})"

    __str__ = __repr__


@dataclass(frozen=True)
class GetResult:
    outcome: Outcome
    values: dict[Oid, SnmpValue] = field(default_factory=dict)
    indicators: dict[Oid, SnmpException] = field(default_factory=dict)
    error_category: str | None = None
    request_count: int = 0
    started_at: datetime | None = None
    duration_ms: int = 0


@dataclass(frozen=True)
class TableResult:
    mib_object: str
    outcome: Outcome
    complete: bool
    columns: tuple[str, ...]
    rows: dict[Oid, dict[str, SnmpValue]] = field(default_factory=dict)
    indicator: str | None = None
    error_category: str | None = None
    request_count: int = 0
    started_at: datetime | None = None
    duration_ms: int = 0

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

    async def get(self, target: Target, oids: Sequence[Oid]) -> GetResult: ...

    async def walk_table(
        self, target: Target, table: TableSpec, columns: Sequence[str] | None = None
    ) -> TableResult: ...
