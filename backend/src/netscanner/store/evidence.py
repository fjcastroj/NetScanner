# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Sources and evidence format (design D5, D10).

One JSONB document per group: the method, its version and the inputs it used.
Observed derivations list references only; inferred data needs at least one
input with a ``snapshot`` of the values used, so the inference can still be
explained after the referenced records change.
"""

from __future__ import annotations

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from netscanner.store.errors import StoreError
from netscanner.store.registry import Origin, check_mib_object, get_method

MAX_EVIDENCE_BYTES = 16 * 1024
RECORD_TABLES = frozenset(
    {"devices", "device_addresses", "interfaces", "neighbor_entries", "ip_mac_entries"}
)

# Snapshot values are the fragments a method used, never whole documents.
SnapshotScalar = int | float | bool | Annotated[str, StringConstraints(max_length=1024)] | None
SnapshotValue = SnapshotScalar | Annotated[list[SnapshotScalar], Field(max_length=32)]
Snapshot = Annotated[dict[str, SnapshotValue], Field(min_length=1, max_length=32)]


class EvidenceError(StoreError):
    """Sources or evidence that do not follow the format or the rules."""


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int = Field(gt=0)
    snapshot: Snapshot | None = None


class QueryInput(_Input):
    kind: Literal["query"] = "query"
    mib_object: str

    @field_validator("mib_object")
    @classmethod
    def _known_mib_object(cls, value: str) -> str:
        return check_mib_object(value)


class RecordInput(_Input):
    kind: Literal["record"] = "record"
    table: str

    @field_validator("table")
    @classmethod
    def _known_table(cls, value: str) -> str:
        if value not in RECORD_TABLES:
            raise ValueError(f"unknown table: {value!r}")
        return value


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str
    method_version: int = Field(gt=0)
    inputs: list[Annotated[QueryInput | RecordInput, Field(discriminator="kind")]] = Field(
        min_length=1, max_length=64
    )

    @field_validator("method")
    @classmethod
    def _known_method(cls, value: str) -> str:
        get_method(value)
        return value

    def has_snapshot(self) -> bool:
        return any(i.snapshot is not None for i in self.inputs)

    def to_json(self) -> dict:
        return self.model_dump(mode="json", exclude_none=True)


def build_evidence(method: str, origin: Origin, inputs: list[QueryInput | RecordInput]) -> Evidence:
    """Validated evidence for ``method`` with the registered version."""
    return validate_evidence(
        {"method": method, "method_version": get_method(method).version, "inputs": inputs},
        origin,
    )


def validate_evidence(value: object, origin: Origin) -> Evidence:
    """Validate format, method, origin rules and size; raise ``EvidenceError``."""
    try:
        evidence = value if isinstance(value, Evidence) else Evidence.model_validate(value)
    except ValueError as exc:
        # Only error types and locations: inputs may hold fragments of device data.
        kinds = sorted({".".join(map(str, e["loc"])) or e["type"] for e in _errors(exc)})
        raise EvidenceError(f"invalid evidence format: {', '.join(kinds)}") from None
    method = get_method(evidence.method)
    if method.origin is not origin:
        raise EvidenceError(f"method {method.name!r} is {method.origin}, not {origin}")
    if evidence.method_version != method.version:
        raise EvidenceError(f"method {method.name!r} is at version {method.version}")
    if origin is Origin.OBSERVED and evidence.has_snapshot():
        raise EvidenceError("sources of an observed derivation are references only")
    if origin is Origin.INFERRED and not evidence.has_snapshot():
        raise EvidenceError("inferred data needs at least one input with a snapshot")
    size = len(json.dumps(evidence.to_json(), separators=(",", ":")).encode())
    if size > MAX_EVIDENCE_BYTES:
        raise EvidenceError(f"evidence is {size} bytes; the limit is {MAX_EVIDENCE_BYTES}")
    return evidence


def _errors(exc: ValueError) -> list[dict]:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        return errors(include_input=False, include_url=False, include_context=False)
    return [{"loc": (), "type": "value_error"}]
