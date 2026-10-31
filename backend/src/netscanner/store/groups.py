# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Provenance groups: generated columns, check constraints and foreign keys (design D1, D4).

A group is the set of columns ``<g>_origin``, ``<g>_method``, ``<g>_evidence``,
``<g>_first_seen_at``, ``<g>_first_query_id``, ``<g>_last_seen_at``,
``<g>_last_query_id``, ``<g>_last_complete_query_id`` and ``<g>_carried``;
tables with a single group use the names without prefix. Every table that
stores observations gets its groups from :func:`provenance_group`, so none can
forget a constraint.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKeyConstraint,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.schema import SchemaItem

PROVENANCE_SUFFIXES = (
    "origin",
    "method",
    "evidence",
    "first_seen_at",
    "first_query_id",
    "last_seen_at",
    "last_query_id",
    "last_complete_query_id",
    "carried",
)
# Columns that are either all set (group present) or all empty (group never stored).
_CORE = ("origin", "first_seen_at", "first_query_id", "last_seen_at", "last_query_id")


@dataclass(frozen=True)
class GroupSpec:
    """A provenance group of a table and the value columns it covers."""

    table: str
    name: str
    fields: tuple[str, ...]
    prefixed: bool = True
    required: bool = False

    def col(self, suffix: str) -> str:
        return f"{self.name}_{suffix}" if self.prefixed else suffix


def provenance_group(spec: GroupSpec, device_column: str = "device_id") -> list[SchemaItem]:
    """Columns and constraints of one group, to pass to ``Table(...)``.

    ``device_column`` is the column holding the device of the row; the
    composite foreign keys ``(<g>_*_query_id, device_column)`` reference the
    unique ``(id, device_id)`` of ``snmp_queries``, so a datum can only point
    to queries of its own device.
    """
    c = spec.col
    nullable = not spec.required
    tag = spec.name
    items: list[SchemaItem] = [
        Column(c("origin"), String(16), nullable=nullable),
        Column(c("method"), String(64)),
        # None must be SQL NULL, not the JSON value null, for the constraints to hold.
        Column(c("evidence"), JSONB(none_as_null=True)),
        Column(c("first_seen_at"), DateTime(timezone=True), nullable=nullable),
        Column(c("first_query_id"), BigInteger, nullable=nullable),
        Column(c("last_seen_at"), DateTime(timezone=True), nullable=nullable),
        Column(c("last_query_id"), BigInteger, nullable=nullable),
        Column(c("last_complete_query_id"), BigInteger),
        Column(c("carried"), JSONB, nullable=False, server_default=text("'{}'::jsonb")),
        CheckConstraint(f"{c('origin')} IN ('observed', 'inferred')", name=f"{tag}_origin"),
        CheckConstraint(
            f"num_nulls({', '.join(c(s) for s in _CORE)}) = 0 OR "
            f"(num_nulls({', '.join(c(s) for s in (*_CORE, 'method', 'evidence'))}) = 7 "
            f"AND {c('last_complete_query_id')} IS NULL)",
            name=f"{tag}_all_or_none",
        ),
        CheckConstraint(
            f"{c('origin')} <> 'inferred' OR ({c('method')} IS NOT NULL AND "
            f"{c('evidence')} IS NOT NULL AND "
            f"jsonb_path_exists({c('evidence')}, '$.inputs[*].snapshot'))",
            name=f"{tag}_inferred",
        ),
        CheckConstraint(
            f"{c('evidence')} IS NULL OR {c('method')} IS NOT NULL", name=f"{tag}_evidence_method"
        ),
        CheckConstraint(f"{c('last_seen_at')} >= {c('first_seen_at')}", name=f"{tag}_seen_order"),
        CheckConstraint(f"jsonb_typeof({c('carried')}) = 'object'", name=f"{tag}_carried"),
    ]
    for kind in ("first", "last", "last_complete"):
        items.append(
            ForeignKeyConstraint(
                [c(f"{kind}_query_id"), device_column],
                ["snmp_queries.id", "snmp_queries.device_id"],
                name=f"fk_{spec.table}_{tag}_{kind}_query",
                # devices and snmp_queries reference each other.
                use_alter=spec.table == "devices",
            )
        )
    return items
