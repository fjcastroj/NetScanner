# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Upsert rules of design D9, applied per provenance group.

Input contract: a field omitted from ``GroupUpdate.values`` was not retrieved;
an explicit ``None`` means absent, and only confirms the absence when the
query is complete.

Queries are ordered by ``(started_at, id)``. A query **sets** a field when it
retrieves its value or confirms its absence, unless precedence protects the
field: an inferred update never changes a field whose effective origin is
observed. A field's effective origin is the one in its ``carried`` entry if it
has one, otherwise the group's. For each group:

- a group is created only by an update that confirms a field (a value, or
  ``None`` in a complete query) or the row; otherwise an optional group stays
  empty and a required one is rejected, as is a new row with no group;
- an update that sets no field leaves the group untouched, unless it
  confirms the row (``confirms_row``): a row returned again by a query renews
  the group's observation (last seen, last query, last complete query) and
  carries every field as usual. An inferred update fully blocked by
  precedence never changes anything;
- a query earlier than the stored first query moves ``first_seen_at`` and
  ``first_query_id`` together;
- a query later than or equal to the stored last query moves ``last_seen_at``,
  ``last_query_id``, origin, method, evidence and the fields it sets; older
  queries leave values unchanged;
- a complete query later than or equal to the stored last complete query
  replaces ``last_complete_query_id``.

Invariant of ``<g>_carried``: a field without an entry has the group's last
query, origin, method and evidence as provenance and holds a value or a
confirmed absence. When the group's last query moves, every field the update
does not set gets an entry with the full provenance it had
(``{query_id, seen_at, origin, method, evidence}``) unless it already has one.
A field never retrieved is ``{"retrieved": false}``. A field set again loses
its entry.

Rows are inserted or locked with ``INSERT ... ON CONFLICT DO UPDATE`` and the
merge is computed on the locked row, so concurrent writers are serialised and
the final state does not depend on the order of storage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Table, literal_column, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncConnection

from netscanner.store.errors import StoreError
from netscanner.store.evidence import MAX_EVIDENCE_BYTES, Evidence, EvidenceError, validate_evidence
from netscanner.store.groups import GroupSpec
from netscanner.store.registry import Origin
from netscanner.store.runs import QueryInfo, get_query

NOT_RETRIEVED_ENTRY = {"retrieved": False}


@dataclass(frozen=True)
class GroupUpdate:
    """New values of one group from one query.

    ``values`` holds the fields the query covers: a value when reported,
    ``None`` when reported absent. Fields of the group not in ``values`` were
    not retrieved. ``confirms_row`` is set only by callers storing a row the
    query returned: the row is observed again even if no field is set.
    """

    spec: GroupSpec
    values: dict[str, Any]
    origin: Origin = Origin.OBSERVED
    method: str | None = None
    evidence: Evidence | None = None
    confirms_row: bool = False

    def __post_init__(self) -> None:
        unknown = set(self.values) - set(self.spec.fields)
        if unknown:
            raise StoreError(f"fields {sorted(unknown)} are not in group {self.spec.name}")
        if self.origin is Origin.INFERRED and (self.method is None or self.evidence is None):
            raise StoreError("inferred data needs a method and evidence")
        if self.evidence is not None:
            if self.method != self.evidence.method:
                raise StoreError("the evidence names another method")
            validate_evidence(self.evidence, self.origin)
        elif self.method is not None and self.origin is Origin.OBSERVED:
            raise StoreError("an observed derivation needs its sources")

    def evidence_json(self) -> dict | None:
        return self.evidence.to_json() if self.evidence else None


def _order(seen_at: datetime, query_id: int) -> tuple[datetime, int]:
    return (seen_at, query_id)


def _confirms(update_: GroupUpdate, name: str, q: QueryInfo) -> bool:
    """Whether the query retrieves the field's value or confirms its absence."""
    return name in update_.values and (update_.values[name] is not None or q.complete)


def initializes(update_: GroupUpdate, q: QueryInfo) -> bool:
    """Whether an update may create its group: it confirms at least one field
    (a value, or ``None`` in a complete query) or confirms the row."""
    return update_.confirms_row or any(_confirms(update_, n, q) for n in update_.spec.fields)


def effective_origin(stored: Any, spec: GroupSpec, name: str) -> str | None:
    """Origin of one field: its carried entry's, otherwise the group's."""
    entry = stored[spec.col("carried")].get(name)
    if entry is not None:
        return entry.get("origin")  # None for a field never retrieved
    return stored[spec.col("origin")]


def _sets(stored: Any, update_: GroupUpdate, q: QueryInfo) -> tuple[list[str], bool]:
    """Fields the update sets after observed/inferred precedence, and whether
    precedence blocked every field it would otherwise set."""
    names = [n for n in update_.spec.fields if _confirms(update_, n, q)]
    if update_.origin is not Origin.INFERRED:
        return names, False
    allowed = [n for n in names if effective_origin(stored, update_.spec, n) != Origin.OBSERVED]
    return allowed, bool(names) and not allowed


def check_evidence_size(evidence: dict | None, carried: dict[str, Any]) -> None:
    """The group's evidence and every evidence in ``carried`` share one size limit."""
    documents = [evidence] + [e.get("evidence") for e in carried.values()]
    size = sum(len(json.dumps(d, separators=(",", ":")).encode()) for d in documents if d)
    if size > MAX_EVIDENCE_BYTES:
        raise EvidenceError(
            f"evidence of the group and its carried fields is {size} bytes; "
            f"the limit is {MAX_EVIDENCE_BYTES}"
        )


def _fresh(update_: GroupUpdate, q: QueryInfo) -> dict[str, Any]:
    c = update_.spec.col
    evidence = update_.evidence_json()
    # Fields never retrieved are unknown, not absent.
    carried = {
        name: dict(NOT_RETRIEVED_ENTRY)
        for name in update_.spec.fields
        if not _confirms(update_, name, q)
    }
    check_evidence_size(evidence, carried)
    return {
        **update_.values,
        c("origin"): str(update_.origin),
        c("method"): update_.method,
        c("evidence"): evidence,
        c("first_seen_at"): q.started_at,
        c("first_query_id"): q.id,
        c("last_seen_at"): q.started_at,
        c("last_query_id"): q.id,
        c("last_complete_query_id"): q.id if q.complete else None,
        c("carried"): carried,
    }


async def merge_group(
    conn: AsyncConnection, stored: Any, update_: GroupUpdate, q: QueryInfo
) -> dict[str, Any]:
    """Column changes that store ``update_`` on the locked row ``stored``."""
    c = update_.spec.col
    if stored[c("origin")] is None:
        if initializes(update_, q):
            return _fresh(update_, q)
        if update_.spec.required:
            raise StoreError(f"group {update_.spec.name} needs an observation to exist")
        return {}  # the optional group stays empty: nothing was observed
    setting, blocked = _sets(stored, update_, q)
    if not setting and (blocked or not update_.confirms_row):
        # Fully blocked by precedence, or nothing set and no row confirmed:
        # nothing changes, dates included.
        return {}
    changes: dict[str, Any] = {}
    key = q.order
    if key < _order(stored[c("first_seen_at")], stored[c("first_query_id")]):
        changes[c("first_seen_at")] = q.started_at
        changes[c("first_query_id")] = q.id
    last_id = stored[c("last_query_id")]
    if key >= _order(stored[c("last_seen_at")], last_id):
        carried = dict(stored[c("carried")])
        moved = last_id != q.id
        for name in update_.spec.fields:
            if name in setting:
                changes[name] = update_.values[name]
                carried.pop(name, None)
            elif name not in carried and moved:
                # Kept from the previous last query, with the full provenance
                # it had there; an existing entry is left as it is.
                carried[name] = {
                    "query_id": last_id,
                    "seen_at": stored[c("last_seen_at")].isoformat(),
                    "origin": stored[c("origin")],
                    "method": stored[c("method")],
                    "evidence": stored[c("evidence")],
                }
        evidence = update_.evidence_json()
        check_evidence_size(evidence, carried)
        changes.update(
            {
                c("origin"): str(update_.origin),
                c("method"): update_.method,
                c("evidence"): evidence,
                c("last_seen_at"): q.started_at,
                c("last_query_id"): q.id,
                c("carried"): carried,
            }
        )
    if q.complete:
        current = stored[c("last_complete_query_id")]
        if current is None or key >= (await get_query(conn, current)).order:
            changes[c("last_complete_query_id")] = q.id
    return changes


async def lock_row(conn: AsyncConnection, table: Table, row_id: int) -> Any:
    stmt = select(table).where(table.c.id == row_id).with_for_update()
    return (await conn.execute(stmt)).one()._mapping


async def apply_updates(
    conn: AsyncConnection, table: Table, row_id: int, updates: list[GroupUpdate], q: QueryInfo
) -> bool:
    """Merge ``updates`` into a stored row; return whether anything changed."""
    stored = await lock_row(conn, table, row_id)
    changes: dict[str, Any] = {}
    for update_ in updates:
        changes.update(await merge_group(conn, stored, update_, q))
    if changes:
        await conn.execute(update(table).where(table.c.id == row_id).values(**changes))
    return bool(changes)


async def upsert(
    conn: AsyncConnection,
    table: Table,
    key: dict[str, Any],
    updates: list[GroupUpdate],
    q: QueryInfo,
) -> int:
    """Insert the row of ``key`` with ``updates`` or merge them into the stored row.

    A new row initializes only the groups whose update confirms a field or the
    row. It is rejected when a required group would not be initialized, or
    when no group at all would be: no observation is invented.
    """
    fresh: dict[str, Any] = dict(key)
    creatable = True
    for update_ in updates:
        if initializes(update_, q):
            fresh.update(_fresh(update_, q))
        elif update_.spec.required:
            creatable = False
    if not creatable or len(fresh) == len(key):
        # Such an update can only merge into a row that already exists.
        stmt = select(table.c.id).where(*(table.c[k] == v for k, v in key.items()))
        row_id = await conn.scalar(stmt.with_for_update())
        if row_id is None:
            raise StoreError(f"a new {table.name} row needs an observation of its groups")
        await apply_updates(conn, table, row_id, updates, q)
        return row_id
    stmt = insert(table).values(**fresh)
    first = next(iter(key))
    # The no-op update takes the row lock; xmax = 0 only for a row just inserted.
    stmt = stmt.on_conflict_do_update(index_elements=list(key), set_={first: stmt.excluded[first]})
    row = (
        await conn.execute(stmt.returning(table.c.id, literal_column("xmax = 0").label("inserted")))
    ).one()
    if not row.inserted:
        await apply_updates(conn, table, row.id, updates, q)
    return row.id
