# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Storage of what the collector observes (network-observations spec, design D3, D9, D10).

Every function stores the rows of one query of one device. Rows are dicts:
a key with a value is reported, a key with ``None`` is reported absent, and a
missing key (or :data:`NOT_RETRIEVED`) was not retrieved. Each row is validated
on its own; invalid rows are counted in the query's ``rejected_count`` without
storing their values, and the rest of the batch is stored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    ValidationError,
    field_validator,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection

from netscanner.store import registry
from netscanner.store.errors import StoreError
from netscanner.store.evidence import QueryInput, RecordInput, build_evidence
from netscanner.store.merge import GroupUpdate, apply_updates, upsert
from netscanner.store.models import (
    ADDRESS_GROUP,
    DEVICE_GROUPS,
    IF_INDEX_MAX,
    INTERFACE_GROUPS,
    IP_MAC_GROUP,
    NEIGHBOR_GROUPS,
    device_addresses,
    devices,
    interfaces,
    ip_mac_entries,
    neighbor_entries,
)
from netscanner.store.registry import Origin, Outcome
from netscanner.store.runs import QueryInfo, add_rejected, get_query

SYSTEM, CHASSIS, VENDOR, MODEL = DEVICE_GROUPS
BASE, EXT, SPEED = INTERFACE_GROUPS
ENTRY, MAN_ADDR, LOCAL_MAP = NEIGHBOR_GROUPS

IF_SPEED_MAX = 4294967295  # ifSpeed saturates here; ifHighSpeed (Mbit/s) takes over.
# Every observation write holds this lock in shared mode; an evaluation
# snapshot takes it exclusively (design D11).
OBSERVATION_LOCK = 0x4E53_0001


class _NotRetrieved:
    def __repr__(self) -> str:
        return "NOT_RETRIEVED"


NOT_RETRIEVED: Any = _NotRetrieved()


@dataclass(frozen=True)
class StoreResult:
    stored: int = 0
    rejected: int = 0
    skipped: int = 0


async def observation_lock(conn: AsyncConnection) -> None:
    await conn.execute(select(func.pg_advisory_xact_lock_shared(OBSERVATION_LOCK)))


# --- Row models -------------------------------------------------------------

Name = Annotated[str, StringConstraints(max_length=255)]
Text = Annotated[str, StringConstraints(max_length=1024)]
IfIndex = Annotated[int, Field(ge=1, le=IF_INDEX_MAX)]
Subtype = Annotated[int, Field(ge=1, le=7)]
Gauge = Annotated[int, Field(ge=0, le=IF_SPEED_MAX)]
Counter64 = Annotated[int, Field(ge=0, le=2**63 - 1)]
_OID = re.compile(r"^[0-2](\.(0|[1-9][0-9]{0,9})){1,127}$")
_HEX = re.compile(r"^(0x)?([0-9a-fA-F]{2})*$")


def parse_octets(value: object) -> bytes:
    """Octets of a physical address given as bytes or common text notations."""
    if isinstance(value, bytes | bytearray):
        return bytes(value)
    if not isinstance(value, str):
        raise ValueError("not an octet string")
    text = value.strip()
    for sep in (":", "-"):
        if sep in text:
            parts = text.split(sep)
            if all(re.fullmatch(r"[0-9a-fA-F]{1,2}", p) for p in parts):
                return bytes(int(p, 16) for p in parts)
            raise ValueError("not an octet string")
    if "." in text:
        parts = text.split(".")
        if all(re.fullmatch(r"[0-9a-fA-F]{4}", p) for p in parts):
            return bytes.fromhex("".join(parts))
        raise ValueError("not an octet string")
    if _HEX.fullmatch(text):
        return bytes.fromhex(text.removeprefix("0x"))
    raise ValueError("not an octet string")


def mac_text(octets: bytes) -> str:
    return ":".join(f"{b:02x}" for b in octets)


class _Row(BaseModel):
    # Unknown keys, such as sysContact or the LLDP time mark, are dropped.
    model_config = ConfigDict(extra="ignore", frozen=True)

    def reported(self, names: tuple[str, ...]) -> dict[str, Any]:
        return {n: getattr(self, n) for n in names if n in self.model_fields_set}


class SystemRow(_Row):
    """System group. There are no fields for sysContact or sysLocation (design D10)."""

    sys_name: Name | None = None
    sys_descr: Text | None = None
    sys_object_id: Name | None = None
    sys_uptime: Counter64 | None = None

    @field_validator("sys_object_id")
    @classmethod
    def _oid(cls, value: str | None) -> str | None:
        if value is not None and not _OID.fullmatch(value):
            raise ValueError("not an object identifier")
        return value


class ModelRow(_Row):
    model: Name | None = None
    software_version: Name | None = None


class IfTableRow(_Row):
    if_index: IfIndex
    if_descr: Text | None = None
    if_type: Annotated[int, Field(ge=1, le=IF_INDEX_MAX)] | None = None
    if_speed: Gauge | None = None
    phys_address: str | None = None
    admin_status: Annotated[int, Field(ge=1, le=3)] | None = None
    oper_status: Annotated[int, Field(ge=1, le=7)] | None = None
    last_change: Counter64 | None = None

    @field_validator("phys_address", mode="before")
    @classmethod
    def _phys(cls, value: object) -> str | None:
        if value is None:
            return None
        octets = parse_octets(value)  # malformed: the row is rejected
        return mac_text(octets) if len(octets) == 6 else None  # only 6-byte addresses


class IfXTableRow(_Row):
    if_index: IfIndex
    if_name: Name | None = None
    if_alias: Text | None = None
    if_high_speed: Gauge | None = None


class AddressRow(_Row):
    address: IPvAnyAddress
    if_index: IfIndex | None = None


class NeighborRow(_Row):
    local_port_num: IfIndex
    remote_index: Annotated[int, Field(ge=0, le=IF_INDEX_MAX)]
    remote_chassis_id_subtype: Subtype | None = None
    remote_chassis_id: Name | None = None
    remote_port_id_subtype: Subtype | None = None
    remote_port_id: Name | None = None
    remote_sys_name: Name | None = None
    remote_port_desc: Text | None = None
    remote_capabilities: Name | None = None


class ManAddrRow(_Row):
    local_port_num: IfIndex
    remote_index: Annotated[int, Field(ge=0, le=IF_INDEX_MAX)]
    address: IPvAnyAddress


class LocalPortRow(_Row):
    local_port_num: IfIndex
    port_id_subtype: Subtype | None = None
    port_id: Name | None = None
    port_desc: Text | None = None


_IP_MAC_TYPES = {1: "other", 2: "invalid", 3: "dynamic", 4: "static", 5: "local"}


class IpMacRow(_Row):
    if_index: IfIndex
    ip_address: IPvAnyAddress
    mac_address: str
    entry_type: Literal["other", "invalid", "dynamic", "static", "local"]

    @field_validator("mac_address", mode="before")
    @classmethod
    def _mac(cls, value: object) -> str:
        octets = parse_octets(value)
        if len(octets) != 6:
            raise ValueError("a MAC address has 6 octets")
        return mac_text(octets)

    @field_validator("entry_type", mode="before")
    @classmethod
    def _type(cls, value: object) -> object:
        return _IP_MAC_TYPES.get(value, value) if isinstance(value, int) else value


def _validate(model: type[_Row], rows: list[Any]) -> tuple[list[Any], int]:
    valid, rejected = [], 0
    for raw in rows:
        if not isinstance(raw, dict):
            rejected += 1
            continue
        clean = {k: v for k, v in raw.items() if v is not NOT_RETRIEVED}
        try:
            valid.append(model.model_validate(clean))
        except ValidationError:
            rejected += 1  # the raw values are not kept anywhere
    return valid, rejected


# --- Common steps -----------------------------------------------------------


async def _source_query(
    conn: AsyncConnection, query_id: int, device_id: int, allowed: frozenset[str] | set[str]
) -> QueryInfo:
    """Check that a datum may be stored from this query (data-provenance spec)."""
    await observation_lock(conn)
    q = await get_query(conn, query_id)
    if q.device_id is None:
        raise StoreError(f"query {query_id} has no device yet; resolve the device first")
    if q.device_id != device_id:
        raise StoreError(f"query {query_id} belongs to another device")
    if q.mib_object not in allowed:
        raise StoreError(f"a query of {q.mib_object} cannot store this datum")
    if q.outcome not in (Outcome.OK, Outcome.EMPTY, Outcome.PARTIAL):
        raise StoreError(f"a query with outcome {q.outcome} has no rows to store")
    return q


async def _prepare(
    conn: AsyncConnection,
    query_id: int,
    device_id: int,
    allowed: frozenset[str] | set[str],
    model: type[_Row],
    rows: list[Any],
) -> tuple[QueryInfo, list[Any], int]:
    q = await _source_query(conn, query_id, device_id, allowed)
    valid, rejected = _validate(model, rows)
    if rejected:
        q = await add_rejected(conn, query_id, rejected)
    return q, valid, rejected


@dataclass(frozen=True)
class _Iface:
    id: int
    if_index: int
    if_name: str | None
    if_descr: str | None
    base_last_query_id: int | None
    ext_last_query_id: int | None

    def source(self) -> QueryInput:
        """The query that established the interface, as a source reference."""
        if self.base_last_query_id is not None:
            return QueryInput(id=self.base_last_query_id, mib_object="IF-MIB::ifTable")
        return QueryInput(id=self.ext_last_query_id, mib_object="IF-MIB::ifXTable")


async def _interfaces(conn: AsyncConnection, device_id: int) -> dict[int, _Iface]:
    rows = await conn.execute(
        select(
            interfaces.c.id,
            interfaces.c.if_index,
            interfaces.c.if_name,
            interfaces.c.if_descr,
            interfaces.c.base_last_query_id,
            interfaces.c.ext_last_query_id,
        ).where(interfaces.c.device_id == device_id)
    )
    return {r.if_index: _Iface(**r._mapping) for r in rows}


def _query_ref(q: QueryInfo) -> QueryInput:
    return QueryInput(id=q.id, mib_object=q.mib_object)


def _interface_link(
    spec_values: dict[str, Any],
    if_index: int | None,
    q: QueryInfo,
    ifaces: dict[int, _Iface],
    method: str,
    column: str = "interface_id",
) -> tuple[dict[str, Any], str | None, Any]:
    """Interface of an ``ifIndex`` read from another table: an observed MIB cross-reference."""
    iface = ifaces.get(if_index) if if_index is not None else None
    if iface is None:
        return {**spec_values, column: None}, None, None
    sources = build_evidence(method, Origin.OBSERVED, [_query_ref(q), iface.source()])
    return {**spec_values, column: iface.id}, method, sources


# --- Devices ----------------------------------------------------------------


async def store_system(
    conn: AsyncConnection, query_id: int, device_id: int, row: dict[str, Any]
) -> StoreResult:
    """System group, the enterprise number it contains and the vendor inferred from it."""
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, {"SNMPv2-MIB::system"}, SystemRow, [row]
    )
    if not valid:
        return StoreResult(rejected=rejected)
    system = valid[0]
    values = system.reported(("sys_name", "sys_descr", "sys_object_id", "sys_uptime"))
    updates = []
    if "sys_object_id" in values:
        number = registry.enterprise_number(system.sys_object_id) if system.sys_object_id else None
        values["enterprise_number"] = number
        if number is not None:
            updates.append(_vendor_update(q, number))
    updates.insert(0, GroupUpdate(SYSTEM, values, confirms_row=True))
    await apply_updates(conn, devices, device_id, updates, q)
    return StoreResult(stored=1)


def _vendor_update(q: QueryInfo, number: int) -> GroupUpdate:
    status, name = registry.lookup_vendor(number)
    evidence = build_evidence(
        "enterprise-registry",
        Origin.INFERRED,
        [QueryInput(id=q.id, mib_object=q.mib_object, snapshot={"enterprise_number": number})],
    )
    return GroupUpdate(
        VENDOR,
        {"vendor_name": name, "vendor_status": str(status)},
        Origin.INFERRED,
        "enterprise-registry",
        evidence,
    )


async def store_model(
    conn: AsyncConnection, query_id: int, device_id: int, row: dict[str, Any]
) -> StoreResult:
    """Model and software version read from ENTITY-MIB (observed)."""
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, {"ENTITY-MIB::entPhysicalTable"}, ModelRow, [row]
    )
    if not valid:
        return StoreResult(rejected=rejected)
    update_ = GroupUpdate(MODEL, valid[0].reported(MODEL.fields), confirms_row=True)
    await apply_updates(conn, devices, device_id, [update_], q)
    return StoreResult(stored=1)


_MODEL = re.compile(r"\bmodel[:=]?\s+([A-Za-z0-9][\w./-]{0,62})", re.IGNORECASE)
_VERSION = re.compile(r"\b(?:version|ver)[:=]?\s+v?([0-9][\w.()-]{0,62})", re.IGNORECASE)


def match_model_fragments(sys_descr: str) -> dict[str, str] | None:
    """Fragments of ``sysDescr`` that name a model and a version, or ``None``."""
    model = _MODEL.search(sys_descr)
    if model is None:
        return None
    found = {"model": model.group(1), "model_fragment": model.group(0)}
    version = _VERSION.search(sys_descr)
    if version is not None:
        found.update(version=version.group(1), version_fragment=version.group(0))
    return found


async def infer_model_from_sysdescr(conn: AsyncConnection, device_id: int) -> bool:
    """Infer model and version from fragments of the stored ``sysDescr``.

    The evidence references the stored description and keeps only the matched
    fragments (design D10). Without a match no inferred value is produced.

    Precedence is per field (design D9): the inference never changes a field
    whose effective origin is observed, so an observed model keeps its value,
    times and queries and ages normally. Returns whether anything changed.
    """
    await observation_lock(conn)
    row = (
        await conn.execute(
            select(devices.c.sys_descr, devices.c.system_last_query_id)
            .where(devices.c.id == device_id)
            # Locked: precedence is decided on the current row.
            .with_for_update()
        )
    ).one()
    if row.sys_descr is None:
        return False
    found = match_model_fragments(row.sys_descr)
    if found is None:
        return False
    q = await get_query(conn, row.system_last_query_id)
    snapshot = {k: v for k, v in found.items() if k.endswith("_fragment")}
    evidence = build_evidence(
        "sysdescr-model-pattern",
        Origin.INFERRED,
        [_query_ref(q), RecordInput(table="devices", id=device_id, snapshot=snapshot)],
    )
    # Without a version fragment the version is not retrieved, not absent.
    values = {"model": found["model"]}
    if "version" in found:
        values["software_version"] = found["version"]
    update_ = GroupUpdate(
        MODEL,
        values,
        Origin.INFERRED,
        "sysdescr-model-pattern",
        evidence,
    )
    return await apply_updates(conn, devices, device_id, [update_], q)


# --- Addresses --------------------------------------------------------------


async def store_addresses(
    conn: AsyncConnection, query_id: int, device_id: int, rows: list[dict[str, Any]]
) -> StoreResult:
    """Addresses from the device's own address table, with their interfaces."""
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, registry.ADDRESS_TABLES, AddressRow, rows
    )
    ifaces = await _interfaces(conn, device_id)
    for row in valid:
        values = row.reported(("if_index",))
        method = sources = None
        if "if_index" in values:
            values, method, sources = _interface_link(
                values, row.if_index, q, ifaces, "ipaddress-ifindex"
            )
        update_ = GroupUpdate(
            ADDRESS_GROUP, values, Origin.OBSERVED, method, sources, confirms_row=True
        )
        key = {"device_id": device_id, "address": str(row.address), "source": "address_table"}
        await upsert(conn, device_addresses, key, [update_], q)
    return StoreResult(stored=len(valid), rejected=rejected)


async def store_management_address(
    conn: AsyncConnection, q: QueryInfo, address: IPv4Address | IPv6Address | str
) -> None:
    """The address a device answered on (a successful management connection)."""
    key = {"device_id": q.device_id, "address": str(address), "source": "management"}
    # A management connection never names an interface: if_index and
    # interface_id are not retrieved (unknown), and the answer confirms the row.
    update_ = GroupUpdate(ADDRESS_GROUP, {}, confirms_row=True)
    await upsert(conn, device_addresses, key, [update_], q)


# --- Interfaces -------------------------------------------------------------


def _speed_from_base(
    row: IfTableRow, stored_high: int | None, ext_query: int | None, q: QueryInfo
) -> GroupUpdate:
    if row.if_speed == IF_SPEED_MAX and stored_high is not None and ext_query is not None:
        return _derived_speed(
            stored_high, [_query_ref(q), QueryInput(id=ext_query, mib_object="IF-MIB::ifXTable")]
        )
    return GroupUpdate(SPEED, {"speed_bps": row.if_speed})


def _derived_speed(high_speed: int, sources: list[QueryInput]) -> GroupUpdate:
    method = "ifhighspeed-when-ifspeed-saturated"
    return GroupUpdate(
        SPEED,
        {"speed_bps": high_speed * 1_000_000},
        Origin.OBSERVED,
        method,
        build_evidence(method, Origin.OBSERVED, sources),
    )


async def store_if_table(
    conn: AsyncConnection, query_id: int, device_id: int, rows: list[dict[str, Any]]
) -> StoreResult:
    """``IF-MIB::ifTable`` rows: the ``base`` group and the speed when it fits ``ifSpeed``."""
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, {"IF-MIB::ifTable"}, IfTableRow, rows
    )
    for row in valid:
        key = {"device_id": device_id, "if_index": row.if_index}
        updates = [GroupUpdate(BASE, row.reported(BASE.fields), confirms_row=True)]
        if "if_speed" in row.model_fields_set:
            stored = (
                await conn.execute(
                    select(interfaces.c.if_high_speed, interfaces.c.ext_last_query_id).where(
                        interfaces.c.device_id == device_id, interfaces.c.if_index == row.if_index
                    )
                )
            ).first()
            high, ext_query = (
                (stored.if_high_speed, stored.ext_last_query_id) if stored else (None, None)
            )
            updates.append(_speed_from_base(row, high, ext_query, q))
        await upsert(conn, interfaces, key, updates, q)
    return StoreResult(stored=len(valid), rejected=rejected)


async def store_if_xtable(
    conn: AsyncConnection, query_id: int, device_id: int, rows: list[dict[str, Any]]
) -> StoreResult:
    """``IF-MIB::ifXTable`` rows: the ``ext`` group, and the speed when ``ifSpeed`` is saturated."""
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, {"IF-MIB::ifXTable"}, IfXTableRow, rows
    )
    for row in valid:
        key = {"device_id": device_id, "if_index": row.if_index}
        updates = [GroupUpdate(EXT, row.reported(EXT.fields), confirms_row=True)]
        if row.if_high_speed is not None:
            stored = (
                await conn.execute(
                    select(interfaces.c.if_speed, interfaces.c.base_last_query_id).where(
                        interfaces.c.device_id == device_id, interfaces.c.if_index == row.if_index
                    )
                )
            ).first()
            if stored is not None and stored.if_speed == IF_SPEED_MAX:
                sources = [
                    QueryInput(id=stored.base_last_query_id, mib_object="IF-MIB::ifTable"),
                    _query_ref(q),
                ]
                updates.append(_derived_speed(row.if_high_speed, sources))
        await upsert(conn, interfaces, key, updates, q)
    return StoreResult(stored=len(valid), rejected=rejected)


# --- Neighbours -------------------------------------------------------------


def _neighbor_key(device_id: int, protocol: str, row: NeighborRow | ManAddrRow) -> dict[str, Any]:
    # The LLDP time mark is not part of the key: it changes on every update.
    return {
        "device_id": device_id,
        "protocol": protocol,
        "local_port_num": row.local_port_num,
        "remote_index": row.remote_index,
    }


async def store_neighbors(
    conn: AsyncConnection, query_id: int, device_id: int, rows: list[dict[str, Any]]
) -> StoreResult:
    """LLDP remote table or CDP cache entries (the ``entry`` group).

    The local port mapping of LLDP entries is a separate group, evaluated by
    :func:`map_local_ports`; a CDP entry names its local ``ifIndex`` directly.
    """
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, set(registry.NEIGHBOR_TABLES), NeighborRow, rows
    )
    protocol = registry.NEIGHBOR_TABLES[q.mib_object]
    ifaces = await _interfaces(conn, device_id) if protocol == "cdp" else {}
    for row in valid:
        updates = [GroupUpdate(ENTRY, row.reported(ENTRY.fields), confirms_row=True)]
        if protocol == "cdp":
            updates.append(_cdp_local_map(row, q, ifaces))
        await upsert(conn, neighbor_entries, _neighbor_key(device_id, protocol, row), updates, q)
    return StoreResult(stored=len(valid), rejected=rejected)


def _cdp_local_map(row: NeighborRow, q: QueryInfo, ifaces: dict[int, _Iface]) -> GroupUpdate:
    values: dict[str, Any] = {"local_port_id_subtype": None, "local_port_id": None}
    values, method, sources = _interface_link(
        values, row.local_port_num, q, ifaces, "cdp-cache-ifindex", "local_interface_id"
    )
    values["local_map_failure"] = None if method else "no-interface-with-ifindex"
    return GroupUpdate(LOCAL_MAP, values, Origin.OBSERVED, method, sources)


async def store_neighbor_man_addresses(
    conn: AsyncConnection, query_id: int, device_id: int, rows: list[dict[str, Any]]
) -> StoreResult:
    """Management addresses from ``lldpRemManAddrTable`` (the ``man_addr`` group).

    Addresses are stored whatever their range; storing never triggers a query.
    """
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, {"LLDP-MIB::lldpRemManAddrTable"}, ManAddrRow, rows
    )
    by_entry: dict[tuple[int, int], list[str]] = {}
    for row in valid:
        addresses = by_entry.setdefault((row.local_port_num, row.remote_index), [])
        if str(row.address) not in addresses:
            addresses.append(str(row.address))
    for (port, index), addresses in by_entry.items():
        key = {
            "device_id": device_id,
            "protocol": "lldp",
            "local_port_num": port,
            "remote_index": index,
        }
        await upsert(
            conn,
            neighbor_entries,
            key,
            [GroupUpdate(MAN_ADDR, {"man_addresses": addresses}, confirms_row=True)],
            q,
        )
    return StoreResult(stored=len(valid), rejected=rejected)


async def map_local_ports(
    conn: AsyncConnection, query_id: int, device_id: int, rows: list[dict[str, Any]]
) -> StoreResult:
    """Map LLDP local ports (``lldpLocPortTable``) of stored LLDP entries to interfaces.

    Rules, in order: port id subtype interfaceName equal to one ``ifName``
    (observed); port description equal to one ``ifDescr`` (inferred); port
    number assumed equal to ``ifIndex`` (inferred, hypothesis H1). Otherwise the
    entry keeps no interface and the reason is stored.
    """
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, {"LLDP-MIB::lldpLocPortTable"}, LocalPortRow, rows
    )
    ports = {row.local_port_num: row for row in valid}
    ifaces = await _interfaces(conn, device_id)
    entries = await conn.execute(
        select(neighbor_entries.c.id, neighbor_entries.c.local_port_num).where(
            neighbor_entries.c.device_id == device_id,
            neighbor_entries.c.protocol == "lldp",
            neighbor_entries.c.local_port_num.in_(list(ports)),
        )
    )
    mapped = 0
    for entry in entries.all():
        update_ = _lldp_local_map(ports[entry.local_port_num], q, ifaces)
        await apply_updates(conn, neighbor_entries, entry.id, [update_], q)
        mapped += 1
    return StoreResult(stored=mapped, rejected=rejected)


INTERFACE_NAME_SUBTYPE = 5


def _lldp_local_map(port: LocalPortRow, q: QueryInfo, ifaces: dict[int, _Iface]) -> GroupUpdate:
    base = {"local_port_id_subtype": port.port_id_subtype, "local_port_id": port.port_id}
    locport = _query_ref(q)
    if port.port_id_subtype == INTERFACE_NAME_SUBTYPE and port.port_id:
        named = [i for i in ifaces.values() if i.if_name == port.port_id]
        if len(named) == 1:
            iface = named[0]
            ext = QueryInput(id=iface.ext_last_query_id, mib_object="IF-MIB::ifXTable")
            method = "lldp-portid-ifname"
            return GroupUpdate(
                LOCAL_MAP,
                {**base, "local_interface_id": iface.id, "local_map_failure": None},
                Origin.OBSERVED,
                method,
                build_evidence(method, Origin.OBSERVED, [locport, ext]),
            )
    if port.port_desc:
        described = [i for i in ifaces.values() if i.if_descr == port.port_desc]
        if len(described) == 1:
            iface = described[0]
            snapshot = {"lldp_loc_port_desc": port.port_desc, "if_descr": iface.if_descr}
            return _inferred_map(base, iface, "lldp-port-description-match", locport, snapshot)
    iface = ifaces.get(port.local_port_num)
    if iface is not None:
        snapshot = {"lldp_loc_port_num": port.local_port_num, "if_index": iface.if_index}
        return _inferred_map(base, iface, "lldp-portnum-equals-ifindex", locport, snapshot)
    return GroupUpdate(
        LOCAL_MAP, {**base, "local_interface_id": None, "local_map_failure": "no-rule-matched"}
    )


def _inferred_map(
    base: dict[str, Any], iface: _Iface, method: str, locport: QueryInput, snapshot: dict[str, Any]
) -> GroupUpdate:
    record = RecordInput(table="interfaces", id=iface.id, snapshot=snapshot)
    return GroupUpdate(
        LOCAL_MAP,
        {**base, "local_interface_id": iface.id, "local_map_failure": None},
        Origin.INFERRED,
        method,
        build_evidence(method, Origin.INFERRED, [locport, iface.source(), record]),
    )


# --- IP-MAC entries ---------------------------------------------------------


async def store_ip_mac(
    conn: AsyncConnection, query_id: int, device_id: int, rows: list[dict[str, Any]]
) -> StoreResult:
    """``ipNetToPhysicalTable`` or ``ipNetToMediaTable`` entries; invalid ones are skipped."""
    q, valid, rejected = await _prepare(
        conn, query_id, device_id, registry.IP_MAC_TABLES, IpMacRow, rows
    )
    ifaces = await _interfaces(conn, device_id)
    skipped = 0
    for row in valid:
        if row.entry_type == "invalid":
            skipped += 1
            continue
        values = {"mac_address": row.mac_address, "entry_type": row.entry_type}
        values, method, sources = _interface_link(values, row.if_index, q, ifaces, "ip-mac-ifindex")
        key = {"device_id": device_id, "if_index": row.if_index, "ip_address": str(row.ip_address)}
        await upsert(
            conn,
            ip_mac_entries,
            key,
            [
                GroupUpdate(
                    IP_MAC_GROUP, values, Origin.OBSERVED, method, sources, confirms_row=True
                )
            ],
            q,
        )
    return StoreResult(stored=len(valid) - skipped, rejected=rejected, skipped=skipped)
