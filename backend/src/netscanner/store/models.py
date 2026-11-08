# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Tables of the provenance model (design D7, D8) and their ORM classes.

Tables are declared with SQLAlchemy Core so that observation tables can take
their provenance groups from :func:`provenance_group`; the ORM classes map
them for reads. Writes of observations go through ``netscanner.store.observations``.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    MetaData,
    SmallInteger,
    String,
    Table,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, MACADDR
from sqlalchemy.orm import DeclarativeBase

from netscanner.store.groups import GroupSpec, provenance_group

NAME = 255
DESCRIPTION = 1024
CATEGORY = 64
IF_INDEX_MAX = 2147483647

metadata = MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "uq": "uq_%(table_name)s_%(column_0_N_name)s",
        "ix": "ix_%(table_name)s_%(column_0_N_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_N_name)s",
    }
)


def _id() -> Column:
    return Column("id", BigInteger, Identity(), primary_key=True)


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _ts(name: str, nullable: bool = True) -> Column:
    return Column(name, DateTime(timezone=True), nullable=nullable)


RUN_KINDS = ("discovery", "rediscovery", "polling")
RUN_STATUSES = ("pending", "running", "completed", "failed", "interrupted")
OUTCOMES = ("ok", "empty", "not_available", "no_response", "partial", "error")
INDICATORS = (
    "noSuchObject",
    "noSuchInstance",
    "endOfMibView",
    "end_of_subtree",
    "value_returned",
)
OPERATIONS = ("get", "getnext", "getbulk", "walk")
SNMP_VERSIONS = ("1", "2c", "3")
REACHED_VIA = ("seed", "lldp", "cdp", "ip-mac")
ADDRESS_SOURCES = ("address_table", "management")
IP_MAC_TYPES = ("other", "dynamic", "static", "local")
RESOLUTION_STATUSES = ("active", "conflicted")
VENDOR_STATUSES = ("known", "generic_agent", "not_in_registry")


# --- Groups (design D4) -----------------------------------------------------

DEVICE_GROUPS = (
    GroupSpec(
        "devices",
        "system",
        ("sys_name", "sys_descr", "sys_object_id", "sys_uptime", "enterprise_number"),
    ),
    GroupSpec("devices", "chassis", ("chassis_id_subtype", "chassis_id")),
    GroupSpec("devices", "vendor", ("vendor_name", "vendor_status")),
    GroupSpec("devices", "model", ("model", "software_version")),
)
INTERFACE_GROUPS = (
    GroupSpec(
        "interfaces",
        "base",
        (
            "if_descr",
            "if_type",
            "if_speed",
            "phys_address",
            "admin_status",
            "oper_status",
            "last_change",
        ),
    ),
    GroupSpec("interfaces", "ext", ("if_name", "if_alias", "if_high_speed")),
    GroupSpec("interfaces", "speed", ("speed_bps",)),
)
NEIGHBOR_GROUPS = (
    GroupSpec(
        "neighbor_entries",
        "entry",
        (
            "remote_chassis_id_subtype",
            "remote_chassis_id",
            "remote_port_id_subtype",
            "remote_port_id",
            "remote_sys_name",
            "remote_port_desc",
            "remote_capabilities",
        ),
    ),
    GroupSpec("neighbor_entries", "man_addr", ("man_addresses",)),
    GroupSpec(
        "neighbor_entries",
        "local_map",
        ("local_port_id_subtype", "local_port_id", "local_interface_id", "local_map_failure"),
    ),
)
ADDRESS_GROUP = GroupSpec(
    "device_addresses",
    "address",
    ("if_index", "interface_id"),
    prefixed=False,
    required=True,
)
IP_MAC_GROUP = GroupSpec(
    "ip_mac_entries",
    "entry",
    ("mac_address", "entry_type", "interface_id"),
    prefixed=False,
    required=True,
)
RESOLUTION_GROUP = GroupSpec(
    "identity_resolutions", "resolution", ("status",), prefixed=False, required=True
)

GROUPS: dict[str, tuple[GroupSpec, ...]] = {
    "devices": DEVICE_GROUPS,
    "interfaces": INTERFACE_GROUPS,
    "neighbor_entries": NEIGHBOR_GROUPS,
    "device_addresses": (ADDRESS_GROUP,),
    "ip_mac_entries": (IP_MAC_GROUP,),
    "identity_resolutions": (RESOLUTION_GROUP,),
}


def _groups(*specs: GroupSpec, device_column: str = "device_id") -> list:
    return [item for spec in specs for item in provenance_group(spec, device_column)]


# --- Runs and queries -------------------------------------------------------

collection_runs = Table(
    "collection_runs",
    metadata,
    _id(),
    Column("kind", String(16), nullable=False),
    Column("status", String(16), nullable=False),
    _ts("requested_at", nullable=False),
    _ts("started_at"),
    _ts("finished_at"),
    Column("parameters", JSONB, nullable=False),
    Column("summary", JSONB(none_as_null=True)),
    Column("error_category", String(CATEGORY)),
    CheckConstraint(_in("kind", RUN_KINDS), name="kind"),
    CheckConstraint(_in("status", RUN_STATUSES), name="status"),
    CheckConstraint(
        "(status = 'pending' AND started_at IS NULL AND finished_at IS NULL)"
        " OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)"
        " OR (status IN ('completed', 'failed') AND started_at IS NOT NULL"
        " AND finished_at IS NOT NULL)"
        " OR (status = 'interrupted' AND finished_at IS NOT NULL)",
        name="lifecycle",
    ),
    CheckConstraint("started_at >= requested_at", name="started_order"),
    CheckConstraint("finished_at >= coalesce(started_at, requested_at)", name="finished_order"),
)

snmp_queries = Table(
    "snmp_queries",
    metadata,
    _id(),
    Column("run_id", BigInteger, ForeignKey("collection_runs.id"), nullable=False, index=True),
    Column("target_address", INET, nullable=False),
    Column("device_id", BigInteger, ForeignKey("devices.id")),
    Column("mib_object", String(NAME), nullable=False),
    Column("operation", String(16), nullable=False),
    Column("snmp_version", String(4), nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("indicator", String(32)),
    Column("error_category", String(CATEGORY)),
    Column("row_count", Integer, nullable=False),
    Column("rejected_count", Integer, nullable=False, server_default=text("0")),
    Column("request_count", Integer, nullable=False),
    _ts("started_at", nullable=False),
    Column("duration_ms", Integer, nullable=False),
    UniqueConstraint("id", "device_id"),
    CheckConstraint(_in("operation", OPERATIONS), name="operation"),
    CheckConstraint(_in("snmp_version", SNMP_VERSIONS), name="snmp_version"),
    CheckConstraint(_in("outcome", OUTCOMES), name="outcome"),
    CheckConstraint(_in("indicator", INDICATORS), name="indicator"),
    CheckConstraint(
        "outcome NOT IN ('empty', 'not_available') OR indicator IS NOT NULL",
        name="indicator_required",
    ),
    CheckConstraint("outcome <> 'error' OR error_category IS NOT NULL", name="error_category"),
    CheckConstraint(
        "error_category IS NULL OR outcome IN ('error', 'partial')", name="error_only_on_failure"
    ),
    CheckConstraint(
        "outcome <> 'no_response' OR (indicator IS NULL AND error_category IS NULL"
        " AND row_count = 0)",
        name="no_diagnosis",
    ),
    CheckConstraint(
        "row_count >= 0 AND rejected_count >= 0 AND rejected_count <= row_count"
        " AND request_count >= 0 AND duration_ms >= 0",
        name="counts",
    ),
)
Index(
    "ix_snmp_queries_latest",
    snmp_queries.c.device_id,
    snmp_queries.c.mib_object,
    snmp_queries.c.started_at.desc(),
)

# --- Devices and identity ---------------------------------------------------

devices = Table(
    "devices",
    metadata,
    _id(),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("sys_name", String(NAME)),
    Column("sys_descr", String(DESCRIPTION)),
    Column("sys_object_id", String(NAME)),
    Column("sys_uptime", BigInteger),
    Column("enterprise_number", BigInteger),
    Column("chassis_id_subtype", SmallInteger),
    Column("chassis_id", String(NAME)),
    Column("vendor_name", String(NAME)),
    Column("vendor_status", String(16)),
    Column("model", String(NAME)),
    Column("software_version", String(NAME)),
    CheckConstraint("chassis_id_subtype BETWEEN 1 AND 7", name="chassis_subtype"),
    CheckConstraint(_in("vendor_status", VENDOR_STATUSES), name="vendor_status"),
    *_groups(*DEVICE_GROUPS, device_column="id"),
)

identity_resolutions = Table(
    "identity_resolutions",
    metadata,
    _id(),
    Column("device_id", BigInteger, ForeignKey("devices.id"), nullable=False),
    Column("key_value", String(NAME), nullable=False),
    Column("status", String(16), nullable=False),
    *_groups(RESOLUTION_GROUP),
    UniqueConstraint("method", "key_value", "device_id"),
    CheckConstraint(_in("method", ("chassis-id", "address")), name="identity_method"),
    CheckConstraint(_in("status", RESOLUTION_STATUSES), name="resolution_status"),
    CheckConstraint("origin = 'inferred'", name="always_inferred"),
)

identity_conflicts = Table(
    "identity_conflicts",
    metadata,
    _id(),
    Column("key_method", String(16), nullable=False),
    Column("key_value", String(NAME), nullable=False),
    Column("device_id", BigInteger, ForeignKey("devices.id"), nullable=False),
    Column("other_device_id", BigInteger, ForeignKey("devices.id"), nullable=False),
    Column("evidence", JSONB, nullable=False),
    Column("query_id", BigInteger, ForeignKey("snmp_queries.id"), nullable=False),
    _ts("detected_at", nullable=False),
    Column("needs_review", Boolean, nullable=False, server_default=text("true")),
    UniqueConstraint("key_method", "key_value", "device_id", "other_device_id"),
    CheckConstraint(_in("key_method", ("chassis-id", "address")), name="key_method"),
    CheckConstraint("device_id <> other_device_id", name="two_devices"),
)

run_devices = Table(
    "run_devices",
    metadata,
    _id(),
    Column("run_id", BigInteger, ForeignKey("collection_runs.id"), nullable=False),
    Column("device_id", BigInteger, ForeignKey("devices.id")),
    Column("target_address", INET, nullable=False),
    Column("reached_via", String(8), nullable=False),
    Column("depth", SmallInteger, nullable=False),
    Column("first_query_id", BigInteger, ForeignKey("snmp_queries.id")),
    Column("answered", Boolean, nullable=False),
    UniqueConstraint("run_id", "target_address"),
    CheckConstraint(_in("reached_via", REACHED_VIA), name="reached_via"),
    CheckConstraint("depth >= 0", name="depth"),
)

# --- Observations -----------------------------------------------------------

interfaces = Table(
    "interfaces",
    metadata,
    _id(),
    Column("device_id", BigInteger, ForeignKey("devices.id"), nullable=False),
    Column("if_index", Integer, nullable=False),
    Column("if_descr", String(DESCRIPTION)),
    Column("if_type", Integer),
    Column("if_speed", BigInteger),
    Column("phys_address", MACADDR),
    Column("admin_status", SmallInteger),
    Column("oper_status", SmallInteger),
    Column("last_change", BigInteger),
    Column("if_name", String(NAME)),
    Column("if_alias", String(DESCRIPTION)),
    Column("if_high_speed", BigInteger),
    Column("speed_bps", BigInteger),
    UniqueConstraint("device_id", "if_index"),
    UniqueConstraint("id", "device_id"),
    CheckConstraint(f"if_index BETWEEN 1 AND {IF_INDEX_MAX}", name="if_index"),
    *_groups(*INTERFACE_GROUPS),
)


def _interface_fk(table: str, column: str) -> ForeignKeyConstraint:
    return ForeignKeyConstraint(
        [column, "device_id"],
        ["interfaces.id", "interfaces.device_id"],
        name=f"fk_{table}_{column}",
    )


device_addresses = Table(
    "device_addresses",
    metadata,
    _id(),
    Column("device_id", BigInteger, ForeignKey("devices.id"), nullable=False),
    Column("address", INET, nullable=False),
    Column("source", String(16), nullable=False),
    Column("if_index", Integer),
    Column("interface_id", BigInteger),
    # One row per source: the address table and a management connection keep
    # their own provenance.
    UniqueConstraint("device_id", "address", "source"),
    CheckConstraint(_in("source", ADDRESS_SOURCES), name="source"),
    _interface_fk("device_addresses", "interface_id"),
    *_groups(ADDRESS_GROUP),
)

neighbor_entries = Table(
    "neighbor_entries",
    metadata,
    _id(),
    Column("device_id", BigInteger, ForeignKey("devices.id"), nullable=False),
    Column("protocol", String(8), nullable=False),
    Column("local_port_num", Integer, nullable=False),
    Column("remote_index", Integer, nullable=False),
    Column("remote_chassis_id_subtype", SmallInteger),
    Column("remote_chassis_id", String(NAME)),
    Column("remote_port_id_subtype", SmallInteger),
    Column("remote_port_id", String(NAME)),
    Column("remote_sys_name", String(NAME)),
    Column("remote_port_desc", String(DESCRIPTION)),
    Column("remote_capabilities", String(NAME)),
    Column("man_addresses", ARRAY(INET)),
    Column("local_port_id_subtype", SmallInteger),
    Column("local_port_id", String(NAME)),
    Column("local_interface_id", BigInteger),
    Column("local_map_failure", String(CATEGORY)),
    UniqueConstraint("device_id", "protocol", "local_port_num", "remote_index"),
    CheckConstraint(_in("protocol", ("lldp", "cdp")), name="protocol"),
    _interface_fk("neighbor_entries", "local_interface_id"),
    *_groups(*NEIGHBOR_GROUPS),
)

ip_mac_entries = Table(
    "ip_mac_entries",
    metadata,
    _id(),
    Column("device_id", BigInteger, ForeignKey("devices.id"), nullable=False),
    Column("if_index", Integer, nullable=False),
    Column("ip_address", INET, nullable=False),
    Column("mac_address", MACADDR, nullable=False),
    Column("entry_type", String(16), nullable=False),
    Column("interface_id", BigInteger),
    UniqueConstraint("device_id", "if_index", "ip_address"),
    CheckConstraint(_in("entry_type", IP_MAC_TYPES), name="entry_type"),
    _interface_fk("ip_mac_entries", "interface_id"),
    *_groups(IP_MAC_GROUP),
)

evaluation_snapshots = Table(
    "evaluation_snapshots",
    metadata,
    _id(),
    Column("run_id", BigInteger, ForeignKey("collection_runs.id"), nullable=False, unique=True),
    _ts("created_at", nullable=False),
    Column("schema_version", Integer, nullable=False),
    Column("content", JSONB, nullable=False),
)


# --- ORM classes ------------------------------------------------------------


class Base(DeclarativeBase):
    metadata = metadata


class CollectionRun(Base):
    __table__ = collection_runs


class SnmpQuery(Base):
    __table__ = snmp_queries


class Device(Base):
    __table__ = devices


class IdentityResolution(Base):
    __table__ = identity_resolutions


class IdentityConflict(Base):
    __table__ = identity_conflicts


class RunDevice(Base):
    __table__ = run_devices


class Interface(Base):
    __table__ = interfaces


class DeviceAddress(Base):
    __table__ = device_addresses


class NeighborEntry(Base):
    __table__ = neighbor_entries


class IpMacEntry(Base):
    __table__ = ip_mac_entries


class EvaluationSnapshot(Base):
    __table__ = evaluation_snapshots
