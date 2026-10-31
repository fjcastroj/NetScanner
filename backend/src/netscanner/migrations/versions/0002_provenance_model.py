# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Provenance model: runs, queries and the observations of iteration 1.

Tables, constraints and indexes of design D1, D4, D7 and D8
(add-data-provenance-model). ``devices`` and ``snmp_queries`` reference each
other, so the composite foreign keys of the device groups are added after both
tables exist and dropped first on downgrade.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None
# Composite foreign keys (group query, device) of the devices table.
DEVICE_QUERY_FKS = [
    ("fk_devices_chassis_first_query", "chassis_first_query_id"),
    ("fk_devices_chassis_last_complete_query", "chassis_last_complete_query_id"),
    ("fk_devices_chassis_last_query", "chassis_last_query_id"),
    ("fk_devices_model_first_query", "model_first_query_id"),
    ("fk_devices_model_last_complete_query", "model_last_complete_query_id"),
    ("fk_devices_model_last_query", "model_last_query_id"),
    ("fk_devices_system_first_query", "system_first_query_id"),
    ("fk_devices_system_last_complete_query", "system_last_complete_query_id"),
    ("fk_devices_system_last_query", "system_last_query_id"),
    ("fk_devices_vendor_first_query", "vendor_first_query_id"),
    ("fk_devices_vendor_last_complete_query", "vendor_last_complete_query_id"),
    ("fk_devices_vendor_last_query", "vendor_last_query_id"),
]


def upgrade() -> None:
    op.create_table(
        "collection_runs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("parameters", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "(status = 'pending' AND started_at IS NULL AND finished_at IS NULL) OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL) OR (status IN ('completed', 'failed') AND started_at IS NOT NULL AND finished_at IS NOT NULL) OR (status = 'interrupted' AND finished_at IS NOT NULL)",
            name=op.f("ck_collection_runs_lifecycle"),
        ),
        sa.CheckConstraint(
            "kind IN ('discovery', 'rediscovery', 'polling')", name=op.f("ck_collection_runs_kind")
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'interrupted')",
            name=op.f("ck_collection_runs_status"),
        ),
        sa.CheckConstraint(
            "finished_at >= coalesce(started_at, requested_at)",
            name=op.f("ck_collection_runs_finished_order"),
        ),
        sa.CheckConstraint(
            "started_at >= requested_at", name=op.f("ck_collection_runs_started_order")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_collection_runs")),
    )
    op.create_table(
        "devices",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("sys_name", sa.String(length=255), nullable=True),
        sa.Column("sys_descr", sa.String(length=1024), nullable=True),
        sa.Column("sys_object_id", sa.String(length=255), nullable=True),
        sa.Column("sys_uptime", sa.BigInteger(), nullable=True),
        sa.Column("enterprise_number", sa.BigInteger(), nullable=True),
        sa.Column("chassis_id_subtype", sa.SmallInteger(), nullable=True),
        sa.Column("chassis_id", sa.String(length=255), nullable=True),
        sa.Column("vendor_name", sa.String(length=255), nullable=True),
        sa.Column("vendor_status", sa.String(length=16), nullable=True),
        sa.Column("model", sa.String(length=255), nullable=True),
        sa.Column("software_version", sa.String(length=255), nullable=True),
        sa.Column("system_origin", sa.String(length=16), nullable=True),
        sa.Column("system_method", sa.String(length=64), nullable=True),
        sa.Column("system_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("system_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("system_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("system_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("system_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("system_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "system_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("chassis_origin", sa.String(length=16), nullable=True),
        sa.Column("chassis_method", sa.String(length=64), nullable=True),
        sa.Column("chassis_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("chassis_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("chassis_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("chassis_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("chassis_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("chassis_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "chassis_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("vendor_origin", sa.String(length=16), nullable=True),
        sa.Column("vendor_method", sa.String(length=64), nullable=True),
        sa.Column("vendor_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("vendor_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vendor_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("vendor_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vendor_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("vendor_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "vendor_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("model_origin", sa.String(length=16), nullable=True),
        sa.Column("model_method", sa.String(length=64), nullable=True),
        sa.Column("model_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("model_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("model_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("model_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("model_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("model_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "model_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "chassis_origin <> 'inferred' OR (chassis_method IS NOT NULL AND chassis_evidence IS NOT NULL AND jsonb_path_exists(chassis_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_devices_chassis_inferred"),
        ),
        sa.CheckConstraint(
            "chassis_origin IN ('observed', 'inferred')", name=op.f("ck_devices_chassis_origin")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(chassis_carried) = 'object'", name=op.f("ck_devices_chassis_carried")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(model_carried) = 'object'", name=op.f("ck_devices_model_carried")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(system_carried) = 'object'", name=op.f("ck_devices_system_carried")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(vendor_carried) = 'object'", name=op.f("ck_devices_vendor_carried")
        ),
        sa.CheckConstraint(
            "model_origin <> 'inferred' OR (model_method IS NOT NULL AND model_evidence IS NOT NULL AND jsonb_path_exists(model_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_devices_model_inferred"),
        ),
        sa.CheckConstraint(
            "model_origin IN ('observed', 'inferred')", name=op.f("ck_devices_model_origin")
        ),
        sa.CheckConstraint(
            "system_origin <> 'inferred' OR (system_method IS NOT NULL AND system_evidence IS NOT NULL AND jsonb_path_exists(system_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_devices_system_inferred"),
        ),
        sa.CheckConstraint(
            "system_origin IN ('observed', 'inferred')", name=op.f("ck_devices_system_origin")
        ),
        sa.CheckConstraint(
            "vendor_origin <> 'inferred' OR (vendor_method IS NOT NULL AND vendor_evidence IS NOT NULL AND jsonb_path_exists(vendor_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_devices_vendor_inferred"),
        ),
        sa.CheckConstraint(
            "vendor_origin IN ('observed', 'inferred')", name=op.f("ck_devices_vendor_origin")
        ),
        sa.CheckConstraint(
            "vendor_status IN ('known', 'generic_agent', 'not_in_registry')",
            name=op.f("ck_devices_vendor_status"),
        ),
        sa.CheckConstraint(
            "chassis_evidence IS NULL OR chassis_method IS NOT NULL",
            name=op.f("ck_devices_chassis_evidence_method"),
        ),
        sa.CheckConstraint(
            "chassis_id_subtype BETWEEN 1 AND 7", name=op.f("ck_devices_chassis_subtype")
        ),
        sa.CheckConstraint(
            "chassis_last_seen_at >= chassis_first_seen_at",
            name=op.f("ck_devices_chassis_seen_order"),
        ),
        sa.CheckConstraint(
            "model_evidence IS NULL OR model_method IS NOT NULL",
            name=op.f("ck_devices_model_evidence_method"),
        ),
        sa.CheckConstraint(
            "model_last_seen_at >= model_first_seen_at", name=op.f("ck_devices_model_seen_order")
        ),
        sa.CheckConstraint(
            "num_nulls(chassis_origin, chassis_first_seen_at, chassis_first_query_id, chassis_last_seen_at, chassis_last_query_id) = 0 OR (num_nulls(chassis_origin, chassis_first_seen_at, chassis_first_query_id, chassis_last_seen_at, chassis_last_query_id, chassis_method, chassis_evidence) = 7 AND chassis_last_complete_query_id IS NULL)",
            name=op.f("ck_devices_chassis_all_or_none"),
        ),
        sa.CheckConstraint(
            "num_nulls(model_origin, model_first_seen_at, model_first_query_id, model_last_seen_at, model_last_query_id) = 0 OR (num_nulls(model_origin, model_first_seen_at, model_first_query_id, model_last_seen_at, model_last_query_id, model_method, model_evidence) = 7 AND model_last_complete_query_id IS NULL)",
            name=op.f("ck_devices_model_all_or_none"),
        ),
        sa.CheckConstraint(
            "num_nulls(system_origin, system_first_seen_at, system_first_query_id, system_last_seen_at, system_last_query_id) = 0 OR (num_nulls(system_origin, system_first_seen_at, system_first_query_id, system_last_seen_at, system_last_query_id, system_method, system_evidence) = 7 AND system_last_complete_query_id IS NULL)",
            name=op.f("ck_devices_system_all_or_none"),
        ),
        sa.CheckConstraint(
            "num_nulls(vendor_origin, vendor_first_seen_at, vendor_first_query_id, vendor_last_seen_at, vendor_last_query_id) = 0 OR (num_nulls(vendor_origin, vendor_first_seen_at, vendor_first_query_id, vendor_last_seen_at, vendor_last_query_id, vendor_method, vendor_evidence) = 7 AND vendor_last_complete_query_id IS NULL)",
            name=op.f("ck_devices_vendor_all_or_none"),
        ),
        sa.CheckConstraint(
            "system_evidence IS NULL OR system_method IS NOT NULL",
            name=op.f("ck_devices_system_evidence_method"),
        ),
        sa.CheckConstraint(
            "system_last_seen_at >= system_first_seen_at", name=op.f("ck_devices_system_seen_order")
        ),
        sa.CheckConstraint(
            "vendor_evidence IS NULL OR vendor_method IS NOT NULL",
            name=op.f("ck_devices_vendor_evidence_method"),
        ),
        sa.CheckConstraint(
            "vendor_last_seen_at >= vendor_first_seen_at", name=op.f("ck_devices_vendor_seen_order")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_devices")),
    )
    op.create_table(
        "evaluation_snapshots",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"], ["collection_runs.id"], name=op.f("fk_evaluation_snapshots_run_id")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evaluation_snapshots")),
        sa.UniqueConstraint("run_id", name=op.f("uq_evaluation_snapshots_run_id")),
    )
    op.create_table(
        "snmp_queries",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("target_address", postgresql.INET(), nullable=False),
        sa.Column("device_id", sa.BigInteger(), nullable=True),
        sa.Column("mib_object", sa.String(length=255), nullable=False),
        sa.Column("operation", sa.String(length=16), nullable=False),
        sa.Column("snmp_version", sa.String(length=4), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("indicator", sa.String(length=32), nullable=True),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("rejected_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "error_category IS NULL OR outcome IN ('error', 'partial')",
            name=op.f("ck_snmp_queries_error_only_on_failure"),
        ),
        sa.CheckConstraint(
            "indicator IN ('noSuchObject', 'noSuchInstance', 'endOfMibView', 'end_of_subtree')",
            name=op.f("ck_snmp_queries_indicator"),
        ),
        sa.CheckConstraint(
            "operation IN ('get', 'getnext', 'getbulk', 'walk')",
            name=op.f("ck_snmp_queries_operation"),
        ),
        sa.CheckConstraint(
            "outcome <> 'error' OR error_category IS NOT NULL",
            name=op.f("ck_snmp_queries_error_category"),
        ),
        sa.CheckConstraint(
            "outcome <> 'no_response' OR (indicator IS NULL AND error_category IS NULL AND row_count = 0)",
            name=op.f("ck_snmp_queries_no_diagnosis"),
        ),
        sa.CheckConstraint(
            "outcome IN ('ok', 'empty', 'not_available', 'no_response', 'partial', 'error')",
            name=op.f("ck_snmp_queries_outcome"),
        ),
        sa.CheckConstraint(
            "outcome NOT IN ('empty', 'not_available') OR indicator IS NOT NULL",
            name=op.f("ck_snmp_queries_indicator_required"),
        ),
        sa.CheckConstraint(
            "snmp_version IN ('1', '2c', '3')", name=op.f("ck_snmp_queries_snmp_version")
        ),
        sa.CheckConstraint(
            "row_count >= 0 AND rejected_count >= 0 AND rejected_count <= row_count AND request_count >= 0 AND duration_ms >= 0",
            name=op.f("ck_snmp_queries_counts"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_snmp_queries_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["collection_runs.id"], name=op.f("fk_snmp_queries_run_id")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_snmp_queries")),
        sa.UniqueConstraint("id", "device_id", name=op.f("uq_snmp_queries_id_device_id")),
    )
    op.create_index(
        "ix_snmp_queries_latest",
        "snmp_queries",
        ["device_id", "mib_object", sa.literal_column("started_at DESC")],
        unique=False,
    )
    op.create_index(op.f("ix_snmp_queries_run_id"), "snmp_queries", ["run_id"], unique=False)
    for name, column in DEVICE_QUERY_FKS:
        op.create_foreign_key(name, "devices", "snmp_queries", [column, "id"], ["id", "device_id"])
    op.create_table(
        "identity_conflicts",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("key_method", sa.String(length=16), nullable=False),
        sa.Column("key_value", sa.String(length=255), nullable=False),
        sa.Column("device_id", sa.BigInteger(), nullable=False),
        sa.Column("other_device_id", sa.BigInteger(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("query_id", sa.BigInteger(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("needs_review", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.CheckConstraint(
            "key_method IN ('chassis-id', 'address')", name=op.f("ck_identity_conflicts_key_method")
        ),
        sa.CheckConstraint(
            "device_id <> other_device_id", name=op.f("ck_identity_conflicts_two_devices")
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_identity_conflicts_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["other_device_id"], ["devices.id"], name=op.f("fk_identity_conflicts_other_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["query_id"], ["snmp_queries.id"], name=op.f("fk_identity_conflicts_query_id")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_identity_conflicts")),
        sa.UniqueConstraint(
            "key_method",
            "key_value",
            "device_id",
            "other_device_id",
            name=op.f("uq_identity_conflicts_key_method_key_value_device_id_other_device_id"),
        ),
    )
    op.create_table(
        "identity_resolutions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("device_id", sa.BigInteger(), nullable=False),
        sa.Column("key_value", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("method", sa.String(length=64), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_query_id", sa.BigInteger(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_query_id", sa.BigInteger(), nullable=False),
        sa.Column("last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(carried) = 'object'",
            name=op.f("ck_identity_resolutions_resolution_carried"),
        ),
        sa.CheckConstraint(
            "method IN ('chassis-id', 'address')",
            name=op.f("ck_identity_resolutions_identity_method"),
        ),
        sa.CheckConstraint(
            "origin <> 'inferred' OR (method IS NOT NULL AND evidence IS NOT NULL AND jsonb_path_exists(evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_identity_resolutions_resolution_inferred"),
        ),
        sa.CheckConstraint(
            "origin = 'inferred'", name=op.f("ck_identity_resolutions_always_inferred")
        ),
        sa.CheckConstraint(
            "origin IN ('observed', 'inferred')",
            name=op.f("ck_identity_resolutions_resolution_origin"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'conflicted')",
            name=op.f("ck_identity_resolutions_resolution_status"),
        ),
        sa.CheckConstraint(
            "evidence IS NULL OR method IS NOT NULL",
            name=op.f("ck_identity_resolutions_resolution_evidence_method"),
        ),
        sa.CheckConstraint(
            "last_seen_at >= first_seen_at",
            name=op.f("ck_identity_resolutions_resolution_seen_order"),
        ),
        sa.CheckConstraint(
            "num_nulls(origin, first_seen_at, first_query_id, last_seen_at, last_query_id) = 0 OR (num_nulls(origin, first_seen_at, first_query_id, last_seen_at, last_query_id, method, evidence) = 7 AND last_complete_query_id IS NULL)",
            name=op.f("ck_identity_resolutions_resolution_all_or_none"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_identity_resolutions_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_identity_resolutions_resolution_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_identity_resolutions_resolution_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_identity_resolutions_resolution_last_query",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_identity_resolutions")),
        sa.UniqueConstraint(
            "method",
            "key_value",
            "device_id",
            name=op.f("uq_identity_resolutions_method_key_value_device_id"),
        ),
    )
    op.create_table(
        "interfaces",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("device_id", sa.BigInteger(), nullable=False),
        sa.Column("if_index", sa.Integer(), nullable=False),
        sa.Column("if_descr", sa.String(length=1024), nullable=True),
        sa.Column("if_type", sa.Integer(), nullable=True),
        sa.Column("if_speed", sa.BigInteger(), nullable=True),
        sa.Column("phys_address", postgresql.MACADDR(), nullable=True),
        sa.Column("admin_status", sa.SmallInteger(), nullable=True),
        sa.Column("oper_status", sa.SmallInteger(), nullable=True),
        sa.Column("last_change", sa.BigInteger(), nullable=True),
        sa.Column("if_name", sa.String(length=255), nullable=True),
        sa.Column("if_alias", sa.String(length=1024), nullable=True),
        sa.Column("if_high_speed", sa.BigInteger(), nullable=True),
        sa.Column("speed_bps", sa.BigInteger(), nullable=True),
        sa.Column("base_origin", sa.String(length=16), nullable=True),
        sa.Column("base_method", sa.String(length=64), nullable=True),
        sa.Column("base_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("base_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("base_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("base_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("base_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("base_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "base_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("ext_origin", sa.String(length=16), nullable=True),
        sa.Column("ext_method", sa.String(length=64), nullable=True),
        sa.Column("ext_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ext_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ext_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("ext_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ext_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("ext_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "ext_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("speed_origin", sa.String(length=16), nullable=True),
        sa.Column("speed_method", sa.String(length=64), nullable=True),
        sa.Column("speed_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("speed_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("speed_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("speed_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("speed_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("speed_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "speed_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "base_origin <> 'inferred' OR (base_method IS NOT NULL AND base_evidence IS NOT NULL AND jsonb_path_exists(base_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_interfaces_base_inferred"),
        ),
        sa.CheckConstraint(
            "base_origin IN ('observed', 'inferred')", name=op.f("ck_interfaces_base_origin")
        ),
        sa.CheckConstraint(
            "ext_origin <> 'inferred' OR (ext_method IS NOT NULL AND ext_evidence IS NOT NULL AND jsonb_path_exists(ext_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_interfaces_ext_inferred"),
        ),
        sa.CheckConstraint(
            "ext_origin IN ('observed', 'inferred')", name=op.f("ck_interfaces_ext_origin")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(base_carried) = 'object'", name=op.f("ck_interfaces_base_carried")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(ext_carried) = 'object'", name=op.f("ck_interfaces_ext_carried")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(speed_carried) = 'object'", name=op.f("ck_interfaces_speed_carried")
        ),
        sa.CheckConstraint(
            "speed_origin <> 'inferred' OR (speed_method IS NOT NULL AND speed_evidence IS NOT NULL AND jsonb_path_exists(speed_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_interfaces_speed_inferred"),
        ),
        sa.CheckConstraint(
            "speed_origin IN ('observed', 'inferred')", name=op.f("ck_interfaces_speed_origin")
        ),
        sa.CheckConstraint(
            "base_evidence IS NULL OR base_method IS NOT NULL",
            name=op.f("ck_interfaces_base_evidence_method"),
        ),
        sa.CheckConstraint(
            "base_last_seen_at >= base_first_seen_at", name=op.f("ck_interfaces_base_seen_order")
        ),
        sa.CheckConstraint(
            "ext_evidence IS NULL OR ext_method IS NOT NULL",
            name=op.f("ck_interfaces_ext_evidence_method"),
        ),
        sa.CheckConstraint(
            "ext_last_seen_at >= ext_first_seen_at", name=op.f("ck_interfaces_ext_seen_order")
        ),
        sa.CheckConstraint(
            "if_index BETWEEN 1 AND 2147483647", name=op.f("ck_interfaces_if_index")
        ),
        sa.CheckConstraint(
            "num_nulls(base_origin, base_first_seen_at, base_first_query_id, base_last_seen_at, base_last_query_id) = 0 OR (num_nulls(base_origin, base_first_seen_at, base_first_query_id, base_last_seen_at, base_last_query_id, base_method, base_evidence) = 7 AND base_last_complete_query_id IS NULL)",
            name=op.f("ck_interfaces_base_all_or_none"),
        ),
        sa.CheckConstraint(
            "num_nulls(ext_origin, ext_first_seen_at, ext_first_query_id, ext_last_seen_at, ext_last_query_id) = 0 OR (num_nulls(ext_origin, ext_first_seen_at, ext_first_query_id, ext_last_seen_at, ext_last_query_id, ext_method, ext_evidence) = 7 AND ext_last_complete_query_id IS NULL)",
            name=op.f("ck_interfaces_ext_all_or_none"),
        ),
        sa.CheckConstraint(
            "num_nulls(speed_origin, speed_first_seen_at, speed_first_query_id, speed_last_seen_at, speed_last_query_id) = 0 OR (num_nulls(speed_origin, speed_first_seen_at, speed_first_query_id, speed_last_seen_at, speed_last_query_id, speed_method, speed_evidence) = 7 AND speed_last_complete_query_id IS NULL)",
            name=op.f("ck_interfaces_speed_all_or_none"),
        ),
        sa.CheckConstraint(
            "speed_evidence IS NULL OR speed_method IS NOT NULL",
            name=op.f("ck_interfaces_speed_evidence_method"),
        ),
        sa.CheckConstraint(
            "speed_last_seen_at >= speed_first_seen_at", name=op.f("ck_interfaces_speed_seen_order")
        ),
        sa.ForeignKeyConstraint(
            ["base_first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_base_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["base_last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_base_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["base_last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_base_last_query",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_interfaces_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["ext_first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_ext_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["ext_last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_ext_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["ext_last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_ext_last_query",
        ),
        sa.ForeignKeyConstraint(
            ["speed_first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_speed_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["speed_last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_speed_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["speed_last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_interfaces_speed_last_query",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_interfaces")),
        sa.UniqueConstraint("device_id", "if_index", name=op.f("uq_interfaces_device_id_if_index")),
        sa.UniqueConstraint("id", "device_id", name=op.f("uq_interfaces_id_device_id")),
    )
    op.create_table(
        "run_devices",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("device_id", sa.BigInteger(), nullable=True),
        sa.Column("target_address", postgresql.INET(), nullable=False),
        sa.Column("reached_via", sa.String(length=8), nullable=False),
        sa.Column("depth", sa.SmallInteger(), nullable=False),
        sa.Column("first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("answered", sa.Boolean(), nullable=False),
        sa.CheckConstraint(
            "reached_via IN ('seed', 'lldp', 'cdp', 'ip-mac')",
            name=op.f("ck_run_devices_reached_via"),
        ),
        sa.CheckConstraint("depth >= 0", name=op.f("ck_run_devices_depth")),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_run_devices_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["first_query_id"], ["snmp_queries.id"], name=op.f("fk_run_devices_first_query_id")
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["collection_runs.id"], name=op.f("fk_run_devices_run_id")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_run_devices")),
        sa.UniqueConstraint(
            "run_id", "target_address", name=op.f("uq_run_devices_run_id_target_address")
        ),
    )
    op.create_table(
        "device_addresses",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("device_id", sa.BigInteger(), nullable=False),
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("if_index", sa.Integer(), nullable=True),
        sa.Column("interface_id", sa.BigInteger(), nullable=True),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("method", sa.String(length=64), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_query_id", sa.BigInteger(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_query_id", sa.BigInteger(), nullable=False),
        sa.Column("last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(carried) = 'object'", name=op.f("ck_device_addresses_address_carried")
        ),
        sa.CheckConstraint(
            "origin <> 'inferred' OR (method IS NOT NULL AND evidence IS NOT NULL AND jsonb_path_exists(evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_device_addresses_address_inferred"),
        ),
        sa.CheckConstraint(
            "origin IN ('observed', 'inferred')", name=op.f("ck_device_addresses_address_origin")
        ),
        sa.CheckConstraint(
            "source IN ('address_table', 'management')", name=op.f("ck_device_addresses_source")
        ),
        sa.CheckConstraint(
            "evidence IS NULL OR method IS NOT NULL",
            name=op.f("ck_device_addresses_address_evidence_method"),
        ),
        sa.CheckConstraint(
            "last_seen_at >= first_seen_at", name=op.f("ck_device_addresses_address_seen_order")
        ),
        sa.CheckConstraint(
            "num_nulls(origin, first_seen_at, first_query_id, last_seen_at, last_query_id) = 0 OR (num_nulls(origin, first_seen_at, first_query_id, last_seen_at, last_query_id, method, evidence) = 7 AND last_complete_query_id IS NULL)",
            name=op.f("ck_device_addresses_address_all_or_none"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_device_addresses_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_device_addresses_address_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["interface_id", "device_id"],
            ["interfaces.id", "interfaces.device_id"],
            name="fk_device_addresses_interface_id",
        ),
        sa.ForeignKeyConstraint(
            ["last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_device_addresses_address_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_device_addresses_address_last_query",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_device_addresses")),
        sa.UniqueConstraint(
            "device_id",
            "address",
            "source",
            name=op.f("uq_device_addresses_device_id_address_source"),
        ),
    )
    op.create_table(
        "ip_mac_entries",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("device_id", sa.BigInteger(), nullable=False),
        sa.Column("if_index", sa.Integer(), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column("mac_address", postgresql.MACADDR(), nullable=False),
        sa.Column("entry_type", sa.String(length=16), nullable=False),
        sa.Column("interface_id", sa.BigInteger(), nullable=True),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("method", sa.String(length=64), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_query_id", sa.BigInteger(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_query_id", sa.BigInteger(), nullable=False),
        sa.Column("last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "entry_type IN ('other', 'dynamic', 'static', 'local')",
            name=op.f("ck_ip_mac_entries_entry_type"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(carried) = 'object'", name=op.f("ck_ip_mac_entries_entry_carried")
        ),
        sa.CheckConstraint(
            "origin <> 'inferred' OR (method IS NOT NULL AND evidence IS NOT NULL AND jsonb_path_exists(evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_ip_mac_entries_entry_inferred"),
        ),
        sa.CheckConstraint(
            "origin IN ('observed', 'inferred')", name=op.f("ck_ip_mac_entries_entry_origin")
        ),
        sa.CheckConstraint(
            "evidence IS NULL OR method IS NOT NULL",
            name=op.f("ck_ip_mac_entries_entry_evidence_method"),
        ),
        sa.CheckConstraint(
            "last_seen_at >= first_seen_at", name=op.f("ck_ip_mac_entries_entry_seen_order")
        ),
        sa.CheckConstraint(
            "num_nulls(origin, first_seen_at, first_query_id, last_seen_at, last_query_id) = 0 OR (num_nulls(origin, first_seen_at, first_query_id, last_seen_at, last_query_id, method, evidence) = 7 AND last_complete_query_id IS NULL)",
            name=op.f("ck_ip_mac_entries_entry_all_or_none"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_ip_mac_entries_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_ip_mac_entries_entry_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["interface_id", "device_id"],
            ["interfaces.id", "interfaces.device_id"],
            name="fk_ip_mac_entries_interface_id",
        ),
        sa.ForeignKeyConstraint(
            ["last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_ip_mac_entries_entry_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_ip_mac_entries_entry_last_query",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ip_mac_entries")),
        sa.UniqueConstraint(
            "device_id",
            "if_index",
            "ip_address",
            name=op.f("uq_ip_mac_entries_device_id_if_index_ip_address"),
        ),
    )
    op.create_table(
        "neighbor_entries",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("device_id", sa.BigInteger(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("local_port_num", sa.Integer(), nullable=False),
        sa.Column("remote_index", sa.Integer(), nullable=False),
        sa.Column("remote_chassis_id_subtype", sa.SmallInteger(), nullable=True),
        sa.Column("remote_chassis_id", sa.String(length=255), nullable=True),
        sa.Column("remote_port_id_subtype", sa.SmallInteger(), nullable=True),
        sa.Column("remote_port_id", sa.String(length=255), nullable=True),
        sa.Column("remote_sys_name", sa.String(length=255), nullable=True),
        sa.Column("remote_port_desc", sa.String(length=1024), nullable=True),
        sa.Column("remote_capabilities", sa.String(length=255), nullable=True),
        sa.Column("man_addresses", postgresql.ARRAY(postgresql.INET()), nullable=True),
        sa.Column("local_port_id_subtype", sa.SmallInteger(), nullable=True),
        sa.Column("local_port_id", sa.String(length=255), nullable=True),
        sa.Column("local_interface_id", sa.BigInteger(), nullable=True),
        sa.Column("local_map_failure", sa.String(length=64), nullable=True),
        sa.Column("entry_origin", sa.String(length=16), nullable=True),
        sa.Column("entry_method", sa.String(length=64), nullable=True),
        sa.Column("entry_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("entry_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("entry_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("entry_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("entry_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("entry_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "entry_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("man_addr_origin", sa.String(length=16), nullable=True),
        sa.Column("man_addr_method", sa.String(length=64), nullable=True),
        sa.Column("man_addr_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("man_addr_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("man_addr_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("man_addr_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("man_addr_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("man_addr_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "man_addr_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("local_map_origin", sa.String(length=16), nullable=True),
        sa.Column("local_map_method", sa.String(length=64), nullable=True),
        sa.Column("local_map_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("local_map_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("local_map_first_query_id", sa.BigInteger(), nullable=True),
        sa.Column("local_map_last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("local_map_last_query_id", sa.BigInteger(), nullable=True),
        sa.Column("local_map_last_complete_query_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "local_map_carried",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "entry_origin <> 'inferred' OR (entry_method IS NOT NULL AND entry_evidence IS NOT NULL AND jsonb_path_exists(entry_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_neighbor_entries_entry_inferred"),
        ),
        sa.CheckConstraint(
            "entry_origin IN ('observed', 'inferred')",
            name=op.f("ck_neighbor_entries_entry_origin"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(entry_carried) = 'object'", name=op.f("ck_neighbor_entries_entry_carried")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(local_map_carried) = 'object'",
            name=op.f("ck_neighbor_entries_local_map_carried"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(man_addr_carried) = 'object'",
            name=op.f("ck_neighbor_entries_man_addr_carried"),
        ),
        sa.CheckConstraint(
            "local_map_origin <> 'inferred' OR (local_map_method IS NOT NULL AND local_map_evidence IS NOT NULL AND jsonb_path_exists(local_map_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_neighbor_entries_local_map_inferred"),
        ),
        sa.CheckConstraint(
            "local_map_origin IN ('observed', 'inferred')",
            name=op.f("ck_neighbor_entries_local_map_origin"),
        ),
        sa.CheckConstraint(
            "man_addr_origin <> 'inferred' OR (man_addr_method IS NOT NULL AND man_addr_evidence IS NOT NULL AND jsonb_path_exists(man_addr_evidence, '$.inputs[*].snapshot'))",
            name=op.f("ck_neighbor_entries_man_addr_inferred"),
        ),
        sa.CheckConstraint(
            "man_addr_origin IN ('observed', 'inferred')",
            name=op.f("ck_neighbor_entries_man_addr_origin"),
        ),
        sa.CheckConstraint(
            "protocol IN ('lldp', 'cdp')", name=op.f("ck_neighbor_entries_protocol")
        ),
        sa.CheckConstraint(
            "entry_evidence IS NULL OR entry_method IS NOT NULL",
            name=op.f("ck_neighbor_entries_entry_evidence_method"),
        ),
        sa.CheckConstraint(
            "entry_last_seen_at >= entry_first_seen_at",
            name=op.f("ck_neighbor_entries_entry_seen_order"),
        ),
        sa.CheckConstraint(
            "local_map_evidence IS NULL OR local_map_method IS NOT NULL",
            name=op.f("ck_neighbor_entries_local_map_evidence_method"),
        ),
        sa.CheckConstraint(
            "local_map_last_seen_at >= local_map_first_seen_at",
            name=op.f("ck_neighbor_entries_local_map_seen_order"),
        ),
        sa.CheckConstraint(
            "man_addr_evidence IS NULL OR man_addr_method IS NOT NULL",
            name=op.f("ck_neighbor_entries_man_addr_evidence_method"),
        ),
        sa.CheckConstraint(
            "man_addr_last_seen_at >= man_addr_first_seen_at",
            name=op.f("ck_neighbor_entries_man_addr_seen_order"),
        ),
        sa.CheckConstraint(
            "num_nulls(entry_origin, entry_first_seen_at, entry_first_query_id, entry_last_seen_at, entry_last_query_id) = 0 OR (num_nulls(entry_origin, entry_first_seen_at, entry_first_query_id, entry_last_seen_at, entry_last_query_id, entry_method, entry_evidence) = 7 AND entry_last_complete_query_id IS NULL)",
            name=op.f("ck_neighbor_entries_entry_all_or_none"),
        ),
        sa.CheckConstraint(
            "num_nulls(local_map_origin, local_map_first_seen_at, local_map_first_query_id, local_map_last_seen_at, local_map_last_query_id) = 0 OR (num_nulls(local_map_origin, local_map_first_seen_at, local_map_first_query_id, local_map_last_seen_at, local_map_last_query_id, local_map_method, local_map_evidence) = 7 AND local_map_last_complete_query_id IS NULL)",
            name=op.f("ck_neighbor_entries_local_map_all_or_none"),
        ),
        sa.CheckConstraint(
            "num_nulls(man_addr_origin, man_addr_first_seen_at, man_addr_first_query_id, man_addr_last_seen_at, man_addr_last_query_id) = 0 OR (num_nulls(man_addr_origin, man_addr_first_seen_at, man_addr_first_query_id, man_addr_last_seen_at, man_addr_last_query_id, man_addr_method, man_addr_evidence) = 7 AND man_addr_last_complete_query_id IS NULL)",
            name=op.f("ck_neighbor_entries_man_addr_all_or_none"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.id"], name=op.f("fk_neighbor_entries_device_id")
        ),
        sa.ForeignKeyConstraint(
            ["entry_first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_entry_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["entry_last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_entry_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["entry_last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_entry_last_query",
        ),
        sa.ForeignKeyConstraint(
            ["local_interface_id", "device_id"],
            ["interfaces.id", "interfaces.device_id"],
            name="fk_neighbor_entries_local_interface_id",
        ),
        sa.ForeignKeyConstraint(
            ["local_map_first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_local_map_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["local_map_last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_local_map_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["local_map_last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_local_map_last_query",
        ),
        sa.ForeignKeyConstraint(
            ["man_addr_first_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_man_addr_first_query",
        ),
        sa.ForeignKeyConstraint(
            ["man_addr_last_complete_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_man_addr_last_complete_query",
        ),
        sa.ForeignKeyConstraint(
            ["man_addr_last_query_id", "device_id"],
            ["snmp_queries.id", "snmp_queries.device_id"],
            name="fk_neighbor_entries_man_addr_last_query",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_neighbor_entries")),
        sa.UniqueConstraint(
            "device_id",
            "protocol",
            "local_port_num",
            "remote_index",
            name=op.f("uq_neighbor_entries_device_id_protocol_local_port_num_remote_index"),
        ),
    )


def downgrade() -> None:
    for name, _ in DEVICE_QUERY_FKS:
        op.drop_constraint(name, "devices", type_="foreignkey")
    op.drop_table("neighbor_entries")
    op.drop_table("ip_mac_entries")
    op.drop_table("device_addresses")
    op.drop_table("run_devices")
    op.drop_table("interfaces")
    op.drop_table("identity_resolutions")
    op.drop_table("identity_conflicts")
    op.drop_index(op.f("ix_snmp_queries_run_id"), table_name="snmp_queries")
    op.drop_index("ix_snmp_queries_latest", table_name="snmp_queries")
    op.drop_table("snmp_queries")
    op.drop_table("evaluation_snapshots")
    op.drop_table("devices")
    op.drop_table("collection_runs")
