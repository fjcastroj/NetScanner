# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Discovery settings, the SNMP credential and candidate reasons.

Migration Plan of add-discovery-and-basic-inventory: ``snmp_credentials``,
``discovery_settings`` with its single row, ``run_devices.skip_reason`` and
``run_devices.found_from_device_id``, and the partial unique index that
allows one active discovery run. Downgrade drops them.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-08
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

SKIP_REASONS = (
    "'out_of_scope', 'excluded', 'special_address', 'already_known', 'max_depth', "
    "'limit_reached', 'no_response', 'auth_failed', 'query_error'"
)
# Initial settings row: nothing to query until the administrator saves a scope;
# limits at the default ceilings of design D6.
DEFAULT_ROW = {
    "id": 1,
    "max_depth": 1,
    "max_candidates": 4096,
    "max_devices": 256,
    "max_datagrams": 50000,
}


def upgrade() -> None:
    op.create_table(
        "snmp_credentials",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("version", sa.String(length=4), nullable=False),
        sa.Column("v3_user", sa.String(length=32), nullable=True),
        sa.Column("v3_level", sa.String(length=16), nullable=True),
        sa.Column("v3_auth_protocol", sa.String(length=16), nullable=True),
        sa.Column("v3_priv_protocol", sa.String(length=16), nullable=True),
        sa.Column("secret", sa.LargeBinary(), nullable=False),
        sa.Column("key_id", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.CheckConstraint("version IN ('v2c', 'v3')", name=op.f("ck_snmp_credentials_version")),
        sa.CheckConstraint(
            "(version = 'v2c' AND num_nonnulls(v3_user, v3_level, v3_auth_protocol, v3_priv_protocol) = 0) OR (version = 'v3' AND v3_user IS NOT NULL AND v3_level IS NOT NULL AND v3_auth_protocol IS NOT NULL)",
            name=op.f("ck_snmp_credentials_v3_fields"),
        ),
        sa.CheckConstraint("key_id ~ '^[0-9a-f]{32}$'", name=op.f("ck_snmp_credentials_key_id")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_snmp_credentials")),
    )
    op.create_index(
        "uq_snmp_credentials_one_active",
        "snmp_credentials",
        ["active"],
        unique=True,
        postgresql_where=sa.text("active"),
    )
    op.create_table(
        "discovery_settings",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column(
            "seeds",
            postgresql.ARRAY(postgresql.INET()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column(
            "allowed_ranges",
            postgresql.ARRAY(postgresql.CIDR()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column(
            "exclusions",
            postgresql.ARRAY(postgresql.CIDR()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("max_depth", sa.SmallInteger(), nullable=False),
        sa.Column("follow_ip_mac", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("max_candidates", sa.Integer(), nullable=False),
        sa.Column("max_devices", sa.Integer(), nullable=False),
        sa.Column("max_datagrams", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("id = 1", name=op.f("ck_discovery_settings_single_row")),
        sa.CheckConstraint(
            "max_depth BETWEEN 0 AND 32 AND max_candidates >= 1 AND max_devices >= 1 AND max_datagrams >= 1",
            name=op.f("ck_discovery_settings_limits"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_discovery_settings")),
    )
    settings = sa.table(
        "discovery_settings",
        *(sa.column(name) for name in DEFAULT_ROW),
    )
    op.bulk_insert(settings, [DEFAULT_ROW])

    op.add_column("run_devices", sa.Column("skip_reason", sa.String(length=32), nullable=True))
    op.add_column("run_devices", sa.Column("found_from_device_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        op.f("fk_run_devices_found_from_device_id"),
        "run_devices",
        "devices",
        ["found_from_device_id"],
        ["id"],
    )
    op.create_check_constraint(
        op.f("ck_run_devices_skip_reason"), "run_devices", f"skip_reason IN ({SKIP_REASONS})"
    )
    op.create_check_constraint(
        op.f("ck_run_devices_device_or_reason"),
        "run_devices",
        "device_id IS NULL OR skip_reason IS NULL",
    )
    op.create_index(
        "uq_collection_runs_one_active_discovery",
        "collection_runs",
        [sa.text("(true)")],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('pending', 'running') AND kind IN ('discovery', 'rediscovery')"
        ),
    )


def downgrade() -> None:
    op.drop_index("uq_collection_runs_one_active_discovery", table_name="collection_runs")
    op.drop_constraint(op.f("ck_run_devices_device_or_reason"), "run_devices", type_="check")
    op.drop_constraint(op.f("ck_run_devices_skip_reason"), "run_devices", type_="check")
    op.drop_constraint(
        op.f("fk_run_devices_found_from_device_id"), "run_devices", type_="foreignkey"
    )
    op.drop_column("run_devices", "found_from_device_id")
    op.drop_column("run_devices", "skip_reason")
    op.drop_table("discovery_settings")
    op.drop_index("uq_snmp_credentials_one_active", table_name="snmp_credentials")
    op.drop_table("snmp_credentials")
