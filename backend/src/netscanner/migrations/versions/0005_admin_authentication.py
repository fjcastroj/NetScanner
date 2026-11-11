# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Administrator account, sessions and login attempts.

Migration Plan of add-admin-authentication: ``admin_account`` (one row at
most, a CHECK on a constant key), ``sessions`` (by token hash) and
``login_attempts``. No data migration: after upgrading, the operator creates
the administrator from the server console. Downgrade drops the three tables.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

USERNAME_PATTERN = "^[A-Za-z0-9._-]{1,64}$"


def upgrade() -> None:
    op.create_table(
        "admin_account",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name=op.f("ck_admin_account_single_row")),
        sa.CheckConstraint(
            f"username ~ '{USERNAME_PATTERN}'", name=op.f("ck_admin_account_username")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_account")),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_address", postgresql.INET(), nullable=True),
        sa.CheckConstraint("token_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_sessions_token_hash")),
        sa.CheckConstraint(
            "last_used_at >= created_at AND expires_at > created_at",
            name=op.f("ck_sessions_times"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sessions")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_sessions_token_hash")),
    )
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_address", postgresql.INET(), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_login_attempts")),
    )
    op.create_index("ix_login_attempts_source_at", "login_attempts", ["source_address", "at"])


def downgrade() -> None:
    op.drop_index("ix_login_attempts_source_at", table_name="login_attempts")
    op.drop_table("login_attempts")
    op.drop_table("sessions")
    op.drop_table("admin_account")
