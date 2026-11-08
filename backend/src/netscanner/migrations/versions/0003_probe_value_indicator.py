# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Indicator ``value_returned`` for an ambiguous column probe (add-snmp-client-and-lab, D4).

When a walk returns no rows and the column probe answers with a value instead
of ``noSuchObject`` or ``noSuchInstance``, the outcome is ``empty`` and the
actual answer is recorded so the case can be reviewed per vendor.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-08
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

NAME = "ck_snmp_queries_indicator"
BEFORE = "('noSuchObject', 'noSuchInstance', 'endOfMibView', 'end_of_subtree')"
AFTER = "('noSuchObject', 'noSuchInstance', 'endOfMibView', 'end_of_subtree', 'value_returned')"


def upgrade() -> None:
    op.drop_constraint(op.f(NAME), "snmp_queries", type_="check")
    op.create_check_constraint(op.f(NAME), "snmp_queries", f"indicator IN {AFTER}")


def downgrade() -> None:
    # Such rows cannot be relabelled without inventing an answer.
    count = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM snmp_queries WHERE indicator = 'value_returned'")
    )
    if count:
        raise RuntimeError("queries with indicator value_returned exist; downgrade refused")
    op.drop_constraint(op.f(NAME), "snmp_queries", type_="check")
    op.create_check_constraint(op.f(NAME), "snmp_queries", f"indicator IN {BEFORE}")
