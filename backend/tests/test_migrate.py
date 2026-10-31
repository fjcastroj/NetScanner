# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""One-shot migration step: idempotent upgrade, safe failure."""

from __future__ import annotations

import re

import pytest

from netscanner.core.logging_setup import configure_logging
from netscanner.migrate import upgrade

from .conftest import REFUSED, Canaries, TestDatabase, db_settings, make_settings


@pytest.mark.db
def test_upgrade_is_idempotent(
    capsys: pytest.CaptureFixture[str], canaries: Canaries, test_db: TestDatabase
) -> None:
    settings = db_settings(canaries, test_db)
    configure_logging("INFO", settings.secret_values())
    assert upgrade(settings) == 0
    assert upgrade(settings) == 0  # already at head: no change, still success
    assert capsys.readouterr().err.count("database schema at the latest revision") == 2


def test_failed_migration_exits_non_zero_without_canary(
    capsys: pytest.CaptureFixture[str], canaries: Canaries, closed_port: int
) -> None:
    settings = make_settings(canaries, db_port=closed_port)
    configure_logging("INFO", settings.secret_values())
    assert upgrade(settings) == 1
    err = capsys.readouterr().err
    assert "migration failed" in err
    assert re.search(REFUSED, err)
    canaries.assert_absent(err)
