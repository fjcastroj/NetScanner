# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Entry point of the one-shot ``migrate`` service (design D7).

Runs ``alembic upgrade head`` and exits; a database failure is reported by
category only and gives a non-zero exit code so ``api`` and ``collector`` are
not started.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from netscanner.core.config import Settings
from netscanner.core.db import classify_db_error
from netscanner.core.startup import bootstrap

MIGRATIONS = Path(__file__).resolve().parent / "migrations"

log = logging.getLogger("netscanner.migrate")


def alembic_config(settings: Settings) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.attributes["settings"] = settings
    return config


def upgrade(settings: Settings) -> int:
    try:
        command.upgrade(alembic_config(settings), "head")
    except Exception as exc:
        log.error("migration failed: %s (%s)", type(exc).__name__, classify_db_error(exc))
        return 1
    log.info("database schema at the latest revision")
    return 0


def main() -> None:
    sys.exit(upgrade(bootstrap("migrate")))


if __name__ == "__main__":
    main()
