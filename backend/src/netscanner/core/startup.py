# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Common start-up for every process: validated settings, then safe logging."""

from __future__ import annotations

import logging

from netscanner.core.config import Settings, load_settings_or_exit
from netscanner.core.logging_setup import configure_logging


def bootstrap(service: str) -> Settings:
    """Load the settings (or exit with a safe message) and configure logging."""
    settings = load_settings_or_exit()
    configure_logging(settings.log_level, settings.secret_values())
    logging.getLogger(f"netscanner.{service}").info("configuration loaded: %s", settings)
    return settings
