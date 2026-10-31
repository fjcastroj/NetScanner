# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Collector placeholder (design D8): keeps a database connection and idles.

Later changes give it SNMP work; for now it proves the process boundary, the
reconnection logic (design D12) and clean shutdown.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.config import Settings
from netscanner.core.db import classify_db_error, create_engine, ping

log = logging.getLogger("netscanner.collector")

BACKOFF_INITIAL = 1.0
BACKOFF_MAX = 30.0


def next_backoff(delay: float) -> float:
    return min(delay * 2, BACKOFF_MAX)


def touch(path: Path | None) -> None:
    if path is not None:
        path.touch()


async def run_collector(
    settings: Settings,
    stop: asyncio.Event,
    *,
    engine: AsyncEngine | None = None,
) -> None:
    """Run until ``stop`` is set, reconnecting with exponential backoff."""
    engine = engine or create_engine(settings)
    connected: bool | None = None  # unknown before the first attempt
    delay = BACKOFF_INITIAL
    log.info("collector started")
    try:
        while not stop.is_set():
            touch(settings.collector_heartbeat_file)
            try:
                await ping(engine, settings.db_connect_timeout)
            except Exception as exc:
                category = classify_db_error(exc)
                if connected:
                    log.warning("database connection lost (%s)", category)
                log.warning("database unavailable (%s), retrying in %.0f s", category, delay)
                connected = False
                wait = delay
                delay = next_backoff(delay)
            else:
                if not connected:
                    log.info("database connected; collector idle, no work configured")
                connected = True
                delay = BACKOFF_INITIAL
                wait = settings.collector_check_interval
            try:
                await asyncio.wait_for(stop.wait(), timeout=wait)
            except TimeoutError:
                pass
    finally:
        await engine.dispose()
        log.info("collector stopped")
