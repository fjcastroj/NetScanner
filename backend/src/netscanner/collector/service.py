# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Collector: runs discovery runs (design D7 of add-discovery-and-basic-inventory).

At its first connection it marks runs left ``running`` by a previous process
as interrupted. Then, every ``collector_poll_interval`` seconds, it claims the
oldest pending discovery run (``FOR UPDATE SKIP LOCKED``), runs it and closes
it. The database connection is kept with the reconnection logic of design
D12 of setup-project-skeleton, and stopping is clean: a run cut by a stop
stays ``running`` and is marked interrupted at the next start.

The SNMP client comes from the factory ``netscanner.snmp.create_client``,
the only entry point to the client outside ``netscanner.snmp``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.config import Settings
from netscanner.core.db import classify_db_error, create_engine, ping
from netscanner.credential_store import CredentialResolver
from netscanner.discovery.runner import execute_run
from netscanner.scope import DiscoveryCeilings
from netscanner.snmp import SnmpClient, create_client
from netscanner.store.service import Store

log = logging.getLogger("netscanner.collector")

BACKOFF_INITIAL = 1.0
BACKOFF_MAX = 30.0


def next_backoff(delay: float) -> float:
    return min(delay * 2, BACKOFF_MAX)


def touch(path: Path | None) -> None:
    if path is not None:
        path.touch()


async def _heartbeat(path: Path | None, interval: float) -> None:
    while True:
        touch(path)
        await asyncio.sleep(interval)


async def _run_one(
    settings: Settings,
    store: Store,
    client: SnmpClient,
    resolver: CredentialResolver,
    stop: asyncio.Event,
) -> bool:
    """Claim and run one pending run; whether there was one."""
    run_id = await store.claim_pending_run()
    if run_id is None:
        return False
    log.info("discovery run %s started", run_id)
    ceilings = DiscoveryCeilings.from_settings(settings)
    beat = asyncio.create_task(
        _heartbeat(settings.collector_heartbeat_file, settings.collector_check_interval)
    )
    run = asyncio.create_task(execute_run(store, client, resolver, run_id, ceilings))
    stopping = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait({run, stopping}, return_when=asyncio.FIRST_COMPLETED)
        if not run.done():
            run.cancel()
            log.info("discovery run %s left running: stop requested", run_id)
        with contextlib.suppress(asyncio.CancelledError):
            status = await run
            log.info("discovery run %s %s", run_id, status)
    finally:
        beat.cancel()
        stopping.cancel()
    return True


async def run_collector(
    settings: Settings,
    stop: asyncio.Event,
    *,
    engine: AsyncEngine | None = None,
    client: SnmpClient | None = None,
) -> None:
    """Run until ``stop`` is set, reconnecting with exponential backoff.

    ``client`` is for tests only; the composition root uses the factory.
    """
    engine = engine or create_engine(settings)
    store = Store.from_settings(engine, settings)
    resolver = CredentialResolver(engine, settings.secret_key.get_secret_value())
    client = client or create_client(settings, resolver)
    connected: bool | None = None  # unknown before the first attempt
    interrupted_checked = False
    delay = BACKOFF_INITIAL
    log.info("collector started")
    try:
        while not stop.is_set():
            touch(settings.collector_heartbeat_file)
            try:
                await ping(engine, settings.db_connect_timeout)
                if not connected:
                    log.info("database connected; collector idle, waiting for runs")
                connected = True
                delay = BACKOFF_INITIAL
                if not interrupted_checked:
                    marked = await store.mark_interrupted_runs()
                    interrupted_checked = True
                    if marked:
                        log.info("runs marked interrupted: %s", marked)
                ran = await _run_one(settings, store, client, resolver, stop)
            except Exception as exc:
                category = classify_db_error(exc)
                if connected:
                    log.warning("database connection lost (%s)", category)
                log.warning("database unavailable (%s), retrying in %.0f s", category, delay)
                connected = False
                wait = delay
                delay = next_backoff(delay)
            else:
                if ran:
                    continue  # look for the next pending run at once
                wait = min(settings.collector_poll_interval, settings.collector_check_interval)
            try:
                await asyncio.wait_for(stop.wait(), timeout=wait)
            except TimeoutError:
                pass
    finally:
        await engine.dispose()
        log.info("collector stopped")
