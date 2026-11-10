# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Collector: start, idle, reconnect with backoff, clean stop; claiming runs (design D7)."""

from __future__ import annotations

import asyncio
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from netscanner.collector import healthcheck
from netscanner.collector.service import BACKOFF_INITIAL, BACKOFF_MAX, next_backoff, run_collector
from netscanner.core.config import ENV_PREFIX, Settings
from netscanner.core.logging_setup import configure_logging

from .conftest import REFUSED, Canaries, TestDatabase, db_settings, make_settings
from .tcp_proxy import TcpProxy


async def wait_for_text(capsys: pytest.CaptureFixture[str], text: str, timeout: float) -> str:
    seen = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        seen += capsys.readouterr().err
        if text in seen:
            return seen
        await asyncio.sleep(0.05)
    raise AssertionError(f"{text!r} not logged; got:\n{seen}")


def test_backoff_doubles_up_to_thirty_seconds() -> None:
    delays = [BACKOFF_INITIAL]
    for _ in range(7):
        delays.append(next_backoff(delays[-1]))
    assert delays == [1, 2, 4, 8, 16, 30, 30, 30]
    assert BACKOFF_MAX == 30


@pytest.mark.db
async def test_collector_idles_and_stops_cleanly(
    capsys: pytest.CaptureFixture[str],
    canaries: Canaries,
    test_db: TestDatabase,
    store_settings: Settings,
    tmp_path: Path,
) -> None:
    heartbeat = tmp_path / "heartbeat"
    # The collector reads runs, so it needs the migrated database (Compose runs migrate first).
    settings = db_settings(
        canaries, test_db, db_name=store_settings.db_name, collector_heartbeat_file=heartbeat
    )
    configure_logging("INFO", settings.secret_values())
    stop = asyncio.Event()
    task = asyncio.create_task(run_collector(settings, stop))
    await wait_for_text(capsys, "collector idle", timeout=10)
    assert healthcheck.main([str(heartbeat), "60"]) == 0
    stop.set()
    await asyncio.wait_for(task, timeout=5)
    err = await wait_for_text(capsys, "collector stopped", timeout=1)
    canaries.assert_absent(err)


async def test_collector_retries_when_database_refuses(
    capsys: pytest.CaptureFixture[str], canaries: Canaries, closed_port: int
) -> None:
    settings = make_settings(canaries, db_port=closed_port)
    configure_logging("INFO", settings.secret_values())
    stop = asyncio.Event()
    task = asyncio.create_task(run_collector(settings, stop))
    err = await wait_for_text(capsys, "retrying in 2 s", timeout=10)
    assert re.search(r"database unavailable " + REFUSED + r", retrying in 1 s", err)
    stop.set()
    await asyncio.wait_for(task, timeout=5)
    canaries.assert_absent(err, capsys.readouterr().err)


@pytest.mark.db
async def test_collector_logs_loss_and_reconnects(
    capsys: pytest.CaptureFixture[str],
    canaries: Canaries,
    test_db: TestDatabase,
    store_settings: Settings,
) -> None:
    proxy = TcpProxy(test_db.host, test_db.port)
    proxy.start()
    settings = db_settings(
        canaries,
        test_db,
        db_name=store_settings.db_name,
        db_host="127.0.0.1",
        db_port=proxy.port,
        collector_check_interval=0.2,
    )
    configure_logging("INFO", settings.secret_values())
    stop = asyncio.Event()
    task = asyncio.create_task(run_collector(settings, stop))
    try:
        await wait_for_text(capsys, "collector idle", timeout=10)
        proxy.stop()
        await wait_for_text(capsys, "database connection lost", timeout=10)
        proxy.start()
        await wait_for_text(capsys, "collector idle", timeout=15)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=5)
        proxy.stop()


@pytest.mark.db
async def test_collector_wrong_password_without_canary(
    capsys: pytest.CaptureFixture[str], canaries: Canaries, test_db: TestDatabase
) -> None:
    settings = db_settings(canaries, test_db, db_password=canaries.db_password)
    configure_logging("INFO", settings.secret_values())
    stop = asyncio.Event()
    task = asyncio.create_task(run_collector(settings, stop))
    err = await wait_for_text(capsys, "database unavailable (authentication failed)", timeout=10)
    stop.set()
    await asyncio.wait_for(task, timeout=5)
    canaries.assert_absent(err, capsys.readouterr().err)


def test_healthcheck_fails_without_recent_heartbeat(tmp_path: Path) -> None:
    path = tmp_path / "hb"
    assert healthcheck.main([str(path), "60"]) == 1
    path.touch()
    old = time.time() - 120
    os.utime(path, (old, old))
    assert healthcheck.main([str(path), "60"]) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM cannot be delivered gracefully")
def test_collector_process_exits_cleanly_on_sigterm(canaries: Canaries, closed_port: int) -> None:
    base = {k: v for k, v in os.environ.items() if not k.startswith(ENV_PREFIX)}
    env = {
        **base,
        "NETSCANNER_SECRET_KEY": canaries.secret_key,
        "NETSCANNER_DB_PASSWORD": canaries.db_password,
        "NETSCANNER_DB_HOST": "127.0.0.1",
        "NETSCANNER_DB_PORT": str(closed_port),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "netscanner.collector"],
        env=env,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stderr is not None
        for line in proc.stderr:
            if "retrying in" in line:
                break
        proc.send_signal(signal.SIGTERM)
        _, rest = proc.communicate(timeout=10)
    finally:
        proc.kill()
    assert proc.returncode == 0
    assert "collector stopped" in rest
    canaries.assert_absent(rest)
