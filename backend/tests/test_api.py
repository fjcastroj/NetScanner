# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Health endpoint, recovery after a database outage and generic errors."""

from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient

from netscanner.api.app import HEALTH_DEGRADED, HEALTH_OK, create_app
from netscanner.core.config import Settings
from netscanner.core.logging_setup import configure_logging

from .conftest import REFUSED, Canaries, TestDatabase, db_settings, make_settings
from .tcp_proxy import TcpProxy


def client_for(settings: Settings) -> TestClient:
    configure_logging("INFO", settings.secret_values())
    return TestClient(create_app(settings), raise_server_exceptions=False)


def assert_degraded(response, *forbidden: str) -> None:
    assert response.status_code == 503
    assert response.json() == HEALTH_DEGRADED
    for text in forbidden:
        assert text not in response.text
    assert "Traceback" not in response.text


@pytest.mark.db
def test_health_ok_with_database(canaries: Canaries, test_db: TestDatabase) -> None:
    with client_for(db_settings(canaries, test_db)) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == HEALTH_OK


def test_health_degraded_when_database_refuses(
    capsys: pytest.CaptureFixture[str], canaries: Canaries, closed_port: int
) -> None:
    with client_for(make_settings(canaries, db_port=closed_port)) as client:
        response = client.get("/api/health")
    assert_degraded(response, "127.0.0.1", str(closed_port), "postgresql")
    err = capsys.readouterr().err
    assert re.search(r"database unavailable " + REFUSED, err)
    canaries.assert_absent(response.text, err)


def test_health_degraded_when_host_unknown(
    capsys: pytest.CaptureFixture[str], canaries: Canaries
) -> None:
    host = "netscanner-db.invalid"
    with client_for(make_settings(canaries, db_host=host)) as client:
        response = client.get("/api/health")
    assert_degraded(response, host)
    err = capsys.readouterr().err
    assert "database unavailable (" in err
    assert host not in err
    canaries.assert_absent(response.text, err)


@pytest.mark.db
def test_wrong_password_reported_without_canary(
    capsys: pytest.CaptureFixture[str], canaries: Canaries, test_db: TestDatabase
) -> None:
    settings = db_settings(canaries, test_db, db_password=canaries.db_password)
    with client_for(settings) as client:
        response = client.get("/api/health")
    assert_degraded(response, test_db.host)
    err = capsys.readouterr().err
    assert "database unavailable (authentication failed)" in err
    canaries.assert_absent(response.text, err)


@pytest.mark.db
def test_health_recovers_after_database_returns(canaries: Canaries, test_db: TestDatabase) -> None:
    proxy = TcpProxy(test_db.host, test_db.port)
    proxy.start()
    try:
        settings = db_settings(canaries, test_db, db_host="127.0.0.1", db_port=proxy.port)
        with client_for(settings) as client:
            assert client.get("/api/health").status_code == 200
            proxy.stop()
            assert_degraded(client.get("/api/health"))
            proxy.start()
            deadline = time.monotonic() + 30
            while (status := client.get("/api/health").status_code) != 200:
                assert time.monotonic() < deadline, "health did not recover"
                time.sleep(0.5)
            assert status == 200
    finally:
        proxy.stop()


def test_unhandled_exception_gives_generic_500(
    capsys: pytest.CaptureFixture[str], canaries: Canaries, closed_port: int
) -> None:
    settings = make_settings(canaries, db_port=closed_port)
    configure_logging("INFO", settings.secret_values())
    app = create_app(settings)

    @app.get("/api/boom")
    async def boom() -> None:
        raise RuntimeError(f"internal detail {canaries.secret_key} {canaries.db_password}")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/boom")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    err = capsys.readouterr().err
    assert "unhandled error in GET /api/boom" in err
    assert "RuntimeError: internal detail *** ***" in err
    canaries.assert_absent(response.text, err)


def test_no_api_docs_exposed(canaries: Canaries, closed_port: int) -> None:
    with client_for(make_settings(canaries, db_port=closed_port)) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404
