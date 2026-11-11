# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Administrator and logged-in clients for API tests (add-admin-authentication).

The test client talks to ``https://testserver``, so the ``Secure`` session
cookie is kept exactly as a browser would keep it, and it sends the
``X-NetScanner-Request`` header that the web interface adds to every request.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.api.app import create_app
from netscanner.auth.account import create_account
from netscanner.core.config import Settings

ADMIN = "lab-admin"
# Random per test session: a lab test value, never a real password.
ADMIN_PASSWORD = "lab-" + secrets.token_urlsafe(18)
BASE_URL = "https://testserver"
HEADERS = {"X-NetScanner-Request": "1"}


async def create_admin(
    engine: AsyncEngine, username: str = ADMIN, password: str = ADMIN_PASSWORD
) -> None:
    await create_account(engine, username, password, datetime.now(UTC))


@contextmanager
def api_client(
    settings: Settings, *, headers: dict[str, str] | None = None
) -> Iterator[TestClient]:
    app = create_app(settings)
    with TestClient(
        app, base_url=BASE_URL, headers=HEADERS if headers is None else headers,
        raise_server_exceptions=False,
    ) as client:  # fmt: skip
        yield client


def login(client: TestClient, username: str = ADMIN, password: str = ADMIN_PASSWORD) -> None:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
