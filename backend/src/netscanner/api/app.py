# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""FastAPI application: health, the routes of design D10 and generic error responses.

Request validation errors give the field and the reason only, never the
submitted value (design D10).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError, OperationalError

from netscanner.api.common import Services, problems_response
from netscanner.api.routes import router
from netscanner.core.config import Settings
from netscanner.core.db import classify_db_error, create_engine, ping
from netscanner.credential_store import CredentialService
from netscanner.scope import DiscoveryCeilings
from netscanner.store.service import Store

log = logging.getLogger("netscanner.api")

HEALTH_OK = {"status": "ok", "database": "ok"}
HEALTH_DEGRADED = {"status": "degraded", "database": "unavailable"}


def create_app(settings: Settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.engine = create_engine(settings)
        app.state.database_ok = None  # unknown until the first check
        app.state.services = Services(
            store=Store.from_settings(app.state.engine, settings),
            credentials=CredentialService(app.state.engine, settings.secret_key.get_secret_value()),
            ceilings=DiscoveryCeilings.from_settings(settings),
        )
        try:
            yield
        finally:
            await app.state.engine.dispose()

    app = FastAPI(
        title="NetScanner API",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/api/health")
    async def health(request: Request) -> JSONResponse:
        state = request.app.state
        try:
            await ping(state.engine, settings.db_connect_timeout)
        except Exception as exc:
            if state.database_ok is not False:
                log.warning("database unavailable (%s)", classify_db_error(exc))
            state.database_ok = False
            return JSONResponse(HEALTH_DEGRADED, status_code=503)
        if state.database_ok is False:
            log.info("database available again")
        state.database_ok = True
        return JSONResponse(HEALTH_OK)

    app.include_router(router)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        problems = []
        for error in exc.errors():
            location = [str(p) for p in error.get("loc", ())]
            if location and location[0] in ("body", "query", "path"):
                location = location[1:]
            problems.append((".".join(location) or "request", str(error.get("msg", "invalid"))))
        return problems_response(problems)

    @app.exception_handler(OperationalError)
    @app.exception_handler(DBAPIError)
    @app.exception_handler(OSError)
    async def database_unavailable(request: Request, exc: Exception) -> JSONResponse:
        log.warning(
            "request %s %s failed: database unavailable (%s)",
            request.method,
            request.url.path,
            classify_db_error(exc),
        )
        return JSONResponse({"detail": "Service unavailable"}, status_code=503)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # The traceback goes to the log through the secret masking filter; the
        # client only gets a generic body.
        log.error("unhandled error in %s %s", request.method, request.url.path, exc_info=exc)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    return app
