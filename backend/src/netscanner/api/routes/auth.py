# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Login, logout and the current session (design D4, D5).

``POST /auth/login`` and ``POST /auth/logout`` are public; ``GET
/auth/session`` needs a session. A failed login always gives the same body,
whatever was wrong.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from netscanner.api.common import Payload, message_response, problems_response
from netscanner.auth.guard import (
    auth_service,
    clear_session_cookie,
    session_token,
    set_session_cookie,
)
from netscanner.auth.limiter import source_address

router = APIRouter(prefix="/auth")

LOGIN_FAILED = "invalid user name or password"
TOO_MANY = "too many failed logins; try again later"
MAX_USERNAME = 64
MAX_PASSWORD = 1024


def _login_problems(payload: dict[str, Any]) -> list[tuple[str, str]]:
    problems = []
    for name, limit in (("username", MAX_USERNAME), ("password", MAX_PASSWORD)):
        value = payload.get(name)
        if not isinstance(value, str) or not value:
            problems.append((name, "is required"))
        elif len(value) > limit:
            problems.append((name, f"must have at most {limit} characters"))
    return problems


@router.post("/login", response_model=None)
async def login(payload: Payload, request: Request) -> JSONResponse:
    problems = _login_problems(payload)
    if problems:
        return problems_response(problems)
    auth = auth_service(request)
    source = source_address(
        request.headers.get("x-forwarded-for"), request.client.host if request.client else None
    )
    result = await auth.login(payload["username"], payload["password"], source)
    if result.outcome == "limited":
        response = message_response(TOO_MANY, 429)
        response.headers["Retry-After"] = str(result.retry_after)
        return response
    if result.outcome == "failed" or result.token is None or result.session is None:
        return message_response(LOGIN_FAILED, 401)
    response = JSONResponse(
        jsonable_encoder({"username": result.username, "expires_at": result.session.expires_at})
    )
    set_session_cookie(response, result.token, auth.cookie_secure)
    return response


@router.post("/logout", response_model=None)
async def logout(request: Request) -> JSONResponse:
    auth = auth_service(request)
    await auth.logout(session_token(request))
    response = JSONResponse({"detail": "logged out"})
    clear_session_cookie(response, auth.cookie_secure)
    return response


@router.get("/session")
async def current_session(request: Request) -> dict[str, Any]:
    session = request.state.session
    return jsonable_encoder(
        {"username": await auth_service(request).username(), "expires_at": session.expires_at}
    )
