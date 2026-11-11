# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Route protection and the session cookie (design D3, D4, D6).

``require_session`` and ``check_cross_site`` are dependencies of the whole
``/api`` router. Every route needs a valid session except the explicit public
list. Requests that change state need ``X-NetScanner-Request: 1`` and, when
an ``Origin`` is sent, an allowed origin from configuration. This is the only
module that reads or writes the session cookie (design D1).
"""

from __future__ import annotations

from fastapi import HTTPException, Request, Response

from netscanner.auth.service import AuthService
from netscanner.core.config import normalise_origin

COOKIE = "netscanner_session"
REQUEST_HEADER = "x-netscanner-request"
PUBLIC_ROUTES = frozenset(
    {
        ("GET", "/api/health"),
        ("GET", "/api/status"),
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/logout"),
    }
)
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
UNAUTHENTICATED = "authentication required"  # the same for a missing, unknown or expired session
CROSS_SITE = "request refused"


def auth_service(request: Request) -> AuthService:
    return request.app.state.auth


def is_public(request: Request) -> bool:
    """Whether the request is for a public route.

    The public routes have no path parameters, so the request path itself
    (the value routing matched) is compared, never a header.
    """
    return (request.method, request.scope["path"]) in PUBLIC_ROUTES


async def require_session(request: Request) -> None:
    if is_public(request):
        return
    session = await auth_service(request).session_for(request.cookies.get(COOKIE))
    if session is None:
        raise HTTPException(status_code=401, detail=UNAUTHENTICATED)
    request.state.session = session


async def check_cross_site(request: Request) -> None:
    if request.method not in STATE_CHANGING:
        return
    if request.headers.get(REQUEST_HEADER) != "1":
        raise HTTPException(status_code=403, detail=CROSS_SITE)
    origin = request.headers.get("origin")
    if origin is not None:
        try:
            allowed = normalise_origin(origin) in auth_service(request).origins
        except ValueError:
            allowed = False
        if not allowed:
            raise HTTPException(status_code=403, detail=CROSS_SITE)


def session_token(request: Request) -> str | None:
    return request.cookies.get(COOKIE)


def set_session_cookie(response: Response, token: str, secure: bool) -> None:
    # No Max-Age: the cookie ends with the browser; the server decides expiry.
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure, path="/")


def clear_session_cookie(response: Response, secure: bool) -> None:
    response.delete_cookie(COOKIE, path="/", secure=secure, httponly=True, samesite="strict")
