# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Shared pieces of the API routes: dependencies and error bodies (design D10).

Validation errors give one ``{"field", "reason"}`` per problem and never the
submitted value, so a mistyped secret is not sent back.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Body, Depends, Request
from fastapi.responses import JSONResponse

from netscanner.credential_store import CredentialService
from netscanner.scope import DiscoveryCeilings
from netscanner.store.service import Store

DEFAULT_PAGE = 100
MAX_PAGE = 500


@dataclass(frozen=True)
class Services:
    store: Store
    credentials: CredentialService
    ceilings: DiscoveryCeilings


def services(request: Request) -> Services:
    return request.app.state.services


Svc = Annotated[Services, Depends(services)]
Payload = Annotated[dict[str, Any], Body()]


def problems_response(problems: list[tuple[str, str]], status_code: int = 422) -> JSONResponse:
    return JSONResponse(
        {"detail": [{"field": field, "reason": reason} for field, reason in problems]},
        status_code=status_code,
    )


def message_response(message: str, status_code: int) -> JSONResponse:
    return JSONResponse({"detail": message}, status_code=status_code)
