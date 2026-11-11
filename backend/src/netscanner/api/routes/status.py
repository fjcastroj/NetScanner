# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""``GET /api/status`` (public): authentication is enabled, and whether the
administrator exists. Nothing else about the account or any session.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from netscanner.auth.guard import auth_service

router = APIRouter()


@router.get("/status")
async def status(request: Request) -> dict:
    return {"authentication": True, "admin_exists": await auth_service(request).admin_exists()}
