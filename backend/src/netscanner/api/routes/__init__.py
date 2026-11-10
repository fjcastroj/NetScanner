# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""API routers under ``/api`` (design D10)."""

from __future__ import annotations

from fastapi import APIRouter

from netscanner.api.routes import inventory, runs, settings, status

router = APIRouter(prefix="/api")
for module in (status, settings, runs, inventory):
    router.include_router(module.router)

__all__ = ["router"]
