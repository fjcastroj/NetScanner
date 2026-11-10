# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""``GET /api/status``: the application runs in lab mode without authentication."""

from __future__ import annotations

from fastapi import APIRouter

from netscanner.scope import LAB_RANGES

router = APIRouter()


@router.get("/status")
async def status() -> dict:
    return {
        "lab_mode": True,
        "authentication": False,
        "lab_ranges": [str(network) for network in LAB_RANGES],
    }
