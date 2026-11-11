# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""API routers under ``/api`` (design D10; add-admin-authentication D4, D6).

Every route of this router needs a session except the public list of
``netscanner.auth.guard``, and every request that changes state passes the
cross-site check. A new route added here is protected without further code.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from netscanner.api.routes import auth, inventory, runs, settings, status
from netscanner.auth.guard import check_cross_site, require_session

# The session is checked first, so a request without one answers 401 whatever it is.
router = APIRouter(
    prefix="/api", dependencies=[Depends(require_session), Depends(check_cross_site)]
)
for module in (status, auth, settings, runs, inventory):
    router.include_router(module.router)

__all__ = ["router"]
