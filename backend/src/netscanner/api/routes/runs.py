# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Discovery runs: start one, list them, follow one (design D7, D10).

The API only creates pending runs, with the settings frozen into their
parameters; the collector runs them. A second run while one is pending or
running is refused atomically by the partial unique index (409). Progress is
computed when read, from ``run_devices`` and ``snmp_queries``.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from netscanner.api.common import (
    DEFAULT_PAGE,
    MAX_PAGE,
    Services,
    Svc,
    message_response,
    problems_response,
)
from netscanner.scope import (
    LimitsAboveCeiling,
    SettingsError,
    run_parameters_for,
    validate_settings,
)
from netscanner.store.configuration import FIELDS

router = APIRouter(prefix="/runs")

FINISHED = ("completed", "failed", "interrupted")
RUN_IN_PROGRESS = "a discovery run is already in progress"


@router.post("", status_code=201, response_model=None)
async def start_run(svc: Svc) -> dict[str, Any] | JSONResponse:
    stored = await svc.store.read_discovery_settings()
    try:
        # Checked again: the ceilings or the stored row may have changed since saving.
        settings = validate_settings({k: stored[k] for k in FIELDS}, svc.ceilings)
    except SettingsError as exc:
        return problems_response(exc.problems)
    problems = []
    if not settings.seeds:
        problems.append(("seeds", "at least one seed is required"))
    credential = await svc.credentials.describe()
    if not credential.configured:
        problems.append(("credential", "no credential is configured"))
    if problems:
        return problems_response(problems)
    try:
        params = run_parameters_for(settings, svc.ceilings, credential.credential_id)
    except LimitsAboveCeiling as exc:
        return problems_response([(name, "above the server's ceiling") for name in exc.names])
    try:
        run_id = await svc.store.create_run("discovery", params)
    except IntegrityError:
        return message_response(RUN_IN_PROGRESS, 409)
    return await _detail(svc, run_id)  # type: ignore[return-value]


@router.get("")
async def list_runs(
    svc: Svc,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = DEFAULT_PAGE,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    total, runs = await svc.store.list_runs(limit, offset)
    return jsonable_encoder({"total": total, "limit": limit, "offset": offset, "items": runs})


@router.get("/{run_id}", response_model=None)
async def get_run(run_id: int, svc: Svc) -> dict[str, Any] | JSONResponse:
    detail = await _detail(svc, run_id)
    return message_response("run not found", 404) if detail is None else detail


async def _detail(svc: Services, run_id: int) -> dict[str, Any] | None:
    run = await svc.store.get_run(run_id)
    if run is None:
        return None
    report = await svc.store.run_report(run_id)
    progress = {
        "candidates": report["reached"],
        "reached_by": report["reached_by"],
        "devices": report["devices"],
        "new_devices": report["new_devices"],
        "without_answer": report["without_answer"],
        "reasons": report["reasons"],
        "queries": await svc.store.count_queries(run_id),
    }
    body = {**run, "progress": progress, "report": report if run["status"] in FINISHED else None}
    return jsonable_encoder(body)
