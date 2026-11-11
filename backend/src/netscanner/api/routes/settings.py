# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Discovery settings and the credential (design D6, D10; RF-01, RF-02).

The credential is write-only: ``PUT`` takes the secret fields, ``GET`` gives
only its non-secret description and whether it can be decrypted with the
current key (``usable``), decided by key identifier without decrypting.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from netscanner.api.common import Payload, Services, Svc, problems_response
from netscanner.credential_store import CredentialDescription
from netscanner.scope import SettingsError, validate_settings
from netscanner.snmp.credentials import CredentialError

router = APIRouter(prefix="/settings")

VERSION_TAGS = ("2c.", "3.")


def _ceilings(svc: Services) -> dict[str, int]:
    return asdict(svc.ceilings)


async def _settings_body(svc: Services) -> dict[str, Any]:
    stored = await svc.store.read_discovery_settings()
    return {**stored, "ceilings": _ceilings(svc)}


@router.get("/discovery")
async def get_discovery_settings(svc: Svc) -> dict[str, Any]:
    return await _settings_body(svc)


@router.put("/discovery", response_model=None)
async def put_discovery_settings(payload: Payload, svc: Svc) -> dict[str, Any] | JSONResponse:
    try:
        validated = validate_settings(payload, svc.ceilings)
    except SettingsError as exc:
        return problems_response(exc.problems)
    await svc.store.save_discovery_settings(validated.model_dump(mode="json"))
    return await _settings_body(svc)


def _description(description: CredentialDescription) -> dict[str, Any]:
    body = asdict(description)
    body.pop("credential_id")  # internal
    return body


@router.get("/credential")
async def get_credential(svc: Svc) -> dict[str, Any]:
    return _description(await svc.credentials.describe())


@router.put("/credential", response_model=None)
async def put_credential(payload: Payload, svc: Svc) -> dict[str, Any] | JSONResponse:
    try:
        await svc.credentials.save(payload)
    except CredentialError as exc:
        return problems_response([(_field(f), reason) for f, reason in exc.problems])
    return _description(await svc.credentials.describe())


def _field(name: str) -> str:
    """Field without the version tag of the validation union (``2c.community``)."""
    for tag in VERSION_TAGS:
        if name.startswith(tag):
            return name[len(tag) :]
    return name
