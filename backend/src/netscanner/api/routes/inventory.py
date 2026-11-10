# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Device list and detail with provenance (RF-11, RF-29, design D10).

Every value comes with its origin (observed or inferred), method, source
table, query and run, last seen time, age and staleness; the detail adds the
evidence, which holds only the fragments a method used.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from netscanner.api.common import DEFAULT_PAGE, MAX_PAGE, Svc, message_response
from netscanner.store.reading import GroupView, RecordView

router = APIRouter(prefix="/devices")

# Summary fields of the list: (name in the response, group, field).
SUMMARY = (
    ("name", "system", "sys_name"),
    ("vendor", "vendor", "vendor_name"),
    ("model", "model", "model"),
    ("software_version", "model", "software_version"),
)


def field_value(group: GroupView | None, name: str, *, evidence: bool) -> dict[str, Any]:
    """One value with its provenance; ``state`` is value, absent or unknown."""
    source = None if group is None else group.field_source(name)
    if group is None or source is None:
        return {"value": None, "state": "unknown"}
    body = {
        "value": group.values[name],
        "state": group.field_state(name),
        "origin": source.origin,
        "method": source.method,
        "source": source.mib_object,
        "query_id": source.query_id,
        "run_id": source.run_id,
        "seen_at": source.seen_at,
        "age_seconds": int(source.age.total_seconds()),
        "stale": source.stale,
    }
    if evidence:
        body["evidence"] = source.evidence
    return body


def group_body(group: GroupView | None) -> dict[str, Any] | None:
    if group is None:
        return None
    return {
        "first_seen_at": group.first_seen_at,
        "last_seen_at": group.last_seen_at,
        "stale": group.stale,
        "presence": group.presence.state,
        "source": group.mib_object,
        "fields": {name: field_value(group, name, evidence=True) for name in group.values},
    }


def record_body(record: RecordView) -> dict[str, Any]:
    return {
        "id": record.id,
        **record.key,
        "groups": {name: group_body(g) for name, g in record.groups.items()},
    }


@router.get("")
async def list_devices(
    svc: Svc,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = DEFAULT_PAGE,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    total, devices = await svc.store.list_devices(limit, offset)
    items = []
    for device in devices:
        system = device.groups.get("system")
        item: dict[str, Any] = {
            "id": device.id,
            "management_address": device.management_address,
            "interface_count": device.interface_count,
            "first_seen_at": system.first_seen_at if system else None,
            "last_seen_at": system.last_seen_at if system else None,
            "stale": system.stale if system else None,
        }
        for key, group, name in SUMMARY:
            item[key] = field_value(device.groups.get(group), name, evidence=False)
        items.append(item)
    return jsonable_encoder({"total": total, "limit": limit, "offset": offset, "items": items})


@router.get("/{device_id}", response_model=None)
async def get_device(device_id: int, svc: Svc) -> dict[str, Any] | JSONResponse:
    if not await svc.store.device_exists(device_id):
        return message_response("device not found", 404)
    device = await svc.store.read_device(device_id)
    addresses = await svc.store.read_addresses(device_id)
    interfaces = await svc.store.read_interfaces(device_id)
    body = {
        "id": device.id,
        "groups": {name: group_body(g) for name, g in device.groups.items()},
        "addresses": [record_body(r) for r in addresses],
        "interfaces": [record_body(r) for r in interfaces],
    }
    return jsonable_encoder(body)
