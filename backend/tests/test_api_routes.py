# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Routes of design D10 (task 6.2; inventory-api spec).

The application runs with its real composition (``create_app``) on the
migrated test database. Runs created through the API are executed by the
test helper ``claim_and_run`` with the test transport mapping (design D3),
as the collector would do with the real one.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.core.config import Settings

from .auth_helpers import api_client, create_admin, login
from .conftest import Canaries, DiscoveryLab, all_rows_text
from .discovery_run import Network, claim_and_run
from .snmp_agent import Behaviour, ScriptedAgent
from .test_discovery_runs import device

pytestmark = pytest.mark.db

LAB = "10.99.0.0/24"
SRX, SW1, SW2, SILENT, EXTERNAL = (
    "10.99.0.13", "10.99.0.2", "10.99.0.3", "10.99.0.9", "203.0.113.10"
)  # fmt: skip
LAB_SETTINGS = {
    "seeds": [SRX, SW1, SILENT], "allowed_ranges": [LAB], "exclusions": [], "max_depth": 1,
    "follow_ip_mac": False, "max_candidates": 4096, "max_devices": 256, "max_datagrams": 50000,
}  # fmt: skip


@pytest.fixture
async def client(engine: AsyncEngine, store_settings: Settings) -> AsyncIterator[TestClient]:
    # ``engine`` truncates the tables after the test. Logged in as the administrator
    # (add-admin-authentication); the routes without a session are tested in test_auth.py.
    await create_admin(engine)
    with api_client(store_settings) as test_client:
        login(test_client)
        yield test_client


@pytest.fixture
def secret_key(store_settings: Settings) -> str:
    return store_settings.secret_key.get_secret_value()


def fields(response) -> dict[str, str]:
    assert response.status_code == 422, response.text
    return {p["field"]: p["reason"] for p in response.json()["detail"]}


# --- Status ----------------------------------------------------------------------


def test_status_reports_authentication(client: TestClient) -> None:
    # Lab mode ended with add-admin-authentication (D9); the account is not described.
    assert client.get("/api/status").json() == {"authentication": True, "admin_exists": True}


# --- Discovery settings ----------------------------------------------------------


def test_settings_saved_and_read_back(client: TestClient) -> None:
    initial = client.get("/api/settings/discovery").json()
    assert initial["seeds"] == [] and initial["ceilings"]["max_depth"] == 5
    saved = client.put("/api/settings/discovery", json={**LAB_SETTINGS, "exclusions": [SW2]})
    assert saved.status_code == 200, saved.text
    body = client.get("/api/settings/discovery").json()
    assert body["seeds"] == LAB_SETTINGS["seeds"]
    assert body["allowed_ranges"] == [LAB] and body["exclusions"] == [f"{SW2}/32"]
    assert body["updated_at"] > initial["updated_at"]


@pytest.mark.parametrize(
    ("change", "field"),
    [
        ({"allowed_ranges": ["10.99.0.0/33"]}, "allowed_ranges.0"),
        ({"seeds": ["198.51.100.77"]}, "seeds.0"),
        ({"max_depth": 6}, "max_depth"),
        ({"max_datagrams": 50001}, "max_datagrams"),
        ({"allowed_ranges": ["198.51.100.0/24"], "exclusions": ["10.99.0/24"]}, "exclusions.0"),
        ({"unexpected": "198.51.100.88"}, "unexpected"),
    ],
)
def test_invalid_settings_give_field_and_reason_without_the_value(
    client: TestClient, change: dict, field: str
) -> None:
    response = client.put("/api/settings/discovery", json={**LAB_SETTINGS, **change})
    found = fields(response)
    assert found.get(field)
    for value in change.values():
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str):
                assert item not in response.text  # the submitted value is never echoed
    assert client.get("/api/settings/discovery").json()["seeds"] == []  # nothing saved


def test_malformed_request_gives_field_without_value(client: TestClient) -> None:
    response = client.put(
        "/api/settings/discovery",
        content=b'["canary-body-198.51.100.99"]',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422 and "canary-body" not in response.text
    assert "limit" in fields(client.get("/api/devices?limit=0"))


# --- Credential --------------------------------------------------------------------


def test_credential_is_write_only(client: TestClient, engine: AsyncEngine) -> None:
    assert client.get("/api/settings/credential").json()["configured"] is False
    community = "canary-" + secrets.token_hex(12)
    saved = client.put("/api/settings/credential", json={"version": "2c", "community": community})
    assert saved.status_code == 200 and community not in saved.text
    body = client.get("/api/settings/credential").json()
    assert body["configured"] and body["version"] == "v2c" and body["usable"]
    assert body["updated_at"] and community not in json.dumps(body)
    assert "community" not in body and "secret" not in body

    auth, priv = secrets.token_hex(16), secrets.token_hex(16)
    v3 = {
        "version": "3", "user": "lab-user", "level": "authPriv", "auth_protocol": "SHA-256",
        "auth_key": auth, "priv_protocol": "AES-128", "priv_key": priv,
    }  # fmt: skip
    saved = client.put("/api/settings/credential", json=v3)
    assert saved.status_code == 200
    body = saved.json()
    assert (body["version"], body["user"], body["level"]) == ("v3", "lab-user", "authPriv")
    assert auth not in saved.text and priv not in saved.text


def test_invalid_credential_names_fields_never_values(client: TestClient) -> None:
    short = "sh-" + secrets.token_hex(2)  # 7 characters: below the SNMPv3 minimum of 8
    response = client.put(
        "/api/settings/credential",
        json={"version": "3", "user": "u", "level": "authPriv", "auth_protocol": "SHA-256",
              "auth_key": short, "priv_protocol": "AES-128", "priv_key": short},
    )  # fmt: skip
    found = fields(response)
    assert "auth_key" in found and short not in response.text
    assert client.get("/api/settings/credential").json()["configured"] is False


# --- Runs ---------------------------------------------------------------------------


def test_run_needs_seeds_and_credential(client: TestClient) -> None:
    found = fields(client.post("/api/runs"))
    assert set(found) == {"seeds", "credential"}


def test_second_run_is_refused_while_one_is_active(client: TestClient) -> None:
    client.put("/api/settings/discovery", json=LAB_SETTINGS)
    client.put("/api/settings/credential", json={"version": "2c", "community": "netscanner-lab"})
    first = client.post("/api/runs")
    assert first.status_code == 201, first.text
    run = first.json()
    assert run["status"] == "pending" and run["kind"] == "discovery"
    assert run["parameters"]["limits"] == {
        "max_candidates": 4096, "max_devices": 256, "max_datagrams": 50000
    }  # fmt: skip
    assert run["parameters"]["seeds"] == LAB_SETTINGS["seeds"]
    second = client.post("/api/runs")
    assert second.status_code == 409 and "already in progress" in second.json()["detail"]
    listed = client.get("/api/runs").json()
    assert listed["total"] == 1 and listed["items"][0]["id"] == run["id"]
    assert client.get("/api/runs/999999").status_code == 404


# --- The lab run through the API: progress, device list and detail -------------------


@pytest.mark.lab
async def test_lab_run_devices_list_and_srx01_detail(
    client: TestClient, engine: AsyncEngine, secret_key: str, discovery_lab: DiscoveryLab
) -> None:
    client.put("/api/settings/discovery", json=LAB_SETTINGS)
    client.put(
        "/api/settings/credential", json={"version": "2c", "community": discovery_lab.community}
    )
    run_id = client.post("/api/runs").json()["id"]
    silent = ScriptedAgent({}, community=discovery_lab.community, behaviour=Behaviour(stop_after=0))
    canary = ScriptedAgent({}, community=discovery_lab.community)
    async with silent, canary:
        network = Network({**discovery_lab.ports, EXTERNAL: canary.port}, default=silent.port)
        run = await claim_and_run(engine, secret_key, network, run_id)
        assert canary.requests == 0
    assert run.status == "completed"

    detail = client.get(f"/api/runs/{run_id}").json()
    assert detail["status"] == "completed"
    assert detail["progress"]["devices"] == 3 and detail["progress"]["candidates"] == 5
    assert detail["progress"]["reasons"] == {"no_response": 1, "out_of_scope": 1}
    assert detail["progress"]["queries"] == len(await run.queries())
    assert detail["report"]["new_devices"] == 3

    listed = client.get("/api/devices").json()
    assert listed["total"] == 3 and listed["limit"] == 100
    by_address = {d["management_address"]: d for d in listed["items"]}
    assert set(by_address) == {SRX, SW1, SW2}
    srx = by_address[SRX]
    assert srx["name"]["value"] and srx["interface_count"] == 259
    assert srx["vendor"]["value"] == "Juniper" and srx["vendor"]["origin"] == "inferred"
    assert (srx["model"]["value"], srx["model"]["origin"]) == ("srx1500", "inferred")
    assert srx["software_version"]["value"] == "19.4R3.11"
    assert srx["first_seen_at"] and srx["last_seen_at"] and srx["stale"] is False
    assert by_address[SW2]["vendor"]["value"] == "Fortinet"

    # Pagination.
    page = client.get("/api/devices?limit=1&offset=1").json()
    assert (page["total"], page["limit"], page["offset"]) == (3, 1, 1)
    assert [d["id"] for d in page["items"]] == [listed["items"][1]["id"]]
    assert client.get("/api/devices?offset=3").json()["items"] == []

    # Detail of srx-01: inferred model with method and fragments, observed interfaces.
    body = client.get(f"/api/devices/{srx['id']}").json()
    model = body["groups"]["model"]["fields"]["model"]
    assert (model["value"], model["origin"], model["method"]) == (
        "srx1500", "inferred", "juniper-sysdescr-pattern"
    )  # fmt: skip
    snapshots = [i.get("snapshot") for i in model["evidence"]["inputs"]]
    assert {"model_fragment": "Juniper Networks, Inc. srx1500 internet router",
            "version_fragment": "kernel JUNOS 19.4R3.11"} in snapshots  # fmt: skip
    assert len(body["interfaces"]) == 259
    first = body["interfaces"][0]["groups"]["base"]
    descr = first["fields"]["if_descr"]
    assert descr["origin"] == "observed" and descr["source"] == "IF-MIB::ifTable"
    assert descr["age_seconds"] >= 0 and descr["stale"] is False and descr["seen_at"]
    assert body["addresses"] and client.get("/api/devices/999999").status_code == 404


# --- Task 5.7: canary credentials never in an API response --------------------------


async def test_canary_credential_absent_from_every_api_response(
    client: TestClient, engine: AsyncEngine, secret_key: str, canaries: Canaries
) -> None:
    community = "canary-" + secrets.token_hex(12)
    a, b = "10.99.0.21", "10.99.0.22"
    settings = {**LAB_SETTINGS, "seeds": [a, b, SILENT]}
    responses = [
        client.put("/api/settings/discovery", json=settings),
        client.put("/api/settings/credential", json={"version": "2c", "community": community}),
    ]
    run_id = client.post("/api/runs").json()["id"]
    good = ScriptedAgent(device("sw-a"), community=community)
    failing = ScriptedAgent(
        device("sw-b"), community=community, behaviour=Behaviour(error_status="genErr")
    )
    quiet = ScriptedAgent({}, community=community, behaviour=Behaviour(stop_after=0))
    async with good, failing, quiet:
        network = Network({a: good.port, b: failing.port}, default=quiet.port)
        run = await claim_and_run(engine, secret_key, network, run_id)
    assert run.status == "completed"
    responses += [
        client.get(path)
        for path in (
            "/api/status", "/api/settings/discovery", "/api/settings/credential", "/api/runs",
            f"/api/runs/{run_id}", "/api/devices",
        )
    ]  # fmt: skip
    devices = client.get("/api/devices").json()["items"]
    assert devices
    responses += [client.get(f"/api/devices/{d['id']}") for d in devices]
    # Errors and timeouts were part of the run.
    assert {q["outcome"] for q in await run.queries()} >= {"ok", "error", "no_response"}
    for response in responses:
        assert response.status_code < 400, response.text
        assert community not in response.text
        assert secret_key not in response.text
        canaries.assert_absent(response.text)
    assert community not in await all_rows_text(engine)
