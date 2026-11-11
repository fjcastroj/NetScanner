# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Deployment invariant, checked statically in both Compose files.

The authentication and guessing-limit design of add-admin-authentication
(D3, D6, D7) assumes that external HTTP traffic reaches the API only through
nginx in ``web``: the session cookie, the allowed origins and the
``X-Forwarded-For`` entry nginx appends. So ``web`` must remain the only
service that publishes a host port, and no service may use the host network.
The stack test still checks the running stack separately.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.lab.yml")
HOST_KEYS = ("ports", "network_mode")
ALLOWED = ("services", "web", "ports")


def load(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def host_exposure(node: object, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], object]]:
    """Every ``ports`` and ``network_mode`` key anywhere in a document, anchors included."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = (*path, str(key))
            if key in HOST_KEYS:
                found.append((here, value))
            found += host_exposure(value, here)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            found += host_exposure(item, (*path, str(i)))
    return found


@pytest.mark.parametrize("name", COMPOSE_FILES)
def test_only_web_publishes_a_host_port(name: str) -> None:
    document = load(name)
    exposure = host_exposure(document)
    offending = [".".join(path) for path, _ in exposure if path != ALLOWED]
    assert offending == [], f"{name}: only services.web may publish ports: {offending}"
    for service, definition in (document.get("services") or {}).items():
        mode = str((definition or {}).get("network_mode", ""))
        assert mode != "host", f"{name}: {service} uses the host network"
    services = document.get("services") or {}
    if "api" in services:
        assert "ports" not in (services["api"] or {}), f"{name}: api must stay internal"
    published = sorted(s for s, d in services.items() if "ports" in (d or {}))
    print(f"\n{name}: services {sorted(services)}; publishing a host port: {published}")


def test_web_publishes_and_api_stays_internal_when_combined() -> None:
    base, lab = (load(n)["services"] for n in COMPOSE_FILES)
    combined = {name: {**(base.get(name) or {}), **(lab.get(name) or {})} for name in base | lab}
    published = sorted(name for name, d in combined.items() if "ports" in d)
    assert published == ["web"]
    assert base["web"]["ports"] == ["${NETSCANNER_WEB_BIND:-127.0.0.1:8080}:8080"]
    assert "ports" not in combined["api"] and "network_mode" not in combined["api"]
    assert all(d.get("network_mode") != "host" for d in combined.values())


def test_the_check_detects_a_published_port_and_the_host_network() -> None:
    sample = yaml.safe_load(
        """
        x-agent: &agent
          ports: ["161:161/udp"]
        services:
          web: {ports: ["127.0.0.1:8080:8080"]}
          api: {ports: ["8000:8000"]}
          collector: {network_mode: host}
          agent: *agent
        """
    )
    offending = sorted(".".join(p) for p, _ in host_exposure(sample) if p != ALLOWED)
    assert offending == [
        "services.agent.ports",
        "services.api.ports",
        "services.collector.network_mode",
        "x-agent.ports",
    ]
