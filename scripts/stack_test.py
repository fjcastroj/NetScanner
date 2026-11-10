# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Automated stack test (design D13): build and run the whole Compose stack.

Uses throwaway random secrets, its own Compose project name and a free host
port, so it never touches a stack already running. The stack and its volumes
are removed at the end, even when a check fails.

The stack runs with the lab override file, as the snmp-lab spec delivers it
(``-f docker-compose.yml -f docker-compose.lab.yml``), and ends with a
discovery of the lab through the API: settings and credential saved, a run
until completed and the three lab devices in the list
(add-discovery-and-basic-inventory, task 8.1).

Usage: python scripts/stack_test.py
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_USER = "netscanner"
DB_NAME = "netscanner"
HEALTH_OK = {"status": "ok", "database": "ok"}
HEALTH_DEGRADED = {"status": "degraded", "database": "unavailable"}
RECOVERY_SECONDS = 30
MARKER_TABLE = "stack_test_marker"
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.lab.yml")
# Lab data only (lab/manifest.yaml): the lab community and addresses.
LAB_COMMUNITY = "netscanner-lab"
LAB_SETTINGS = {
    "seeds": ["10.99.0.13", "10.99.0.2", "10.99.0.9"],
    "allowed_ranges": ["10.99.0.0/24"],
    "exclusions": [],
    "max_depth": 1,
    "follow_ip_mac": False,
    "max_candidates": 4096,
    "max_devices": 256,
    "max_datagrams": 50000,
}
LAB_DEVICES = {"10.99.0.13", "10.99.0.2", "10.99.0.3"}
RUN_SECONDS = 180


class StackTestError(Exception):
    pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def step(message: str) -> None:
    print(f"==> {message}", flush=True)


class Stack:
    def __init__(self, project: str, env_file: Path, port: int) -> None:
        self.project = project
        self.env_file = env_file
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self.health_url = f"{self.base_url}/api/health"

    def compose(self, *args: str, check: bool = True, capture: bool = False) -> str:
        cmd = [
            "docker", "compose", "--progress", "quiet",
            "--project-name", self.project,
            "--project-directory", str(ROOT),
            "--env-file", str(self.env_file),
            *(arg for name in COMPOSE_FILES for arg in ("-f", str(ROOT / name))),
            *args,
        ]  # fmt: skip
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            capture_output=capture,
            check=False,
            env={k: v for k, v in os.environ.items() if not k.startswith("NETSCANNER_")},
        )
        if check and result.returncode != 0:
            detail = (result.stderr or "").strip() if capture else ""
            raise StackTestError(f"`docker compose {' '.join(args)}` failed. {detail}")
        return result.stdout or ""

    def up(self, *extra: str) -> None:
        self.compose("up", "-d", "--wait", "--wait-timeout", "300", *extra)

    def health(self) -> tuple[int, dict | None]:
        try:
            with urllib.request.urlopen(self.health_url, timeout=5) as resp:  # noqa: S310
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                return exc.code, json.loads(body)
            except ValueError:
                return exc.code, None
        except (urllib.error.URLError, OSError):
            return 0, None

    def api(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        """A JSON request to the API through the web port."""
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(  # noqa: S310 - local test URL
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            except ValueError:
                return exc.code, {}

    def wait_health(self, status: int, body: dict, timeout: float) -> float:
        start = time.monotonic()
        last: tuple[int, dict | None] = (0, None)
        while time.monotonic() - start < timeout:
            last = self.health()
            if last == (status, body):
                return time.monotonic() - start
            time.sleep(1)
        raise StackTestError(f"health did not become {status} {body} within {timeout} s: {last}")

    def services(self) -> list[dict]:
        out = self.compose("ps", "--all", "--format", "json", capture=True)
        out = out.strip()
        if out.startswith("["):
            return json.loads(out)
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def container_id(self, service: str) -> str:
        return self.compose("ps", "--all", "-q", service, capture=True).strip()

    def inspect(self, service: str, template: str) -> str:
        cid = self.container_id(service)
        result = subprocess.run(
            ["docker", "inspect", "--format", template, cid],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def wait_service_health(self, service: str, timeout: float = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.inspect(service, "{{.State.Health.Status}}") == "healthy":
                return
            time.sleep(1)
        raise StackTestError(f"{service} did not become healthy")

    def psql(self, sql: str) -> str:
        return self.compose(
            "exec", "-T", "db",
            "psql", "-U", DB_USER, "-d", DB_NAME, "-v", "ON_ERROR_STOP=1", "-tAc", sql,
            capture=True,
        ).strip()  # fmt: skip


def check(condition: bool, message: str) -> None:
    if not condition:
        raise StackTestError(message)
    print(f"    ok: {message}", flush=True)


def run_checks(stack: Stack) -> None:
    step("building and starting the stack")
    stack.up("--build")

    step("all services running and healthy; migrate exited successfully")
    by_name = {s["Service"]: s for s in stack.services()}
    for name in ("db", "api", "collector", "web"):
        state = by_name.get(name, {})
        check(
            state.get("State") == "running" and state.get("Health") == "healthy",
            f"{name} is running and healthy",
        )
    migrate = by_name.get("migrate", {})
    check(
        migrate.get("State") == "exited" and migrate.get("ExitCode") == 0,
        "migrate exited with code 0",
    )

    step("health through the web port")
    check(stack.health() == (200, HEALTH_OK), f"GET {stack.health_url} is 200 ok")

    step("only web publishes a host port; containers are not root")
    for name, svc in by_name.items():
        published = [p for p in svc.get("Publishers") or [] if p.get("PublishedPort")]
        if name == "web":
            check([p["PublishedPort"] for p in published] == [stack.port], "web on the test port")
        else:
            check(not published, f"{name} publishes no host port")
    for name, port in (("db", "5432"), ("api", "8000")):
        mapped = stack.compose("port", name, port, check=False, capture=True).strip()
        check(mapped in ("", ":0"), f"`docker compose port {name} {port}` gives nothing")
    for name in ("db", "api", "collector", "web"):
        uid = stack.compose("exec", "-T", name, "id", "-u", capture=True).strip()
        check(uid not in ("", "0"), f"{name} runs as uid {uid}")

    step("collector stopped: API keeps answering")
    stack.compose("stop", "collector")
    check(stack.health() == (200, HEALTH_OK), "health still 200 without the collector")
    stack.compose("start", "collector")
    stack.wait_service_health("collector")

    step("api restarted: collector keeps running, web reaches the new api")
    collector_started = stack.inspect("collector", "{{.State.StartedAt}}")
    stack.compose("restart", "api")
    stack.wait_health(200, HEALTH_OK, timeout=60)
    print("    ok: health 200 through web after the api restart", flush=True)
    check(
        stack.inspect("collector", "{{.State.StartedAt}}") == collector_started,
        "collector was not restarted",
    )
    stack.wait_service_health("api")

    step("database outage: health 503, then 200 again without restarting api")
    api_started = stack.inspect("api", "{{.State.StartedAt}}")
    stack.compose("stop", "db")
    stack.wait_health(503, HEALTH_DEGRADED, timeout=30)
    print("    ok: health 503 degraded while the database is down", flush=True)
    stack.compose("start", "db")
    stack.wait_service_health("db")
    took = stack.wait_health(200, HEALTH_OK, timeout=RECOVERY_SECONDS)
    print(f"    ok: health back to 200 {took:.0f} s after db was healthy", flush=True)
    check(stack.inspect("api", "{{.State.StartedAt}}") == api_started, "api was not restarted")
    check(stack.inspect("collector", "{{.State.Running}}") == "true", "collector still running")
    stack.wait_service_health("collector")

    step("data survives down / up without -v")
    marker = secrets.token_hex(8)
    stack.psql(
        f"CREATE TABLE {MARKER_TABLE} (value text); INSERT INTO {MARKER_TABLE} VALUES ('{marker}')"  # noqa: S608
    )  # constant table name and a hex token
    stack.compose("down")
    stack.up()
    stored = stack.psql(f"SELECT value FROM {MARKER_TABLE}")  # noqa: S608 - constant
    check(stored == marker, "marker row preserved")
    stack.psql(f"DROP TABLE {MARKER_TABLE}")
    check(stack.health() == (200, HEALTH_OK), "health 200 after restart")

    lab_discovery(stack)


def lab_discovery(stack: Stack) -> None:
    step("lab discovery through the API")
    status, body = stack.api("GET", "/api/status")
    check(status == 200 and body.get("lab_mode") is True, "status reports lab mode")
    status, _ = stack.api("PUT", "/api/settings/discovery", LAB_SETTINGS)
    check(status == 200, "discovery settings saved")
    status, body = stack.api(
        "PUT", "/api/settings/credential", {"version": "2c", "community": LAB_COMMUNITY}
    )
    check(status == 200 and body.get("usable") is True, "credential saved and usable")
    check(LAB_COMMUNITY not in json.dumps(body), "credential response has no secret")
    status, run = stack.api("POST", "/api/runs")
    check(status == 201 and run.get("status") == "pending", f"run {run.get('id')} created")
    status, _ = stack.api("POST", "/api/runs")
    check(status == 409, "a second run is refused while the first is active")
    started = time.monotonic()
    while time.monotonic() - started < RUN_SECONDS:
        status, run = stack.api("GET", f"/api/runs/{run['id']}")
        if run.get("status") not in ("pending", "running"):
            break
        time.sleep(2)
    took = time.monotonic() - started
    progress = run.get("progress") or {}
    check(run.get("status") == "completed", f"run completed in {took:.0f} s")
    check(
        progress.get("reasons") == {"no_response": 1, "out_of_scope": 1},
        f"candidates per reason {progress.get('reasons')}",
    )
    status, devices = stack.api("GET", "/api/devices")
    addresses = {d.get("management_address") for d in devices.get("items", [])}
    check(
        status == 200 and devices.get("total") == 3 and addresses == LAB_DEVICES,
        "the device list returns the three lab devices",
    )
    summary = (run.get("report") or {}).get("summary") or {}
    print(
        f"    lab run: {progress.get('candidates')} candidates, {progress.get('devices')} "
        f"devices, {progress.get('queries')} queries, {summary.get('reported_datagrams')} "
        f"datagrams, limits reached {summary.get('limits_reached')}",
        flush=True,
    )


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__.splitlines()[0]).parse_args(argv)

    port = free_port()
    project = f"netscanner-stacktest-{secrets.token_hex(4)}"
    with tempfile.TemporaryDirectory(prefix="netscanner-stack-") as tmp:
        env_file = Path(tmp) / "stack.env"
        env_file.write_text(
            "\n".join(
                [
                    f"NETSCANNER_SECRET_KEY={secrets.token_urlsafe(32)}",
                    f"NETSCANNER_DB_PASSWORD={secrets.token_urlsafe(24)}",
                    f"NETSCANNER_DB_USER={DB_USER}",
                    f"NETSCANNER_DB_NAME={DB_NAME}",
                    f"NETSCANNER_WEB_BIND=127.0.0.1:{port}",
                    "NETSCANNER_COLLECTOR_CHECK_INTERVAL=2",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        stack = Stack(project, env_file, port)
        print(f"stack test: project {project}, web port {port}", flush=True)
        try:
            run_checks(stack)
        except StackTestError as exc:
            print(f"STACK TEST FAILED: {exc}", file=sys.stderr, flush=True)
            stack.compose("ps", "--all", check=False)
            stack.compose("logs", "--no-color", "--tail", "50", check=False)
            return 1
        finally:
            step("removing the stack and its volumes")
            stack.compose("down", "-v", "--remove-orphans", check=False)
    print("STACK TEST PASSED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
