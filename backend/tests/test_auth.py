# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Sessions, login, guessing limit and route protection (tasks 3.2 to 4.3).

The application runs with its real composition on the migrated test database.
The authentication clock is replaced through ``app.state.auth.clock`` to test
expiry and the guessing window without waiting.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import statistics
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.api.app import create_app
from netscanner.auth import passwords
from netscanner.auth.guard import PUBLIC_ROUTES
from netscanner.auth.limiter import source_address
from netscanner.core.config import Settings
from netscanner.core.logging_setup import configure_logging

from .auth_helpers import ADMIN, ADMIN_PASSWORD, BASE_URL, HEADERS, api_client, create_admin, login
from .conftest import Clock, all_rows_text

pytestmark = pytest.mark.db

T = datetime(2026, 11, 10, 9, 0, tzinfo=UTC)
LOGIN = "/api/auth/login"
SESSION = "/api/auth/session"


@pytest.fixture
async def admin(engine: AsyncEngine) -> AsyncIterator[None]:
    await create_admin(engine)
    yield


@contextmanager
def client_at(settings: Settings, clock: Clock, **kwargs) -> Iterator[TestClient]:
    with api_client(settings, **kwargs) as client:
        client.app.state.auth.clock = clock  # type: ignore[attr-defined]
        yield client


async def rows(engine: AsyncEngine, sql: str) -> list[dict]:
    async with engine.connect() as conn:
        return [dict(r) for r in (await conn.execute(text(sql))).mappings()]


def attempt(client: TestClient, username: str, password: str, source: str | None = None):
    headers = {} if source is None else {"X-Forwarded-For": source}
    return client.post(LOGIN, json={"username": username, "password": password}, headers=headers)


@contextmanager
def counted_verifications() -> Iterator[list[str]]:
    """Every Argon2id verification, by the hash it was checked against."""
    calls: list[str] = []
    real = passwords._hasher

    class Counting:
        def verify(self, hash_: str, password: str) -> bool:
            calls.append("dummy" if hash_ == passwords.dummy_hash() else "stored")
            return real.verify(hash_, password)

        def __getattr__(self, name: str):
            return getattr(real, name)

    passwords._hasher = Counting()  # type: ignore[assignment]
    try:
        yield calls
    finally:
        passwords._hasher = real


# --- 3.2 sessions -------------------------------------------------------------------


async def test_login_sets_a_strict_http_only_secure_session_cookie(
    admin: None, store_settings: Settings, engine: AsyncEngine
) -> None:
    with api_client(store_settings) as client:
        response = attempt(client, ADMIN, ADMIN_PASSWORD)
        assert response.status_code == 200
        assert response.json()["username"] == ADMIN
        cookie = response.headers["set-cookie"]
        token = re.match(r"netscanner_session=([^;]+);", cookie).group(1)  # type: ignore[union-attr]
        attributes = {a.strip().split("=")[0].lower() for a in cookie.split(";")[1:]}
        assert {"httponly", "secure", "path", "samesite"} <= attributes
        assert "samesite=strict" in cookie.lower() and "path=/" in cookie.lower()
        assert not attributes & {"max-age", "expires"}  # ends with the browser
        assert client.get(SESSION).json()["username"] == ADMIN
    # Stored only as its SHA-256.
    [stored] = await rows(engine, "SELECT token_hash FROM sessions")
    assert stored["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in await all_rows_text(engine)


async def test_each_login_creates_a_new_session(
    admin: None, store_settings: Settings, engine: AsyncEngine
) -> None:
    with api_client(store_settings) as client:
        login(client)
        first = client.cookies.get("netscanner_session")
        login(client)  # the cookie sent with this request is ignored
        second = client.cookies.get("netscanner_session")
    assert first and second and first != second
    assert len(await rows(engine, "SELECT id FROM sessions")) == 2


async def test_idle_expiry(admin: None, store_settings: Settings, engine: AsyncEngine) -> None:
    clock = Clock(T)
    with client_at(store_settings, clock) as client:
        login(client)
        clock.advance(timedelta(hours=7, minutes=59))
        assert client.get(SESSION).status_code == 200  # used: last_used_at moves
        clock.advance(timedelta(hours=8, seconds=1))
        response = client.get(SESSION)
        assert response.status_code == 401
        assert response.json() == {"detail": "authentication required"}
    assert await rows(engine, "SELECT id FROM sessions") == []  # deleted


async def test_absolute_expiry(admin: None, store_settings: Settings) -> None:
    clock = Clock(T)
    with client_at(store_settings, clock) as client:
        login(client)
        for _ in range(3):  # used every 7 h: never idle
            clock.advance(timedelta(hours=7))
            assert client.get(SESSION).status_code == 200
        clock.advance(timedelta(hours=3))  # 24 h after login
        assert client.get(SESSION).status_code == 401


async def test_last_used_written_at_most_once_a_minute(
    admin: None, store_settings: Settings, engine: AsyncEngine
) -> None:
    clock = Clock(T)
    with client_at(store_settings, clock) as client:
        login(client)
        clock.advance(timedelta(seconds=30))
        client.get(SESSION)
        assert (await rows(engine, "SELECT last_used_at FROM sessions"))[0]["last_used_at"] == T
        clock.advance(timedelta(seconds=31))
        client.get(SESSION)
        assert (await rows(engine, "SELECT last_used_at FROM sessions"))[0][
            "last_used_at"
        ] == T + timedelta(seconds=61)


async def test_logout_deletes_the_session_and_clears_the_cookie(
    admin: None, store_settings: Settings, engine: AsyncEngine
) -> None:
    with api_client(store_settings) as client:
        login(client)
        token = client.cookies.get("netscanner_session")
        response = client.post("/api/auth/logout")
        assert response.status_code == 200
        cookie = response.headers["set-cookie"].lower()
        assert cookie.startswith('netscanner_session=""') or "max-age=0" in cookie
        assert await rows(engine, "SELECT id FROM sessions") == []
        # The old token no longer works, even if a client kept it.
        client.cookies.clear()
        client.cookies.set("netscanner_session", token)
        assert client.get(SESSION).status_code == 401
        client.cookies.clear()
        # Logout without a session still clears the cookie.
        again = client.post("/api/auth/logout")
        assert again.status_code == 200 and "netscanner_session" in again.headers["set-cookie"]


# --- 3.3 equal answer, one verification per path --------------------------------------


async def test_every_login_path_performs_exactly_one_verification(
    engine: AsyncEngine, store_settings: Settings
) -> None:
    found: dict[str, list[str]] = {}
    bodies: dict[str, dict] = {}
    with api_client(store_settings) as client:
        with counted_verifications() as calls:
            bodies["no account"] = attempt(client, ADMIN, ADMIN_PASSWORD, "192.0.2.1").json()
            found["no account"] = list(calls)
        await create_admin(engine)
        for name, (user, pw) in {
            "unknown user": ("someone-else", ADMIN_PASSWORD),
            "wrong password": (ADMIN, ADMIN_PASSWORD + "x"),
            "right password": (ADMIN, ADMIN_PASSWORD),
        }.items():
            with counted_verifications() as calls:
                response = attempt(client, user, pw, f"192.0.2.{len(found) + 1}")
                found[name] = list(calls)
            bodies[name] = response.json()
    assert found == {
        "no account": ["dummy"],
        "unknown user": ["dummy"],
        "wrong password": ["stored"],
        "right password": ["stored"],
    }
    failed = {"detail": "invalid user name or password"}
    assert bodies["no account"] == bodies["unknown user"] == bodies["wrong password"] == failed
    print("\nArgon2id verifications per login path:", {k: len(v) for k, v in found.items()})


async def test_unknown_user_and_wrong_password_take_similar_time(
    admin: None, store_settings: Settings
) -> None:
    runs = 7
    times: dict[str, list[float]] = {"unknown user": [], "wrong password": []}
    with api_client(store_settings) as client:
        attempt(client, "warm-up", "warm-up-password", "198.51.100.200")
        for i in range(runs):
            for name, user in (("unknown user", "someone-else"), ("wrong password", ADMIN)):
                source = f"198.51.100.{i * 2 + (name == 'wrong password')}"  # below the limit
                started = time.perf_counter()
                response = attempt(client, user, "not-the-password", source)
                times[name].append(time.perf_counter() - started)
                assert response.status_code == 401
    medians = {name: statistics.median(values) for name, values in times.items()}
    ratio = medians["unknown user"] / medians["wrong password"]
    print(
        "\nlogin timing, median of", runs, "runs:",
        {k: f"{v * 1000:.1f} ms" for k, v in medians.items()}, f"ratio {ratio:.2f}",
    )  # fmt: skip
    assert 0.5 < ratio < 2.0  # generous: the mechanism is checked by the test above


async def test_outdated_hash_rehashed_on_login(
    engine: AsyncEngine, store_settings: Settings
) -> None:
    from argon2 import PasswordHasher

    await create_admin(engine)
    old = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(ADMIN_PASSWORD)
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE admin_account SET password_hash = :h"), {"h": old})
    with api_client(store_settings) as client:
        login(client)
    [row] = await rows(engine, "SELECT password_hash FROM admin_account")
    assert row["password_hash"] != old and not passwords.needs_rehash(row["password_hash"])
    assert passwords.verify(row["password_hash"], ADMIN_PASSWORD)


# --- 3.4 guessing limit ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "connection", "expected"),
    [
        (None, "192.0.2.5", "192.0.2.5"),  # no header: the connection address
        ("10.99.0.250", "192.0.2.100", "10.99.0.250"),  # the entry nginx added
        ("203.0.113.66, 10.99.0.250", "192.0.2.100", "10.99.0.250"),  # forged first entry
        ("203.0.113.66, 198.51.100.1,   10.99.0.250  ", "192.0.2.100", "10.99.0.250"),  # spaces
        ("203.0.113.66, 2001:DB8::0:1", "192.0.2.100", "2001:db8::1"),  # IPv6, normalised
        ("10.99.0.250, not-an-address", "192.0.2.100", "192.0.2.100"),  # malformed: connection
        ("10.99.0.250, ", "192.0.2.100", "192.0.2.100"),  # empty last entry
        ("10.99.0.250, 10.99.0.251:5000", "192.0.2.100", "192.0.2.100"),  # with a port
        ("garbage", None, "0.0.0.0"),  # nothing usable at all
    ],
)
def test_source_address(header: str | None, connection: str | None, expected: str) -> None:
    assert source_address(header, connection) == expected


async def test_sixth_failure_gives_429_and_checks_no_password(
    admin: None, store_settings: Settings
) -> None:
    clock = Clock(T)
    with client_at(store_settings, clock) as client:
        for i in range(5):
            clock.advance(timedelta(seconds=10))
            # Forged first entries change every time; the last one is the source.
            response = attempt(client, ADMIN, "wrong-password-1", f"203.0.113.{i}, 10.99.0.250")
            assert response.status_code == 401
        with counted_verifications() as calls:
            limited = attempt(client, ADMIN, ADMIN_PASSWORD, "203.0.113.99, 10.99.0.250")
        assert limited.status_code == 429 and calls == []  # not even the right password
        retry = int(limited.headers["Retry-After"])
        assert retry == 15 * 60 - 40  # until the oldest failure leaves the window
        # Another source address is not affected; the account is not locked.
        assert attempt(client, ADMIN, ADMIN_PASSWORD, "10.99.0.251").status_code == 200
        clock.advance(timedelta(seconds=retry))
        assert attempt(client, ADMIN, ADMIN_PASSWORD, "10.99.0.250").status_code == 200


async def test_success_is_not_counted(admin: None, store_settings: Settings) -> None:
    clock = Clock(T)
    with client_at(store_settings, clock) as client:
        for _ in range(4):
            assert attempt(client, ADMIN, "wrong-password-1", "10.99.0.250").status_code == 401
        assert attempt(client, ADMIN, ADMIN_PASSWORD, "10.99.0.250").status_code == 200
        assert attempt(client, ADMIN, "wrong-password-1", "10.99.0.250").status_code == 401
        assert attempt(client, ADMIN, "wrong-password-1", "10.99.0.250").status_code == 429


async def test_old_attempts_are_deleted(
    admin: None, store_settings: Settings, engine: AsyncEngine
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO login_attempts (at, source_address, succeeded)"
                " VALUES (:old, '10.99.0.7', false), (:recent, '10.99.0.7', false)"
            ),
            {"old": T - timedelta(days=1, minutes=1), "recent": T - timedelta(hours=1)},
        )
    with client_at(store_settings, Clock(T)) as client:
        attempt(client, ADMIN, ADMIN_PASSWORD, "10.99.0.8")
    left = await rows(engine, "SELECT at FROM login_attempts ORDER BY at")
    assert [r["at"] for r in left] == [T - timedelta(hours=1), T]


async def test_attempts_logged_without_password(
    admin: None,
    store_settings: Settings,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("DEBUG", store_settings.secret_values())
    caplog.set_level(logging.DEBUG)
    canary = "canary-" + secrets.token_hex(12)
    stranger = "canary-user-" + secrets.token_hex(4)
    with api_client(store_settings) as client:
        attempt(client, ADMIN, canary, "10.99.0.250")
        attempt(client, stranger, canary, "10.99.0.251")
        attempt(client, ADMIN, ADMIN_PASSWORD, "10.99.0.252")
    err = capsys.readouterr().err
    messages = [
        line.split("netscanner.auth: ", 1)[1]
        for line in err.splitlines()
        if "netscanner.auth: " in line
    ]
    assert messages == [
        f"login failed from 10.99.0.250 as {ADMIN}",
        "login failed from 10.99.0.251",  # the user name only when it matches the account
        f"login succeeded from 10.99.0.252 as {ADMIN}",
    ]
    for output in (caplog.text, err):
        assert canary not in output and ADMIN_PASSWORD not in output and stranger not in output


async def test_login_input_validated_without_echo(admin: None, store_settings: Settings) -> None:
    with api_client(store_settings) as client:
        long_password = "canary-" + "x" * 1100
        for body in ({}, {"username": ADMIN}, {"username": 1, "password": []},
                     {"username": ADMIN, "password": long_password}):  # fmt: skip
            response = client.post(LOGIN, json=body)
            assert response.status_code == 422
            assert "canary" not in response.text


# --- 4.1, 4.2 route protection ----------------------------------------------------------

# Values for path parameters; a route with any other parameter cannot be called.
PATH_VALUES = {"run_id": "1", "device_id": "1"}
CALLABLE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def every_route(app) -> list[tuple[str, str]]:
    """Every (method, path template) of the application, from FastAPI's route list."""
    found = []
    for context in iter_route_contexts(app.routes):
        for method in sorted(context.methods or {"(none)"}):
            found.append((method, context.path))
    return found


def call_path(template: str) -> str:
    names = re.findall(r"{([^}:]+)(?::[^}]*)?}", template)
    unknown = [n for n in names if n not in PATH_VALUES]
    if unknown:
        raise AssertionError(f"cannot call {template}: unknown path parameters {unknown}")
    return re.sub(r"{([^}:]+)(?::[^}]*)?}", lambda m: PATH_VALUES[m.group(1)], template)


async def test_every_route_outside_the_public_list_needs_a_session(
    admin: None, store_settings: Settings, engine: AsyncEngine
) -> None:
    before = await all_rows_text(engine)
    with api_client(store_settings) as client:
        routes = every_route(client.app)
        assert PUBLIC_ROUTES <= set(routes), "a public route is missing"
        protected = [r for r in routes if r not in PUBLIC_ROUTES]
        problems = []
        for method, template in protected:
            if method not in CALLABLE_METHODS:
                problems.append(f"{method} {template}: method the test cannot call")
                continue
            try:
                path = call_path(template)
            except AssertionError as exc:
                problems.append(str(exc))
                continue
            response = client.request(method, path, json={})
            if response.status_code != 401 or response.json() != {
                "detail": "authentication required"
            }:
                problems.append(
                    f"{method} {template} answered {response.status_code} without a session"
                )
            elif response.headers.get("cache-control") != "no-store":
                problems.append(f"{method} {template}: no Cache-Control: no-store")
    assert problems == [], "\n".join(problems)
    assert await all_rows_text(engine) == before  # no action performed
    print(
        f"\nroute enumeration: {len(protected)} protected routes answered 401;",
        "public:",
        sorted(f"{m} {p}" for m, p in PUBLIC_ROUTES),
    )


def test_enumeration_fails_on_a_route_left_open(store_settings: Settings) -> None:
    from fastapi import APIRouter

    app = create_app(store_settings)
    unprotected = APIRouter(prefix="/api")

    @unprotected.get("/forgotten")
    async def forgotten() -> dict:
        return {}

    app.include_router(unprotected)
    with TestClient(app, base_url=BASE_URL, headers=HEADERS) as client:
        assert ("GET", "/api/forgotten") in every_route(app)
        assert client.get("/api/forgotten").status_code == 200  # the test above would name it
    with pytest.raises(AssertionError, match="unknown path parameters"):
        call_path("/api/things/{thing_id}")


async def test_protected_responses_are_not_cached(admin: None, store_settings: Settings) -> None:
    with api_client(store_settings) as client:
        login(client)
        for path in ("/api/devices/1", "/api/devices", "/api/settings/discovery", SESSION):
            assert client.get(path).headers["cache-control"] == "no-store"


async def test_status_and_health_are_public(store_settings: Settings) -> None:
    with api_client(store_settings) as client:
        assert client.get("/api/status").status_code == 200
        assert client.get("/api/health").status_code == 200


async def test_no_account_can_be_created_through_the_api(
    store_settings: Settings, engine: AsyncEngine
) -> None:
    with api_client(store_settings) as client:
        assert attempt(client, ADMIN, ADMIN_PASSWORD).status_code == 401
        for path in ("/api/auth/register", "/api/auth/account", "/api/admin"):
            assert client.post(
                path, json={"username": ADMIN, "password": ADMIN_PASSWORD}
            ).status_code in (401, 404)
    assert await rows(engine, "SELECT id FROM admin_account") == []


# --- 4.3 cross-site requests ----------------------------------------------------------------

SETTINGS_BODY = {
    "seeds": [], "allowed_ranges": ["10.99.0.0/24"], "exclusions": [], "max_depth": 1,
    "follow_ip_mac": False, "max_candidates": 4096, "max_devices": 256, "max_datagrams": 50000,
}  # fmt: skip


def put_settings(client: TestClient, headers: dict[str, str]):
    return client.put("/api/settings/discovery", json=SETTINGS_BODY, headers=headers)


async def test_cross_site_check_with_local_origins(admin: None, store_settings: Settings) -> None:
    with api_client(store_settings, headers={}) as client:
        response = client.post(LOGIN, json={"username": ADMIN, "password": ADMIN_PASSWORD})
        assert response.status_code == 403  # login needs the header too
        login_ok = client.post(
            LOGIN, json={"username": ADMIN, "password": ADMIN_PASSWORD}, headers=HEADERS
        )
        assert login_ok.status_code == 200
        results = {
            "missing header": put_settings(client, {}),
            "wrong header value": put_settings(client, {"X-NetScanner-Request": "yes"}),
            "wrong Origin": put_settings(client, {**HEADERS, "Origin": "https://evil.example"}),
            "null Origin": put_settings(client, {**HEADERS, "Origin": "null"}),
            "other port": put_settings(client, {**HEADERS, "Origin": "http://localhost:9999"}),
            "https localhost": put_settings(
                client, {**HEADERS, "Origin": "https://localhost:8080"}
            ),
            "localhost": put_settings(client, {**HEADERS, "Origin": "http://localhost:8080"}),
            "127.0.0.1": put_settings(client, {**HEADERS, "Origin": "http://127.0.0.1:8080"}),
            "no Origin": put_settings(client, HEADERS),
            "GET without header": client.get("/api/settings/discovery", headers={}),
        }
    codes = {name: r.status_code for name, r in results.items()}
    assert codes == {
        "missing header": 403, "wrong header value": 403, "wrong Origin": 403,
        "null Origin": 403, "other port": 403, "https localhost": 403,
        "localhost": 200, "127.0.0.1": 200, "no Origin": 200, "GET without header": 200,
    }  # fmt: skip
    print("\ncross-site check, local origins:", codes)


async def test_form_from_another_site_creates_no_run(
    admin: None, store_settings: Settings, engine: AsyncEngine
) -> None:
    with api_client(store_settings) as client:
        login(client)
        # What a cross-site form can send: no custom header, the other site's Origin.
        response = client.post(
            "/api/runs", headers={"X-NetScanner-Request": "", "Origin": "https://evil.example"}
        )
        assert response.status_code == 403
    assert await rows(engine, "SELECT id FROM collection_runs") == []


async def test_cross_site_check_behind_a_tls_proxy(admin: None, store_settings: Settings) -> None:
    settings = store_settings.model_copy(update={"public_origin": "https://netscanner.example.org"})
    with api_client(settings) as client:
        login(client)
        results = {
            "public https": put_settings(
                client, {**HEADERS, "Origin": "https://netscanner.example.org"}
            ),
            "public http": put_settings(
                client, {**HEADERS, "Origin": "http://netscanner.example.org"}
            ),
            "localhost": put_settings(client, {**HEADERS, "Origin": "http://localhost:8080"}),
            # Forwarded headers never change the allowed origins.
            "forwarded": put_settings(
                client,
                {
                    **HEADERS,
                    "Origin": "https://evil.example",
                    "Host": "evil.example",
                    "X-Forwarded-Host": "evil.example",
                    "X-Forwarded-Proto": "https",
                    "Forwarded": "host=evil.example;proto=https",
                },
            ),
        }
    codes = {name: r.status_code for name, r in results.items()}
    assert codes == {"public https": 200, "public http": 403, "localhost": 403, "forwarded": 403}
    print("\ncross-site check, NETSCANNER_PUBLIC_ORIGIN:", codes)


async def test_forwarded_headers_do_not_add_local_origins(
    admin: None, store_settings: Settings
) -> None:
    with api_client(store_settings) as client:
        login(client)
        response = put_settings(
            client,
            {**HEADERS, "Origin": "http://evil.example:8080", "Host": "evil.example:8080",
             "X-Forwarded-Host": "evil.example:8080", "X-Forwarded-Proto": "http"},
        )  # fmt: skip
    assert response.status_code == 403


# --- 5.2 without the lab-only guard: a real-looking range needs a session --------

REAL_LOOKING = SETTINGS_BODY | {"allowed_ranges": ["198.51.100.0/24"], "seeds": ["198.51.100.10"]}


async def test_real_looking_range_refused_without_session_accepted_with_one(
    admin: None, store_settings: Settings, engine: AsyncEngine
) -> None:
    with api_client(store_settings) as client:
        without = client.put("/api/settings/discovery", json=REAL_LOOKING)
        run_without = client.post("/api/runs")
        assert (without.status_code, run_without.status_code) == (401, 401)
        assert without.json() == {"detail": "authentication required"}
        [stored] = await rows(engine, "SELECT allowed_ranges FROM discovery_settings")
        assert stored["allowed_ranges"] == []  # nothing saved
        login(client)
        with_session = client.put("/api/settings/discovery", json=REAL_LOOKING)
        assert with_session.status_code == 200, with_session.text
        assert with_session.json()["allowed_ranges"] == ["198.51.100.0/24"]
        assert "lab_ranges" not in with_session.json()
        status = client.get("/api/status").json()
    [stored] = await rows(engine, "SELECT allowed_ranges, seeds FROM discovery_settings")
    assert [str(n) for n in stored["allowed_ranges"]] == ["198.51.100.0/24"]
    assert status == {"authentication": True, "admin_exists": True}


async def test_status_without_session_reports_whether_the_admin_exists(
    store_settings: Settings, engine: AsyncEngine
) -> None:
    with api_client(store_settings, headers={}) as client:
        before = client.get("/api/status")
        await create_admin(engine)
        after = client.get("/api/status")
    assert before.json() == {"authentication": True, "admin_exists": False}
    assert after.json() == {"authentication": True, "admin_exists": True}
    assert ADMIN not in after.text and "session" not in after.text
