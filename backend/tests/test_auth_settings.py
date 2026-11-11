# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Session, bind address and public origin settings (add-admin-authentication D3, D6).

Tasks 3.1 and 4.3: the Secure cookie may be off only when the web service is
published on a loopback address, and ``NETSCANNER_PUBLIC_ORIGIN`` must be a
bare origin.
"""

from __future__ import annotations

import io
from datetime import timedelta

import pytest
from pydantic import ValidationError

from netscanner.auth.service import allowed_origins
from netscanner.core.config import (
    api_settings_errors,
    exit_if_invalid_for_api,
    format_validation_error,
    is_loopback_bind,
    parse_web_bind,
)

from .conftest import Canaries, make_settings


def test_session_defaults(canaries: Canaries) -> None:
    settings = make_settings(canaries)
    assert settings.session_idle == timedelta(hours=8)
    assert settings.session_max_age == timedelta(hours=24)
    assert settings.session_cookie_secure is True
    assert settings.web_bind == "127.0.0.1:8080"
    assert settings.public_origin is None


def test_idle_longer_than_max_age_refused(canaries: Canaries) -> None:
    with pytest.raises(ValidationError) as exc:
        make_settings(canaries, session_idle="PT25H", session_max_age="PT24H")
    [line] = format_validation_error(exc.value)
    assert "NETSCANNER_SESSION_IDLE" in line and "NETSCANNER_SESSION_MAX_AGE" in line


# --- NETSCANNER_WEB_BIND and the Secure cookie (task 3.1) -----------------------

LOOPBACK = ["127.0.0.1:8080", "[::1]:8080"]
NOT_LOOPBACK = ["0.0.0.0:8080", "[::]:8080", "8080", "192.0.2.10:8080"]


@pytest.mark.parametrize("bind", LOOPBACK)
def test_secure_off_accepted_with_loopback_bind(canaries: Canaries, bind: str) -> None:
    settings = make_settings(canaries, session_cookie_secure=False, web_bind=bind)
    assert is_loopback_bind(bind)
    assert api_settings_errors(settings) == []
    exit_if_invalid_for_api(settings)  # does not exit


@pytest.mark.parametrize("bind", NOT_LOOPBACK)
def test_secure_off_refused_with_other_bind(canaries: Canaries, bind: str) -> None:
    settings = make_settings(canaries, session_cookie_secure=False, web_bind=bind)
    assert not is_loopback_bind(bind)
    [error] = api_settings_errors(settings)
    assert "NETSCANNER_SESSION_COOKIE_SECURE" in error and "NETSCANNER_WEB_BIND" in error
    out = io.StringIO()
    with pytest.raises(SystemExit) as exc:
        exit_if_invalid_for_api(settings, out)
    assert exc.value.code == 2
    assert "NETSCANNER_SESSION_COOKIE_SECURE" in out.getvalue()
    assert "NETSCANNER_WEB_BIND" in out.getvalue()


@pytest.mark.parametrize("bind", NOT_LOOPBACK)
def test_secure_on_accepted_with_any_bind(canaries: Canaries, bind: str) -> None:
    assert api_settings_errors(make_settings(canaries, web_bind=bind)) == []


@pytest.mark.parametrize(
    ("bind", "parsed"),
    [
        ("127.0.0.1:8080", ("127.0.0.1", 8080)),
        ("[::1]:8443", ("::1", 8443)),
        ("8080", (None, 8080)),
        (" 0.0.0.0:80 ", ("0.0.0.0", 80)),
    ],
)
def test_web_bind_parsed(bind: str, parsed: tuple) -> None:
    assert parse_web_bind(bind) == parsed


@pytest.mark.parametrize(
    "bind",
    [
        "localhost:8080",
        "2001:db8::1:8080",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:",
        "[::1]8080",
    ],
)
def test_malformed_web_bind_refused(canaries: Canaries, bind: str) -> None:
    with pytest.raises(ValidationError) as exc:
        make_settings(canaries, web_bind=bind)
    [line] = format_validation_error(exc.value)
    assert line.startswith("configuration error: NETSCANNER_WEB_BIND:")


# --- NETSCANNER_PUBLIC_ORIGIN (task 4.3) --------------------------------------------


@pytest.mark.parametrize(
    ("value", "normalised"),
    [
        ("https://netscanner.example", "https://netscanner.example"),
        ("https://netscanner.example:8443", "https://netscanner.example:8443"),
        ("HTTPS://NetScanner.Example:443", "https://netscanner.example"),
        ("http://netscanner.example:80", "http://netscanner.example"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ],
)
def test_public_origin_accepted(canaries: Canaries, value: str, normalised: str) -> None:
    settings = make_settings(canaries, public_origin=value)
    assert settings.public_origin == normalised
    assert allowed_origins(settings) == {normalised}


@pytest.mark.parametrize(
    "value",
    [
        "https://netscanner.example/",
        "https://netscanner.example/netscanner",
        "https://admin@netscanner.example",
        "https://admin:secret@netscanner.example",
        "https://netscanner.example?x=1",
        "https://netscanner.example#top",
        "ftp://netscanner.example",
        "netscanner.example",
        "https://",
        "https://netscanner.example:99999",
    ],
)
def test_public_origin_refused(canaries: Canaries, value: str) -> None:
    with pytest.raises(ValidationError) as exc:
        make_settings(canaries, public_origin=value)
    [line] = format_validation_error(exc.value)
    assert line.startswith("configuration error: NETSCANNER_PUBLIC_ORIGIN:")
    assert "secret" not in line


def test_empty_public_origin_means_unset(canaries: Canaries) -> None:
    assert make_settings(canaries, public_origin="").public_origin is None


@pytest.mark.parametrize(
    ("bind", "origins"),
    [
        ("127.0.0.1:8080", {"http://localhost:8080", "http://127.0.0.1:8080"}),
        ("[::1]:9090", {"http://localhost:9090", "http://127.0.0.1:9090"}),
        ("8080", {"http://localhost:8080", "http://127.0.0.1:8080"}),
    ],
)
def test_local_origins_from_the_bind_port(canaries: Canaries, bind: str, origins: set) -> None:
    assert allowed_origins(make_settings(canaries, web_bind=bind)) == origins
