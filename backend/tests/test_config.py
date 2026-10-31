# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Configuration: required secrets, placeholders, .env.example and canaries."""

from __future__ import annotations

import io
import logging
import re
import secrets

import pytest
from pydantic import SecretStr

from netscanner.core.config import (
    EXIT_CONFIG_ERROR,
    PLACEHOLDER,
    Settings,
    env_name,
    load_settings_or_exit,
)
from netscanner.core.startup import bootstrap

from .conftest import REPO_ROOT, Canaries, run_module

ENV_EXAMPLE = REPO_ROOT / ".env.example"


def secret_env(canaries: Canaries) -> dict[str, str]:
    return {
        "NETSCANNER_SECRET_KEY": canaries.secret_key,
        "NETSCANNER_DB_PASSWORD": canaries.db_password,
    }


def example_variables() -> dict[str, str]:
    """Variables in .env.example, including commented-out optional ones."""
    found = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"#?\s*(NETSCANNER_[A-Z0-9_]+)=(.*)$", line)
        if m:
            found[m.group(1)] = m.group(2)
    return found


# --- Required secrets -------------------------------------------------------


@pytest.mark.parametrize("module", ["netscanner.api", "netscanner.collector", "netscanner.migrate"])
def test_missing_secret_names_the_variable(module: str, canaries: Canaries) -> None:
    env = secret_env(canaries)
    del env["NETSCANNER_SECRET_KEY"]
    result = run_module(module, env)
    assert result.returncode == EXIT_CONFIG_ERROR
    assert "NETSCANNER_SECRET_KEY" in result.stderr
    assert "required" in result.stderr
    canaries.assert_absent(result.stdout, result.stderr)


@pytest.mark.parametrize("value", [PLACEHOLDER, "Change-Me", "", "   "])
@pytest.mark.parametrize("field", ["secret_key", "db_password"])
def test_placeholder_or_empty_secret_rejected(
    monkeypatch: pytest.MonkeyPatch, canaries: Canaries, field: str, value: str
) -> None:
    for name, secret in secret_env(canaries).items():
        monkeypatch.setenv(name, secret)
    monkeypatch.setenv(env_name(field), value)
    err = io.StringIO()
    with pytest.raises(SystemExit) as exc:
        load_settings_or_exit(err)
    assert exc.value.code == EXIT_CONFIG_ERROR
    output = err.getvalue()
    assert env_name(field) in output
    expected = "must be changed" if value.strip() else "must not be empty"
    assert expected in output
    canaries.assert_absent(output)


def test_valid_settings_load(monkeypatch: pytest.MonkeyPatch, canaries: Canaries) -> None:
    for name, secret in secret_env(canaries).items():
        monkeypatch.setenv(name, secret)
    settings = load_settings_or_exit()
    assert settings.secret_key.get_secret_value() == canaries.secret_key
    assert settings.db_host == "db"


def test_database_settings_are_separate() -> None:
    fields = Settings.model_fields
    for name in ("db_host", "db_port", "db_name", "db_user", "db_password"):
        assert name in fields
    assert fields["db_password"].annotation is SecretStr
    assert not any("url" in name or "dsn" in name for name in fields)


# --- .env.example -----------------------------------------------------------


def test_every_setting_is_in_env_example() -> None:
    documented = example_variables()
    missing = [env_name(f) for f in Settings.model_fields if env_name(f) not in documented]
    assert missing == [], f"add to .env.example: {missing}"


def test_env_example_has_only_placeholder_secrets() -> None:
    documented = example_variables()
    for field, info in Settings.model_fields.items():
        if info.annotation is SecretStr:
            assert documented[env_name(field)] == PLACEHOLDER


def test_env_example_entries_have_comments() -> None:
    """Every variable belongs to a block of lines that starts with a comment."""
    in_commented_block = False
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            in_commented_block = False
        elif line.startswith("#"):
            in_commented_block = True
        else:
            assert in_commented_block, f"no comment above {line.split('=')[0]}"


# --- Canaries (design D6) ---------------------------------------------------


def test_configuration_printed_or_logged_is_masked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], canaries: Canaries
) -> None:
    for name, secret in secret_env(canaries).items():
        monkeypatch.setenv(name, secret)
    settings = bootstrap("test")  # logs the configuration at startup
    logging.getLogger("netscanner.test").info("settings dump: %r", settings.model_dump())
    texts = [str(settings), repr(settings), settings.model_dump_json(), str(settings.model_dump())]
    captured = capsys.readouterr()
    assert "configuration loaded" in captured.err
    assert "**********" in str(settings)
    canaries.assert_absent(*texts, captured.out, captured.err)


@pytest.mark.parametrize(
    ("variable", "bad_value"),
    [
        ("NETSCANNER_DB_PORT", "not-a-port-"),
        ("NETSCANNER_LOG_LEVEL", "LOUD-"),
        ("NETSCANNER_DB_CONNECT_TIMEOUT", "-"),
    ],
)
def test_invalid_setting_does_not_echo_input(
    canaries: Canaries, variable: str, bad_value: str
) -> None:
    rejected = bad_value + secrets.token_hex(8)
    env = {**secret_env(canaries), variable: rejected}
    result = run_module("netscanner.api", env)
    assert result.returncode == EXIT_CONFIG_ERROR
    assert variable in result.stderr
    assert rejected not in result.stderr + result.stdout
    canaries.assert_absent(result.stdout, result.stderr)


def test_invalid_secret_does_not_echo_input(canaries: Canaries) -> None:
    env = {**secret_env(canaries), "NETSCANNER_DB_PASSWORD": PLACEHOLDER}
    result = run_module("netscanner.collector", env)
    assert result.returncode == EXIT_CONFIG_ERROR
    assert "NETSCANNER_DB_PASSWORD" in result.stderr
    assert "must be changed" in result.stderr
    canaries.assert_absent(result.stdout, result.stderr)
