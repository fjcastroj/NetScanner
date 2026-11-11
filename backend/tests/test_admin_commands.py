# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Administrator console commands and password rules (tasks 2.1 to 2.3, design D2, D10)."""

from __future__ import annotations

import io
import logging
import secrets

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.admin.__main__ import EXIT_OK, EXIT_REFUSED, parser, run
from netscanner.auth import passwords
from netscanner.core.config import Settings
from netscanner.core.logging_setup import configure_logging

from .auth_helpers import api_client, login
from .conftest import all_rows_text

pytestmark = pytest.mark.db


def password() -> str:
    return "canary-" + secrets.token_hex(12)


async def command(
    settings: Settings, argv: list[str], stdin: str = "", prompts: list[str] | None = None
) -> tuple[int, str]:
    answers = iter(prompts or [])
    out = io.StringIO()
    code = await run(
        parser().parse_args(argv), settings, io.StringIO(stdin), out, lambda _: next(answers)
    )
    return code, out.getvalue()


async def scalar(engine: AsyncEngine, sql: str) -> object:
    async with engine.connect() as conn:
        return await conn.scalar(text(sql))


# --- 2.1 hashing and rules ----------------------------------------------------------


def test_hash_is_argon2id_with_the_rfc9106_low_memory_profile() -> None:
    value = passwords.hash_password("lab-password-123")
    assert value.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert passwords.verify(value, "lab-password-123")
    assert not passwords.verify(value, "lab-password-124")
    assert not passwords.verify("not a hash", "lab-password-123")
    assert not passwords.needs_rehash(value)


@pytest.mark.parametrize(
    ("username", "candidate", "ok"),
    [
        ("admin", "a" * 11, False),
        ("admin", "a" * 12, True),
        ("admin", "a" * 128, True),
        ("admin", "a" * 129, False),
        ("administrator", "administrator", False),
    ],
)
def test_password_rules(username: str, candidate: str, ok: bool) -> None:
    if ok:
        passwords.check_password(candidate, username)
    else:
        with pytest.raises(passwords.PasswordRuleError) as exc:
            passwords.check_password(candidate, username)
        assert candidate not in str(exc.value)


@pytest.mark.parametrize(
    ("username", "ok"),
    [("lab-admin", True), ("a.b_c-1", True), ("a" * 64, True), ("", False), ("a" * 65, False),
     ("with space", False), ("ádmin", False), ("admin\n", False)],
)  # fmt: skip
def test_username_rules(username: str, ok: bool) -> None:
    if ok:
        passwords.check_username(username)
    else:
        with pytest.raises(passwords.PasswordRuleError):
            passwords.check_username(username)


# --- 2.2 commands ----------------------------------------------------------------


async def test_create_from_stdin(engine: AsyncEngine, store_settings: Settings) -> None:
    secret = password()
    code, out = await command(
        store_settings, ["create", "--username", "lab-admin", "--password-stdin"], secret + "\n"
    )
    assert (code, out.strip()) == (EXIT_OK, "administrator lab-admin created")
    stored = await scalar(engine, "SELECT password_hash FROM admin_account")
    assert passwords.verify(stored, secret)


@pytest.mark.parametrize("ending", ["", "\n", "\r\n"])
async def test_stdin_line_break_is_not_part_of_the_password(
    engine: AsyncEngine, store_settings: Settings, ending: str
) -> None:
    secret = password()
    argv = ["create", "--username", "lab-admin", "--password-stdin"]
    assert (await command(store_settings, argv, secret + ending))[0] == EXIT_OK
    stored = await scalar(engine, "SELECT password_hash FROM admin_account")
    assert passwords.verify(stored, secret)
    assert not passwords.verify(stored, secret + "\r")


async def test_create_with_prompts_twice(engine: AsyncEngine, store_settings: Settings) -> None:
    secret = password()
    code, _ = await command(
        store_settings, ["create", "--username", "lab-admin"], prompts=[secret, secret]
    )
    assert code == EXIT_OK
    code, out = await command(store_settings, ["reset-password"], prompts=[secret, secret + "x"])
    assert code == EXIT_REFUSED and "do not match" in out and secret not in out


async def test_create_twice_refused(engine: AsyncEngine, store_settings: Settings) -> None:
    argv = ["create", "--username", "lab-admin", "--password-stdin"]
    assert (await command(store_settings, argv, password()))[0] == EXIT_OK
    code, out = await command(
        store_settings, ["create", "--username", "other", "--password-stdin"], password()
    )
    assert code == EXIT_REFUSED and "use reset-password" in out
    assert await scalar(engine, "SELECT count(*) FROM admin_account") == 1
    assert await scalar(engine, "SELECT username FROM admin_account") == "lab-admin"


async def test_reset_without_account_refused(engine: AsyncEngine, store_settings: Settings) -> None:
    code, out = await command(store_settings, ["reset-password", "--password-stdin"], password())
    assert code == EXIT_REFUSED and "use create" in out


async def test_reset_ends_every_session(engine: AsyncEngine, store_settings: Settings) -> None:
    first = password()
    await command(store_settings, ["create", "--username", "lab-admin", "--password-stdin"], first)
    with api_client(store_settings) as one, api_client(store_settings) as two:
        login(one, password=first)
        login(two, password=first)
        assert one.get("/api/auth/session").status_code == 200
        assert await scalar(engine, "SELECT count(*) FROM sessions") == 2
        second = password()
        code, out = await command(store_settings, ["reset-password", "--password-stdin"], second)
        assert code == EXIT_OK and "2 open session(s) ended" in out
        assert await scalar(engine, "SELECT count(*) FROM sessions") == 0
        assert one.get("/api/auth/session").status_code == 401
        assert two.get("/api/auth/session").status_code == 401
        login(one, password=second)


async def test_short_password_refused_without_echo(
    engine: AsyncEngine, store_settings: Settings
) -> None:
    short = "canary-" + secrets.token_hex(2)  # 11 characters
    assert len(short) == 11
    code, out = await command(
        store_settings, ["create", "--username", "lab-admin", "--password-stdin"], short
    )
    assert code == EXIT_REFUSED and "between 12 and 128 characters" in out
    assert short not in out
    assert await scalar(engine, "SELECT count(*) FROM admin_account") == 0


def test_password_never_accepted_as_an_argument(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (
        ["create", "--username", "lab-admin", "--password", "lab-password-123"],
        ["reset-password", "lab-password-123"],
        ["create", "--username", "lab-admin", "--password-stdin", "lab-password-123"],
    ):
        with pytest.raises(SystemExit) as exc:
            parser().parse_args(argv)
        assert exc.value.code == 2
    options = {
        option
        for action in parser()._subparsers._group_actions[0].choices.values()  # type: ignore[union-attr]
        for a in action._actions
        for option in a.option_strings
    }
    assert {o for o in options if "password" in o} == {"--password-stdin"}
    capsys.readouterr()


# --- 2.3 canary ---------------------------------------------------------------------


async def test_created_password_appears_nowhere(
    engine: AsyncEngine,
    store_settings: Settings,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("DEBUG", store_settings.secret_values())
    caplog.set_level(logging.DEBUG)
    secret = password()
    code, out = await command(
        store_settings, ["create", "--username", "lab-admin", "--password-stdin"], secret
    )
    assert code == EXIT_OK
    with api_client(store_settings) as client:
        responses = [
            client.post("/api/auth/login", json={"username": "lab-admin", "password": secret}),
            client.get("/api/auth/session"),
            client.get("/api/status"),
            client.post("/api/auth/logout"),
        ]
    assert [r.status_code for r in responses] == [200, 200, 200, 200]
    for output in (out, caplog.text, capsys.readouterr().err, await all_rows_text(engine),
                   *(r.text for r in responses)):  # fmt: skip
        assert secret not in output
