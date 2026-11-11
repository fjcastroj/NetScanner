# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Administrator commands, run on the server (design D10, RNF-05).

    python -m netscanner.admin create --username <name> [--password-stdin]
    python -m netscanner.admin reset-password [--password-stdin]

With Compose: ``docker compose run --rm api python -m netscanner.admin ...``.
The password is read twice without echo, or once from standard input with
``--password-stdin``; it is never accepted as an argument, so it cannot end up
in the shell history or the process list, and it is never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TextIO

from netscanner.auth.account import AccountExists, NoAccount, create_account, reset_password
from netscanner.auth.passwords import PasswordRuleError
from netscanner.core.config import Settings
from netscanner.core.db import create_engine
from netscanner.core.startup import bootstrap

EXIT_OK, EXIT_REFUSED = 0, 1
STDIN_HELP = "read the password once from standard input"


class InputError(Exception):
    pass


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m netscanner.admin", description=__doc__.splitlines()[0]
    )
    commands = p.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create the administrator account")
    create.add_argument("--username", required=True)
    create.add_argument("--password-stdin", action="store_true", help=STDIN_HELP)
    reset = commands.add_parser("reset-password", help="replace the password; ends every session")
    reset.add_argument("--password-stdin", action="store_true", help=STDIN_HELP)
    return p


def read_password(
    from_stdin: bool, stdin: TextIO, prompt: Callable[[str], str] = getpass.getpass
) -> str:
    if from_stdin:
        # One line; its line break (LF, or CRLF when piped from Windows) is not
        # part of the password.
        line = stdin.readline()
        if line.endswith("\n"):
            line = line[:-1]
        return line[:-1] if line.endswith("\r") else line
    first = prompt("Password: ")
    if prompt("Repeat the password: ") != first:
        raise InputError("the two passwords do not match")
    return first


async def run(
    args: argparse.Namespace,
    settings: Settings,
    stdin: TextIO,
    out: TextIO,
    prompt: Callable[[str], str] = getpass.getpass,
) -> int:
    try:
        password = read_password(args.password_stdin, stdin, prompt)
    except InputError as exc:
        print(f"refused: {exc}", file=out)
        return EXIT_REFUSED
    engine = create_engine(settings)
    now = datetime.now(UTC)
    try:
        if args.command == "create":
            await create_account(engine, args.username, password, now)
            print(f"administrator {args.username} created", file=out)
        else:
            ended = await reset_password(engine, password, now)
            print(f"password replaced; {ended} open session(s) ended", file=out)
    except PasswordRuleError as exc:
        print(f"refused: {exc}", file=out)
        return EXIT_REFUSED
    except AccountExists:
        print("refused: an administrator already exists; use reset-password", file=out)
        return EXIT_REFUSED
    except NoAccount:
        print("refused: no administrator exists yet; use create", file=out)
        return EXIT_REFUSED
    finally:
        del password
        await engine.dispose()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    settings = bootstrap("admin")
    return asyncio.run(run(args, settings, sys.stdin, sys.stdout))


if __name__ == "__main__":
    sys.exit(main())
