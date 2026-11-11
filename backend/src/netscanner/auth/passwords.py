# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Password hashing and the account rules (design D2, RNF-05).

Argon2id with the ``argon2-cffi`` RFC 9106 low-memory profile. Every check of
a password, against the stored hash or the fixed dummy hash, goes through
:func:`verify`, so each login path performs exactly one Argon2id verification
(design D5). This is the only module that imports ``argon2`` (design D1).
"""

from __future__ import annotations

import re
import secrets
from functools import cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.profiles import RFC_9106_LOW_MEMORY

PASSWORD_MIN = 12
PASSWORD_MAX = 128
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")

_hasher = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)


class PasswordRuleError(ValueError):
    """A user name or password that breaks the rules; the message never holds the value."""


def check_username(username: str) -> None:
    if not USERNAME_PATTERN.fullmatch(username):
        raise PasswordRuleError(
            "the user name must have 1 to 64 characters: letters, digits, '.', '_' or '-'"
        )


def check_password(password: str, username: str) -> None:
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        raise PasswordRuleError(
            f"the password must have between {PASSWORD_MIN} and {PASSWORD_MAX} characters"
        )
    if password == username:
        raise PasswordRuleError("the password must differ from the user name")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify(password_hash: str, password: str) -> bool:
    """One Argon2id verification; ``False`` for a wrong password or an unusable hash."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Whether the stored hash uses parameters other than the current profile."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


@cache
def dummy_hash() -> str:
    """A fixed hash, made once per process, checked when there is no matching account.

    Its password is random and never kept, so no input can match it.
    """
    return _hasher.hash(secrets.token_urlsafe(32))
