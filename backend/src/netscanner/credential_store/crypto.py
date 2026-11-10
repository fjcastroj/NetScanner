# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Encryption of the SNMP credential's secret fields (design D5).

HKDF-SHA256 over ``NETSCANNER_SECRET_KEY`` with two fixed labels gives the
32-byte Fernet key and a 16-byte key identifier, stored hex-encoded. The
identifier lets a credential encrypted with another key be reported as
unusable without decrypting anything, and does not reveal the encryption
key while the secret key has enough entropy.

Only this package and the SNMP adapter (through ``CredentialResolver``) may
call :func:`decrypt_secret`; an architecture test checks it.
"""

from __future__ import annotations

import base64
import json

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENCRYPTION_INFO = b"netscanner snmp credential encryption key v1"
KEY_ID_INFO = b"netscanner snmp credential key identifier v1"


class CredentialUnreadable(Exception):
    """The stored credential cannot be used with the current secret key.

    The message never contains a secret value or the token.
    """

    category = "credential_unreadable"


def _derive(secret_key: str, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(
        secret_key.encode()
    )


def key_id(secret_key: str) -> str:
    return _derive(secret_key, KEY_ID_INFO, 16).hex()


def _fernet(secret_key: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_derive(secret_key, ENCRYPTION_INFO, 32)))


def encrypt_secret(fields: dict[str, str], secret_key: str) -> bytes:
    return _fernet(secret_key).encrypt(json.dumps(fields, separators=(",", ":")).encode())


def decrypt_secret(token: bytes, secret_key: str) -> dict[str, str]:
    """The decryption helper. Raises :class:`CredentialUnreadable` on any failure."""
    try:
        return json.loads(_fernet(secret_key).decrypt(bytes(token)))
    except (InvalidToken, ValueError):
        raise CredentialUnreadable("the stored SNMP credential cannot be decrypted") from None
