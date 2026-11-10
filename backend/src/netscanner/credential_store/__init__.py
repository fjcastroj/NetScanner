# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Storage of the SNMP credential set (snmp-credentials spec, RF-01, RNF-01).

The API uses :class:`CredentialService` (write-only); the SNMP adapter uses
:class:`CredentialResolver`, the only path to a decrypted credential.
"""

from netscanner.credential_store.crypto import CredentialUnreadable
from netscanner.credential_store.resolver import CredentialResolver
from netscanner.credential_store.service import (
    CredentialDescription,
    CredentialService,
    credential_version,
    delete_unused_credentials,
)

__all__ = [
    "CredentialDescription",
    "CredentialResolver",
    "CredentialService",
    "CredentialUnreadable",
    "credential_version",
    "delete_unused_credentials",
]
