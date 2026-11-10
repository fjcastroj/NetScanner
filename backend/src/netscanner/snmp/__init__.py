# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Read-only SNMP client (add-snmp-client-and-lab).

Code that queries devices depends on :class:`SnmpClient` and the result
types only; the PySNMP implementation lives in ``pysnmp_client`` and is the
only module that imports the library.
"""

from netscanner.snmp.credentials import (
    CredentialError,
    SnmpV2cCredential,
    SnmpV3Credential,
    parse_credential,
)
from netscanner.snmp.factory import create_client
from netscanner.snmp.results import GetResult, SnmpClient, SnmpException, TableResult
from netscanner.snmp.tables import TABLES, TableSpec, get_table
from netscanner.snmp.walker import (
    BoundedClient,
    BudgetPool,
    CredentialSource,
    ScopeViolation,
    SnmpLimits,
)

__all__ = [
    "TABLES",
    "BoundedClient",
    "BudgetPool",
    "CredentialError",
    "CredentialSource",
    "GetResult",
    "ScopeViolation",
    "SnmpClient",
    "SnmpException",
    "SnmpLimits",
    "SnmpV2cCredential",
    "SnmpV3Credential",
    "TableResult",
    "TableSpec",
    "create_client",
    "get_table",
    "parse_credential",
]
