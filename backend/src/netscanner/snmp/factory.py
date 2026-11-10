# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""The only entry point to the SNMP client outside ``netscanner.snmp`` (design D7).

Only composition roots that execute SNMP use it, which today means the
collector; the API only creates pending runs and never obtains a client. The
PySNMP adapter is imported here, inside the function, so importing
``netscanner.snmp`` does not load the SNMP library.
"""

from __future__ import annotations

from netscanner.core.config import Settings
from netscanner.snmp.results import SnmpClient
from netscanner.snmp.walker import CredentialSource, SnmpLimits


def create_client(settings: Settings, resolver: CredentialSource) -> SnmpClient:
    from netscanner.snmp.pysnmp_client import PySnmpClient

    return PySnmpClient(resolver, SnmpLimits.from_settings(settings))
