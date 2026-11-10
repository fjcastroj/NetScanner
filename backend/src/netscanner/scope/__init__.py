# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Which addresses NetScanner may query (snmp-scope spec, RNF-03, RNF-06).

Pure code with no I/O: the scope policy, authorised targets, the lab-only
guard and the validation and freezing of discovery settings.
"""

from netscanner.scope.policy import (
    LAB_RANGES,
    AuthorizedTarget,
    Rejection,
    ScopeError,
    ScopePolicy,
    check_lab_guard,
)
from netscanner.scope.settings import (
    DiscoveryCeilings,
    DiscoverySettings,
    LimitsAboveCeiling,
    SettingsError,
    check_run_limits,
    run_parameters_for,
    validate_settings,
)

__all__ = [
    "LAB_RANGES",
    "AuthorizedTarget",
    "DiscoveryCeilings",
    "DiscoverySettings",
    "LimitsAboveCeiling",
    "Rejection",
    "ScopeError",
    "ScopePolicy",
    "SettingsError",
    "check_lab_guard",
    "check_run_limits",
    "run_parameters_for",
    "validate_settings",
]
