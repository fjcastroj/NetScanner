# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Vendor-specific rules, each in its own module (RNF-08).

A rule here applies only to the vendor selected by its enterprise number and
only where the standard tables and the generic rules give nothing. Each rule
is based on verified captures (``docs/vendors``); a vendor without a capture
has no rule.
"""

from __future__ import annotations

from netscanner.vendors import juniper
from netscanner.vendors.juniper import ModelMatch


def infer_model(enterprise_number: int | None, sys_descr: str) -> tuple[str, ModelMatch] | None:
    """A vendor rule's method and match for this device, or ``None``.

    The rule is selected by the enterprise number of ``sysObjectID`` only; the
    caller uses it only when ENTITY-MIB gave no model and the generic pattern
    found nothing. Only Juniper has a rule.
    """
    if enterprise_number == juniper.ENTERPRISE_NUMBER:
        found = juniper.match_sysdescr(sys_descr)
        if found is not None:
            return juniper.METHOD, found
    return None


__all__ = ["ModelMatch", "infer_model"]
