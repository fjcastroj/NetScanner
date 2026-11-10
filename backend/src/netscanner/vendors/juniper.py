# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Juniper model and version from ``sysDescr`` (RF-11, RNF-08).

Deliberately narrow. The patterns follow only the format observed in the
``srx-01`` capture (SRX1500, JUNOS 19.4R3.11, docs/vendors/juniper-srx1500.md):

    Juniper Networks, Inc. <model> internet router, kernel JUNOS <version>, ...

Other Juniper products, models and releases may describe themselves
differently; for them this rule finds nothing and no model is inferred. It is
used only for devices whose ``sysObjectID`` is in the Juniper enterprise
(2636), when ENTITY-MIB gave no model and the generic pattern found nothing.
Only the matched fragments are kept as evidence, never the whole ``sysDescr``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ENTERPRISE_NUMBER = 2636
METHOD = "juniper-sysdescr-pattern"

_MODEL = re.compile(
    r"^Juniper Networks, Inc\. ([a-z]{2,4}[0-9]{2,5}[a-z0-9-]{0,16}) internet router,"
)
# Right after the model fragment, as in the capture.
_VERSION = re.compile(r" kernel JUNOS ([0-9]{1,3}\.[0-9]{1,3}[A-Z][0-9A-Za-z.-]{1,24}),")


@dataclass(frozen=True)
class ModelMatch:
    model: str
    model_fragment: str
    version: str | None = None
    version_fragment: str | None = None

    def fragments(self) -> dict[str, str]:
        found = {"model_fragment": self.model_fragment}
        if self.version_fragment is not None:
            found["version_fragment"] = self.version_fragment
        return found


def match_sysdescr(sys_descr: str) -> ModelMatch | None:
    """Model and version fragments in the captured format, or ``None``."""
    model = _MODEL.search(sys_descr)
    if model is None:
        return None
    version = _VERSION.match(sys_descr, model.end())
    return ModelMatch(
        model=model.group(1),
        model_fragment=model.group(0).removesuffix(","),
        version=version.group(1) if version else None,
        version_fragment=version.group(0).strip().removesuffix(",") if version else None,
    )
