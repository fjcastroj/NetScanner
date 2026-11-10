# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Juniper model rule from sysDescr (netscanner.vendors.juniper; RF-11, RNF-08).

The rule follows only the format of the srx-01 capture, is selected only by
the Juniper enterprise number and runs only when ENTITY-MIB gave no model and
the generic pattern found nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from netscanner.store.service import Store
from netscanner.vendors import infer_model
from netscanner.vendors.juniper import match_sysdescr

from .store_lab import Lab

DATA = Path(__file__).resolve().parents[2] / "lab" / "snmpsim" / "data"
JUNIPER_OID = "1.3.6.1.4.1.2636.1.1.1.2.137"
METHOD = "juniper-sysdescr-pattern"


def lab_system(device: str) -> dict[str, str]:
    """sysDescr and sysObjectID of a lab device, from its data file."""
    values = {}
    for line in (DATA / f"{device}.snmprec").read_text(encoding="utf-8").splitlines():
        oid, _tag, value = line.split("|", 2)
        if oid == "1.3.6.1.2.1.1.1.0":
            values["sys_descr"] = value
        elif oid == "1.3.6.1.2.1.1.2.0":
            values["sys_object_id"] = value
    return values


SRX = lab_system("srx-01")
SW1 = lab_system("lab-sw-01")
# A Juniper sysDescr in another format (invented): the rule must not guess.
OTHER_JUNIPER = "Juniper Networks, Inc. mx-lab routing platform, JUNOS release LAB-1"


def test_srx01_format_gives_model_and_version_fragments() -> None:
    found = match_sysdescr(SRX["sys_descr"])
    assert found is not None
    assert (found.model, found.version) == ("srx1500", "19.4R3.11")
    assert found.fragments() == {
        "model_fragment": "Juniper Networks, Inc. srx1500 internet router",
        "version_fragment": "kernel JUNOS 19.4R3.11",
    }
    assert all(len(f) < len(SRX["sys_descr"]) // 2 for f in found.fragments().values())


@pytest.mark.parametrize("sys_descr", [SW1["sys_descr"], OTHER_JUNIPER, ""])
def test_other_formats_give_nothing(sys_descr: str) -> None:
    assert match_sysdescr(sys_descr) is None
    assert infer_model(2636, sys_descr) is None


@pytest.mark.parametrize("enterprise", [12356, 9, None])
def test_selected_only_by_the_juniper_enterprise(enterprise: int | None) -> None:
    assert infer_model(enterprise, SRX["sys_descr"]) is None
    assert infer_model(2636, SRX["sys_descr"]) is not None


# --- Through the store ---------------------------------------------------------


@pytest.fixture
def lab(store: Store, engine: AsyncEngine) -> Lab:
    return Lab(store, engine)


async def _infer(lab: Lab, system: dict[str, str]) -> tuple[bool, object]:
    device = await lab.device()
    query = await lab.query("SNMPv2-MIB::system", device=device)
    await lab.store.store_system(query, device, system)
    changed = await lab.store.infer_model_from_sysdescr(device)
    return changed, (await lab.store.read_device(device)).groups.get("model")


@pytest.mark.db
async def test_srx01_model_inferred_with_its_own_method_and_fragments(lab: Lab) -> None:
    await lab.run()
    changed, model = await _infer(lab, SRX)
    assert changed
    assert model.values == {"model": "srx1500", "software_version": "19.4R3.11"}
    for name in ("model", "software_version"):
        source = model.field_source(name)
        assert (source.origin, source.method) == ("inferred", METHOD)
        snapshot = source.evidence["inputs"][1]["snapshot"]
        assert snapshot == {
            "model_fragment": "Juniper Networks, Inc. srx1500 internet router",
            "version_fragment": "kernel JUNOS 19.4R3.11",
        }
        assert SRX["sys_descr"] not in str(source.evidence)  # never the whole sysDescr


@pytest.mark.db
@pytest.mark.parametrize(
    "system",
    [
        SW1,  # Juniper enterprise, synthetic sysDescr not in the captured format
        {"sys_descr": OTHER_JUNIPER, "sys_object_id": JUNIPER_OID},
        {"sys_descr": SRX["sys_descr"], "sys_object_id": "1.3.6.1.4.1.12356.101.1.1"},
    ],
    ids=["lab-sw-01", "other-juniper-format", "non-juniper-sysobjectid"],
)
async def test_no_model_inferred_outside_the_rule(lab: Lab, system: dict[str, str]) -> None:
    await lab.run()
    changed, model = await _infer(lab, system)
    assert not changed
    assert model is None  # no model group at all


@pytest.mark.db
async def test_generic_pattern_goes_first(lab: Lab) -> None:
    await lab.run()
    descr = SRX["sys_descr"].replace("internet router,", "internet router, model SRX-LAB,")
    changed, model = await _infer(lab, {"sys_descr": descr, "sys_object_id": JUNIPER_OID})
    assert changed and model.values["model"] == "SRX-LAB"
    assert model.field_source("model").method == "sysdescr-model-pattern"
