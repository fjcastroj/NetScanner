# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Provenance building blocks: registries, evidence format and the staleness setting."""

from __future__ import annotations

from datetime import timedelta

import pytest

from netscanner.store import registry
from netscanner.store.errors import UnknownNameError
from netscanner.store.evidence import (
    MAX_EVIDENCE_BYTES,
    EvidenceError,
    QueryInput,
    RecordInput,
    build_evidence,
    validate_evidence,
)
from netscanner.store.registry import Origin

from .conftest import REPO_ROOT, Canaries, make_settings

QUERY = {"kind": "query", "id": 812, "mib_object": "LLDP-MIB::lldpLocPortTable"}
RECORD = {"kind": "record", "table": "interfaces", "id": 45}
SNAPSHOT_RECORD = {**RECORD, "snapshot": {"if_index": 7, "if_name": "lab-port-7"}}


def doc(method: str, *inputs: dict, version: int = 1) -> dict:
    return {"method": method, "method_version": version, "inputs": list(inputs)}


# --- Registries -------------------------------------------------------------


def test_registries_reject_unknown_names() -> None:
    with pytest.raises(UnknownNameError):
        registry.check_mib_object("FAKE-MIB::fakeTable")
    with pytest.raises(UnknownNameError):
        registry.get_method("guess-everything")
    with pytest.raises(UnknownNameError):
        registry.check_error_category("Traceback: something")
    assert registry.check_mib_object("IF-MIB::ifXTable") == "IF-MIB::ifXTable"


def test_every_method_documents_itself() -> None:
    for method in registry.METHODS.values():
        assert method.description and method.assumptions and method.version >= 1
    assert registry.get_method("enterprise-registry").origin is Origin.INFERRED
    assert registry.get_method("lldp-portid-ifname").origin is Origin.OBSERVED


@pytest.mark.parametrize(
    ("number", "status", "name"),
    [
        (12356, registry.VendorStatus.KNOWN, "Fortinet"),
        (2636, registry.VendorStatus.KNOWN, "Juniper"),
        (8072, registry.VendorStatus.GENERIC_AGENT, None),
        (99999, registry.VendorStatus.NOT_IN_REGISTRY, None),
    ],
)
def test_vendor_registry(number: int, status: registry.VendorStatus, name: str | None) -> None:
    assert registry.lookup_vendor(number) == (status, name)


@pytest.mark.parametrize(
    ("oid", "number"),
    [("1.3.6.1.4.1.12356.101.1.1", 12356), ("1.3.6.1.4.1.9", 9), ("1.3.6.1.2.1.1", None)],
)
def test_enterprise_number(oid: str, number: int | None) -> None:
    assert registry.enterprise_number(oid) == number


# --- Evidence ---------------------------------------------------------------


def test_inferred_evidence_with_snapshot_accepted() -> None:
    evidence = validate_evidence(
        doc("lldp-portnum-equals-ifindex", QUERY, SNAPSHOT_RECORD), Origin.INFERRED
    )
    assert evidence.to_json()["inputs"][1]["snapshot"] == {"if_index": 7, "if_name": "lab-port-7"}


def test_observed_sources_accepted() -> None:
    sources = build_evidence(
        "lldp-portid-ifname",
        Origin.OBSERVED,
        [
            QueryInput(id=1, mib_object="LLDP-MIB::lldpLocPortTable"),
            QueryInput(id=2, mib_object="IF-MIB::ifXTable"),
        ],
    )
    assert sources.to_json() == {
        "method": "lldp-portid-ifname",
        "method_version": 1,
        "inputs": [
            {"kind": "query", "id": 1, "mib_object": "LLDP-MIB::lldpLocPortTable"},
            {"kind": "query", "id": 2, "mib_object": "IF-MIB::ifXTable"},
        ],
    }


@pytest.mark.parametrize(
    ("value", "origin", "message"),
    [
        ({"method": "lldp-portid-ifname", "inputs": [QUERY]}, Origin.OBSERVED, "format"),
        (doc("lldp-portid-ifname"), Origin.OBSERVED, "format"),
        (doc("lldp-portid-ifname", {**QUERY, "kind": "file"}), Origin.OBSERVED, "format"),
        (doc("lldp-portid-ifname", {**QUERY, "extra": 1}), Origin.OBSERVED, "format"),
        (doc("lldp-portid-ifname", {**QUERY, "mib_object": "X::y"}), Origin.OBSERVED, "format"),
        (doc("lldp-portid-ifname", {**RECORD, "table": "users"}), Origin.OBSERVED, "format"),
        (doc("guess-everything", QUERY), Origin.INFERRED, "format"),
        (doc("lldp-portnum-equals-ifindex", QUERY, RECORD), Origin.INFERRED, "snapshot"),
        (doc("lldp-portid-ifname", QUERY, SNAPSHOT_RECORD), Origin.OBSERVED, "references only"),
        (doc("lldp-portid-ifname", QUERY), Origin.INFERRED, "is observed"),
        (doc("lldp-portid-ifname", QUERY, version=2), Origin.OBSERVED, "version"),
    ],
)
def test_evidence_rejected(value: dict, origin: Origin, message: str) -> None:
    with pytest.raises(EvidenceError, match=message):
        validate_evidence(value, origin)


def test_oversized_evidence_rejected() -> None:
    big = [{**RECORD, "id": i, "snapshot": {"if_descr": "x" * 1000}} for i in range(1, 20)]
    with pytest.raises(EvidenceError, match=f"limit is {MAX_EVIDENCE_BYTES}"):
        validate_evidence(doc("lldp-port-description-match", *big), Origin.INFERRED)


def test_snapshot_values_are_fragments() -> None:
    whole_text = {**RECORD, "snapshot": {"sys_descr": "x" * 5000}}
    with pytest.raises(EvidenceError, match="format"):
        validate_evidence(doc("sysdescr-model-pattern", whole_text), Origin.INFERRED)


def test_evidence_error_does_not_echo_input(canaries: Canaries) -> None:
    value = doc("sysdescr-model-pattern", {**RECORD, "snapshot": {"f": canaries.secret_key * 100}})
    with pytest.raises(EvidenceError) as info:
        validate_evidence(value, Origin.INFERRED)
    canaries.assert_absent(str(info.value), repr(info.value))


def test_record_input_defaults() -> None:
    assert RecordInput(table="devices", id=3).kind == "record"


# --- Staleness setting ------------------------------------------------------


def test_stale_after_defaults_to_seven_days(canaries: Canaries) -> None:
    assert make_settings(canaries).stale_after == timedelta(days=7)


def test_stale_after_from_iso_duration(monkeypatch: pytest.MonkeyPatch, canaries: Canaries) -> None:
    monkeypatch.setenv("NETSCANNER_STALE_AFTER", "PT12H")
    assert make_settings(canaries).stale_after == timedelta(hours=12)


def test_stale_after_must_be_positive(canaries: Canaries) -> None:
    with pytest.raises(ValueError, match="stale_after"):
        make_settings(canaries, stale_after=timedelta(0))


def test_provenance_doc_lists_every_method() -> None:
    doc = (REPO_ROOT / "docs" / "provenance.md").read_text(encoding="utf-8")
    rows = {
        line.split("|")[1].strip().strip("`") for line in doc.splitlines() if line.startswith("| `")
    }
    for method in registry.METHODS.values():
        assert method.name in rows, f"docs/provenance.md does not list {method.name}"
        row = next(line for line in doc.splitlines() if line.startswith(f"| `{method.name}` |"))
        assert f"| {method.origin} | {method.version} |" in row, method.name
