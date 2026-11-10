# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Tests for lab/generate_synthetic.py: reproducible, consistent and confidential."""

from __future__ import annotations

import io
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "lab"))

import generate_synthetic as gen  # noqa: E402

import check_confidentiality as cc  # noqa: E402

DATA = REPO / "lab" / "snmpsim" / "data"
OUTPUTS = ("lab-sw-01.snmprec", "lab-sw-02.snmprec")


@pytest.fixture
def lab_copy(tmp_path: Path) -> Path:
    """A copy of the lab data folder at its repository path, with srx-01 only."""
    data = tmp_path / "lab" / "snmpsim" / "data"
    data.mkdir(parents=True)
    shutil.copy(DATA / "srx-01.snmprec", data)
    return data


def records(path: Path) -> dict[str, tuple[str, str]]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        oid, tag, value = line.split("|", 2)
        out[oid] = (tag, value)
    return out


def test_generator_is_reproducible(lab_copy: Path) -> None:
    gen.generate(lab_copy)
    first = {name: (lab_copy / name).read_bytes() for name in OUTPUTS}
    gen.generate(lab_copy)
    assert {name: (lab_copy / name).read_bytes() for name in OUTPUTS} == first
    # The committed files are the generator's current output.
    assert {name: (DATA / name).read_bytes() for name in OUTPUTS} == first


def test_output_passes_the_confidentiality_check(lab_copy: Path) -> None:
    gen.generate(lab_copy)
    root = lab_copy.parents[2]
    files = [f"lab/snmpsim/data/{name}" for name in OUTPUTS]
    out, err = io.StringIO(), io.StringIO()
    code = cc.run(
        root,
        files,
        check_stale=False,
        terms_path=root / cc.TERMS_FILE,
        allowlist_path=root / cc.ALLOWLIST_FILE,
        out=out,
        err=err,
    )
    assert code == 0, out.getvalue()


def test_switches_are_consistent_with_srx01() -> None:
    srx = gen.read_srx(DATA / "srx-01.snmprec")
    srx_macs = {h.mac for hosts in srx.hosts_by_interface.values() for h in hosts}
    srx_ips = {h.ip for hosts in srx.hosts_by_interface.values() for h in hosts}
    sw1, sw2 = (records(DATA / name) for name in OUTPUTS)

    # FDB of lab-sw-01: learned entries are srx-01's hosts, srx-01 itself
    # (uplink) or lab-sw-02; the rest are the switch's own self/mgmt entries.
    learned_macs = set()
    for oid, (_, status) in sw1.items():
        if oid.startswith("1.3.6.1.2.1.17.7.1.2.2.1.3.") and status == "3":
            octets = oid.split(".")[-6:]
            learned_macs.add("".join(f"{int(o):02x}" for o in octets))
    assert srx.mac in learned_macs and "020000aa0200" in learned_macs
    hosts = learned_macs - {srx.mac, "020000aa0200"}
    assert len(hosts) == gen.SW1_HOSTS and hosts <= srx_macs

    # The LLDP neighbour lab-sw-02 advertises lab-sw-02's own address.
    man = [o for o in sw1 if o.startswith("1.0.8802.1.1.2.1.4.2.1.3.")]
    advertised = {".".join(o.split(".")[-4:]) for o in man}
    assert advertised == {gen.SW2_ADDRESS, gen.EXTERNAL_NEIGHBOR_ADDRESS}
    assert sw2[f"1.3.6.1.2.1.4.20.1.1.{gen.SW2_ADDRESS}"] == ("64", gen.SW2_ADDRESS)

    # lab-sw-02: no LLDP-MIB, no ifXTable, hosts with srx-01's MAC and IP pairs.
    assert not any(o.startswith(("1.0.8802.", "1.3.6.1.2.1.31.")) for o in sw2)
    media = {
        ".".join(o.split(".")[-4:]): v
        for o, (_, v) in sw2.items()
        if o.startswith("1.3.6.1.2.1.4.22.1.2.")
    }
    assert len(media) == gen.SW2_HOSTS and set(media) <= srx_ips
    pairs = {(h.ip, h.mac) for hosts in srx.hosts_by_interface.values() for h in hosts}
    assert set(media.items()) <= pairs

    # lab-sw-01's IP-MAC table: srx-01, lab-sw-02 and the silent address, all in the lab.
    ip_mac = {
        ".".join(o.split(".")[-4:]): v
        for o, (_, v) in sw1.items()
        if o.startswith("1.3.6.1.2.1.4.35.1.4.")
    }
    assert ip_mac == {
        srx.management_address: srx.mac,
        gen.SW2_ADDRESS: "020000aa0200",
        gen.SILENT_ADDRESS: gen.SILENT_MAC,
    }
    assert gen.SILENT_MAC not in srx_macs | learned_macs

    # Every lab address is distinct and no device holds the silent one.
    used = {srx.management_address, gen.SW1_ADDRESS, gen.SW2_ADDRESS}
    assert len(used) == 3 and gen.SILENT_ADDRESS not in used | srx_ips


def test_synthetic_devices_say_so() -> None:
    for name in OUTPUTS:
        descr = records(DATA / name)["1.3.6.1.2.1.1.1.0"][1]
        assert "synthetic lab device" in descr
