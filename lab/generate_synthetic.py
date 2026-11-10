# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Generate the synthetic lab switches from the anonymised srx-01 data (design D9).

Standard library only and a fixed seed: running it again gives byte-identical
files. The switches take their host MAC and IP addresses from srx-01's
ipNetToPhysicalTable and srx-01's own MAC address for the uplink and for
lab-sw-01's IP-MAC entry of srx-01, so later changes can locate hosts and
infer links across the lab. Everything else is
invented and every synthetic device says so in its sysDescr.

Usage: python lab/generate_synthetic.py [--data DIR]
"""

from __future__ import annotations

import argparse
import ipaddress
import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

SEED = 20261103
DATA = Path(__file__).resolve().parent / "snmpsim" / "data"
LAB_NET = ipaddress.IPv4Network("10.99.0.0/24")

SW1_ADDRESS = "10.99.0.2"
SW2_ADDRESS = "10.99.0.3"
SILENT_ADDRESS = "10.99.0.9"  # in the lab range, no agent answers there
EXTERNAL_NEIGHBOR_ADDRESS = "203.0.113.10"  # advertised by LLDP, outside the lab range

# Built from the prefix length: netmasks are allowed only in lab data files.
MASK_24 = str(ipaddress.IPv4Network("0.0.0.0/24").netmask)

SW1_HOSTS = 30
SW2_HOSTS = 5
SILENT_MAC = "020000aa0900"  # invented: the silent address has no device behind it


# --- Reading srx-01 ---------------------------------------------------------


@dataclass(frozen=True)
class Host:
    if_index: int
    ip: str
    mac: str  # 12 hex digits


@dataclass(frozen=True)
class Srx:
    management_address: str
    mac: str
    hosts_by_interface: dict[int, list[Host]]


def read_srx(path: Path) -> Srx:
    own: list[str] = []
    if_index_of: dict[str, int] = {}
    phys: dict[int, str] = {}
    hosts: dict[int, list[Host]] = defaultdict(list)
    for line in path.read_text(encoding="utf-8").splitlines():
        oid, _tag, value = line.split("|", 2)
        if oid.startswith("1.3.6.1.2.1.4.20.1.1."):
            own.append(value)
        elif oid.startswith("1.3.6.1.2.1.4.20.1.2."):
            if_index_of[oid[len("1.3.6.1.2.1.4.20.1.2.") :]] = int(value)
        elif oid.startswith("1.3.6.1.2.1.2.2.1.6.") and len(value) == 12:
            phys[int(oid.rsplit(".", 1)[1])] = value.lower()
        elif oid.startswith("1.3.6.1.2.1.4.35.1.4.") and len(value) == 12:
            parts = oid.split(".")
            if_index, kind, length = int(parts[10]), parts[11], int(parts[12])
            if kind == "1" and length == 4:  # IPv4 entries
                hosts[if_index].append(Host(if_index, ".".join(parts[13:17]), value.lower()))
    # Management address: the lowest own address in the lab range whose
    # interface has a 6-byte physical address.
    candidates = sorted(
        (ipaddress.IPv4Address(a), if_index_of[a])
        for a in own
        if ipaddress.IPv4Address(a) in LAB_NET and if_index_of.get(a) in phys
    )
    if not candidates:
        raise SystemExit("srx-01 has no own lab address with a physical address")
    address, if_index = candidates[0]
    return Srx(str(address), phys[if_index], dict(hosts))


def pick_hosts(srx: Srx, rng: random.Random) -> tuple[list[Host], list[Host]]:
    """Hosts for each switch from the two interfaces with most IP-MAC entries."""
    ranked = sorted(srx.hosts_by_interface, key=lambda i: (-len(srx.hosts_by_interface[i]), i))
    seen = {srx.mac}
    chosen = []
    for if_index, count in ((ranked[0], SW1_HOSTS), (ranked[1], SW2_HOSTS)):
        pool = [h for h in srx.hosts_by_interface[if_index] if h.mac not in seen]
        unique = list({h.mac: h for h in pool}.values())
        picked = sorted(rng.sample(unique, count), key=lambda h: ipaddress.IPv4Address(h.ip))
        seen.update(h.mac for h in picked)
        chosen.append(picked)
    return chosen[0], chosen[1]


# --- Writing snmprec --------------------------------------------------------


class Records:
    def __init__(self) -> None:
        self.lines: dict[str, str] = {}

    def add(self, oid: str, tag: str, value: object) -> None:
        if oid in self.lines:
            raise ValueError(f"duplicate OID {oid}")
        self.lines[oid] = f"{oid}|{tag}|{value}"

    def write(self, path: Path) -> None:
        ordered = sorted(self.lines, key=lambda o: tuple(int(p) for p in o.split(".")))
        text = "\n".join(self.lines[o] for o in ordered) + "\n"
        path.write_bytes(text.encode("utf-8"))


def mac_index(mac: str) -> str:
    return ".".join(str(int(mac[i : i + 2], 16)) for i in range(0, 12, 2))


def octets_index(text: str) -> str:
    """Length-prefixed OCTET STRING index."""
    raw = text.encode()
    return ".".join([str(len(raw)), *(str(b) for b in raw)])


def system(r: Records, descr: str, object_id: str, name: str, uptime: int) -> None:
    r.add("1.3.6.1.2.1.1.1.0", "4", descr)
    r.add("1.3.6.1.2.1.1.2.0", "6", object_id)
    r.add("1.3.6.1.2.1.1.3.0", "67", uptime)
    r.add("1.3.6.1.2.1.1.5.0", "4", name)
    r.add("1.3.6.1.2.1.1.7.0", "2", 6)


@dataclass(frozen=True)
class Port:
    if_index: int
    bridge_port: int
    name: str
    descr: str
    mac: str
    oper_up: bool
    speed: int  # bit/s


def interfaces(r: Records, ports: list[Port], rng: random.Random, *, x_table: bool) -> None:
    base = "1.3.6.1.2.1.2.2.1"
    for p in ports:
        i = p.if_index
        r.add(f"{base}.1.{i}", "2", i)
        r.add(f"{base}.2.{i}", "4", p.descr)
        r.add(f"{base}.3.{i}", "2", 6)
        r.add(f"{base}.4.{i}", "2", 1514)
        r.add(f"{base}.5.{i}", "66", min(p.speed, 4294967295))
        r.add(f"{base}.6.{i}", "4x", p.mac)
        r.add(f"{base}.7.{i}", "2", 1)
        r.add(f"{base}.8.{i}", "2", 1 if p.oper_up else 2)
        r.add(f"{base}.9.{i}", "67", rng.randrange(0, 10_000_000))
        in_octets, out_octets = rng.randrange(0, 2**40), rng.randrange(0, 2**40)
        r.add(f"{base}.10.{i}", "65", in_octets % 2**32)
        r.add(f"{base}.11.{i}", "65", rng.randrange(0, 2**32))
        r.add(f"{base}.14.{i}", "65", rng.randrange(0, 100))
        r.add(f"{base}.16.{i}", "65", out_octets % 2**32)
        r.add(f"{base}.17.{i}", "65", rng.randrange(0, 2**32))
        r.add(f"{base}.20.{i}", "65", 0)
        if x_table:
            ext = "1.3.6.1.2.1.31.1.1.1"
            r.add(f"{ext}.1.{i}", "4", p.name)
            r.add(f"{ext}.6.{i}", "70", in_octets)
            r.add(f"{ext}.10.{i}", "70", out_octets)
            r.add(f"{ext}.15.{i}", "66", p.speed // 1_000_000)
            r.add(f"{ext}.18.{i}", "4", "")


def address(r: Records, ip: str, if_index: int, mask: str) -> None:
    r.add(f"1.3.6.1.2.1.4.20.1.1.{ip}", "64", ip)
    r.add(f"1.3.6.1.2.1.4.20.1.2.{ip}", "2", if_index)
    r.add(f"1.3.6.1.2.1.4.20.1.3.{ip}", "64", mask)


def bridge_base(r: Records, bridge_mac: str, ports: list[Port]) -> None:
    r.add("1.3.6.1.2.1.17.1.1.0", "4x", bridge_mac)
    r.add("1.3.6.1.2.1.17.1.2.0", "2", len(ports))
    r.add("1.3.6.1.2.1.17.1.3.0", "2", 2)  # transparent-only
    for p in ports:
        r.add(f"1.3.6.1.2.1.17.1.4.1.1.{p.bridge_port}", "2", p.bridge_port)
        r.add(f"1.3.6.1.2.1.17.1.4.1.2.{p.bridge_port}", "2", p.if_index)


# --- lab-sw-01 --------------------------------------------------------------

LEARNED, SELF, MGMT = 3, 4, 5
# Q-BRIDGE: FDB ids are not VLAN ids; dot1qVlanFdbId maps one to the other.
SW1_VLANS = {10: ("users", 3), 20: ("servers", 4)}


def lab_sw_01(srx: Srx, hosts: list[Host], rng: random.Random) -> Records:
    r = Records()
    system(
        r,
        "Juniper Networks, Inc. ex2300-24p Ethernet Switch, synthetic lab device "
        "(NetScanner lab), not a real capture",
        "1.3.6.1.4.1.2636.1.1.1.2.132",
        "lab-sw-01",
        rng.randrange(10_000_000, 900_000_000),
    )
    # Bridge port n is ifIndex 500 + n and LLDP port number n: neither equals
    # the ifIndex, as on real switches (hypothesis H1 stays open).
    ports = [
        Port(500 + n, n, f"ge-0/0/{n - 1}", f"ge-0/0/{n - 1}", f"020000aa01{n:02x}", True, 10**9)
        for n in range(1, 27)
    ]
    irb = Port(600, 0, "irb.0", "irb.0", "020000aa0100", True, 10**9)
    interfaces(r, [*ports, irb], rng, x_table=True)
    address(r, SW1_ADDRESS, irb.if_index, MASK_24)
    bridge_base(r, "020000aa0100", ports)

    uplink, to_sw2 = ports[23], ports[24]  # ge-0/0/23 to srx-01, ge-0/0/24 to lab-sw-02
    # LLDP local data, port id subtype interfaceName (5).
    r.add("1.0.8802.1.1.2.1.3.1.0", "2", 4)
    r.add("1.0.8802.1.1.2.1.3.2.0", "4x", "020000aa0100")
    r.add("1.0.8802.1.1.2.1.3.3.0", "4", "lab-sw-01")
    for p in ports:
        n = p.bridge_port
        r.add(f"1.0.8802.1.1.2.1.3.7.1.2.{n}", "2", 5)
        r.add(f"1.0.8802.1.1.2.1.3.7.1.3.{n}", "4", p.name)
        r.add(f"1.0.8802.1.1.2.1.3.7.1.4.{n}", "4", p.descr)
    # Remote entries: lab-sw-02, which has no LLDP-MIB of its own (one-sided
    # view), and a device advertising a management address outside the lab.
    neighbors = [
        (to_sw2, 1, "020000aa0200", "port1", "lab-sw-02", "4x|20", SW2_ADDRESS),
        (ports[19], 2, "020000aa0300", "eth0", "lab-ap-01", "4x|04", EXTERNAL_NEIGHBOR_ADDRESS),
    ]
    rem = "1.0.8802.1.1.2.1.4.1.1"
    for port, index, chassis, port_id, name, caps, mgmt in neighbors:
        key = f"0.{port.bridge_port}.{index}"
        r.add(f"{rem}.4.{key}", "2", 4)
        r.add(f"{rem}.5.{key}", "4x", chassis)
        r.add(f"{rem}.6.{key}", "2", 5)
        r.add(f"{rem}.7.{key}", "4", port_id)
        r.add(f"{rem}.8.{key}", "4", port_id)
        r.add(f"{rem}.9.{key}", "4", name)
        r.add(f"{rem}.10.{key}", "4", f"{name}, synthetic lab device")
        tag, value = caps.split("|")
        r.add(f"{rem}.11.{key}", tag, value)
        r.add(f"{rem}.12.{key}", tag, value)
        man = f"1.0.8802.1.1.2.1.4.2.1.3.{key}.1.4.{mgmt}"
        r.add(man, "2", 2)  # lldpRemManAddrIfSubtype ifIndex

    # Q-BRIDGE: VLANs and their FDB ids.
    for vlan, (name, fdb) in SW1_VLANS.items():
        r.add(f"1.3.6.1.2.1.17.7.1.4.2.1.3.0.{vlan}", "66", fdb)
        r.add(f"1.3.6.1.2.1.17.7.1.4.3.1.1.{vlan}", "4", name)
    fdb_users, fdb_servers = SW1_VLANS[10][1], SW1_VLANS[20][1]
    entries: list[tuple[int, str, int, int]] = []
    for i, host in enumerate(hosts):
        fdb = fdb_users if i % 3 else fdb_servers
        entries.append((fdb, host.mac, ports[i % 20].bridge_port, LEARNED))
    for fdb in (fdb_users, fdb_servers):
        entries.append((fdb, srx.mac, uplink.bridge_port, LEARNED))
        entries.append((fdb, "020000aa0200", to_sw2.bridge_port, LEARNED))
        entries.append((fdb, "020000aa0100", 0, MGMT))  # the switch's own management MAC
    for p in (uplink, to_sw2):
        entries.append((fdb_users, p.mac, p.bridge_port, SELF))
    fdb_base = "1.3.6.1.2.1.17.7.1.2.2.1"
    for fdb, mac, port, status in entries:
        key = f"{fdb}.{mac_index(mac)}"
        r.add(f"{fdb_base}.2.{key}", "2", port)
        r.add(f"{fdb_base}.3.{key}", "2", status)

    # A small ipNetToPhysicalTable on irb.0, so that IP-MAC following reaches
    # lab addresses: srx-01 (its management address and MAC), lab-sw-02 (its
    # internal MAC) and the silent address (an invented MAC). No random values,
    # so the rest of the file does not change with it.
    for ip, mac in sw1_ip_mac(srx):
        key = f"{irb.if_index}.1.4.{ip}"
        r.add(f"1.3.6.1.2.1.4.35.1.4.{key}", "4x", mac)
        r.add(f"1.3.6.1.2.1.4.35.1.6.{key}", "2", 3)  # dynamic
        r.add(f"1.3.6.1.2.1.4.35.1.7.{key}", "2", 1)  # reachable
    return r


def sw1_ip_mac(srx: Srx) -> list[tuple[str, str]]:
    """IP-MAC entries of lab-sw-01, in address order."""
    entries = [
        (srx.management_address, srx.mac),
        (SW2_ADDRESS, "020000aa0200"),
        (SILENT_ADDRESS, SILENT_MAC),
    ]
    return sorted(entries, key=lambda e: ipaddress.IPv4Address(e[0]))


# --- lab-sw-02 --------------------------------------------------------------


def lab_sw_02(hosts: list[Host], rng: random.Random) -> Records:
    r = Records()
    system(
        r,
        "FortiSwitch-124E synthetic lab device (NetScanner lab), not a real capture",
        "1.3.6.1.4.1.12356.106.1.124",
        "lab-sw-02",
        rng.randrange(10_000_000, 900_000_000),
    )
    # No LLDP-MIB and no ifXTable: 32-bit counters only. Bridge port = ifIndex.
    ports = [
        Port(n, n, f"port{n}", f"port{n}", f"020000aa02{n:02x}", n <= 10, 10**9)
        for n in range(1, 25)
    ]
    internal = Port(30, 0, "internal", "internal", "020000aa0200", True, 10**9)
    interfaces(r, [*ports, internal], rng, x_table=False)
    address(r, SW2_ADDRESS, internal.if_index, MASK_24)
    bridge_base(r, "020000aa0200", ports)
    # dot1dTpFdbTable: lab-sw-01 on port1, a few hosts, one self entry.
    entries = [("020000aa0100", 1, LEARNED), (ports[0].mac, 1, SELF)]
    entries += [(h.mac, 2 + i, LEARNED) for i, h in enumerate(hosts)]
    base = "1.3.6.1.2.1.17.4.3.1"
    for mac, port, status in entries:
        key = mac_index(mac)
        r.add(f"{base}.1.{key}", "4x", mac)
        r.add(f"{base}.2.{key}", "2", port)
        r.add(f"{base}.3.{key}", "2", status)
    # ipNetToMediaTable with the hosts; ipNetToPhysicalTable is left without
    # rows (snmpsim then answers noSuchInstance: supported but empty).
    for h in hosts:
        media = f"1.3.6.1.2.1.4.22.1.{{}}.{internal.if_index}.{h.ip}"
        r.add(media.format(1), "2", internal.if_index)
        r.add(media.format(2), "4x", h.mac)
        r.add(media.format(3), "64", h.ip)
        r.add(media.format(4), "2", 3)
    return r


def generate(data: Path) -> list[Path]:
    rng = random.Random(SEED)  # noqa: S311 - reproducible lab data, not a secret
    srx = read_srx(data / "srx-01.snmprec")
    sw1_hosts, sw2_hosts = pick_hosts(srx, rng)
    outputs = []
    for name, records in (
        ("lab-sw-01", lab_sw_01(srx, sw1_hosts, rng)),
        ("lab-sw-02", lab_sw_02(sw2_hosts, rng)),
    ):
        path = data / f"{name}.snmprec"
        records.write(path)
        outputs.append(path)
    return outputs


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, default=DATA)
    args = parser.parse_args(argv)
    for path in generate(args.data):
        print(f"wrote {path.name}")


if __name__ == "__main__":
    main()
