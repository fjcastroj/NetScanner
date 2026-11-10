# NetScanner SNMP lab

A small simulated network for development, automated tests and the parts of
the evaluation that the real network cannot cover. It mixes one **real,
anonymised** device with **synthetic** switches. [manifest.yaml](manifest.yaml)
records the origin of every device and of every value set derived from
another device.

## Devices and IP plan

Network `netscanner-lab`, 10.99.0.0/24, gateway 10.99.0.1.

| Address | Device | Origin | What it is |
|---------|--------|--------|------------|
| 10.99.0.13 | `srx-01` | real, anonymised | Juniper SRX1500, JUNOS 19.4R3.11, captured 2026-11-03 |
| 10.99.0.2 | `lab-sw-01` | synthetic | Juniper-like access switch with LLDP and Q-BRIDGE |
| 10.99.0.3 | `lab-sw-02` | synthetic | Fortinet-like switch without LLDP-MIB or `ifXTable` |
| 10.99.0.9 | none | - | address in the lab range where nothing answers |
| 203.0.113.10 | `lab-ap-01` | synthetic | only advertised over LLDP; outside the lab range |

Each device is a separate snmpsim container with its own address, started by
the Compose override file `docker-compose.lab.yml`. The lab community is `netscanner-lab`; it is accepted
only by lab data.

## What each device models

- **`srx-01`** is a lab fixture made from one capture of one device. Its data
  describes that model and firmware on that date, not Juniper devices in
  general (see [docs/vendors/juniper-srx1500.md](../docs/vendors/juniper-srx1500.md)).
  It has 259 interfaces with 64-bit counters and `ifHighSpeed`, about 427
  IPv4 IP-MAC entries in both `ipNetToPhysicalTable` and `ipNetToMediaTable`,
  `ipAddressTable` and `ipAddrTable`, LLDP local system data without local
  port entries, an empty LLDP remote table, and no ENTITY-MIB.
- **`lab-sw-01`** models an access switch:
  - bridge port `n` is `ifIndex 500+n` and LLDP port number `n`, so neither
    equals the `ifIndex`;
  - LLDP local ports use the interface name subtype;
  - two LLDP neighbours: `lab-sw-02` advertising 10.99.0.3, and `lab-ap-01`
    advertising an address in 203.0.113.0/24;
  - `dot1qTpFdbTable` with FDB ids 3 and 4 mapped to VLANs 10 and 20 through
    `dot1qVlanFdbId`, so FDB ids differ from VLAN ids;
  - 30 host MAC addresses from `srx-01` learned on access ports, `srx-01`'s
    MAC on the uplink, `self` entries and a `mgmt` entry.
  - a small `ipNetToPhysicalTable` on `irb.0` with three entries: 10.99.0.13
    with `srx-01`'s MAC address (derived), 10.99.0.3 with `lab-sw-02`'s MAC
    address and 10.99.0.9 with an invented MAC address. With IP-MAC following
    on, they lead discovery to `srx-01`, to `lab-sw-02` (already found over
    LLDP) and to the silent address.
- **`lab-sw-02`** models a smaller switch:
  - no LLDP-MIB, so it is seen from `lab-sw-01` only, a one-sided neighbour;
  - no `ifXTable`, so only 32-bit counters;
  - `dot1dTpFdbTable` with `lab-sw-01` and 5 hosts from `srx-01`;
  - those hosts also in `ipNetToMediaTable`, and an `ipNetToPhysicalTable`
    without rows (supported but empty).

Synthetic devices carry real vendor `sysObjectID` values. Their `sysDescr`
says "synthetic lab device", and the manifest marks them as synthetic.

## Regenerating the synthetic data

```sh
python lab/generate_synthetic.py
```

The generator uses only the standard library and a fixed seed, and reads
`srx-01.snmprec`. Running it again gives byte-identical files, and a test in
`scripts/tests/test_lab_generator.py` checks that, along with consistency
with `srx-01` and the confidentiality check. Never edit the synthetic
`.snmprec` files by hand.

## Running the lab

```sh
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build
```

The collector joins `netscanner-lab` only with this file; without it no stack
creates the lab subnet (a Compose profile cannot attach a network to a
service, so the lab uses an override file). Tests do not
use Compose. They start snmpsim with `lab/snmpsim/data` on a free local port
(see `backend/tests/conftest.py`), with each device selected by its
community, which is the data file name.

## Limitations

- **snmpsim never answers `noSuchObject`.** It answers `noSuchInstance` for
  everything that does not exist, so in the lab every missing table looks
  "supported but empty". `noSuchObject`, mid-walk timeouts, error statuses,
  non-increasing OIDs and malformed datagrams are tested against the scripted
  agent in `backend/tests/snmp_agent.py`.
- **Synthetic switches do not prove vendor behaviour.** They exercise the
  code paths that real switches need, but say nothing about how a real
  Juniper or Fortinet switch answers.
- **Real data is one capture.** It cannot show changes over time, reboots or
  counter wraps.
- Delays, packet loss and agent load are not simulated by snmpsim.

## Pending hypotheses

| Id | Hypothesis | Why it stays pending |
|----|------------|----------------------|
| H1 | `lldpLocPortNum` may or may not equal `ifIndex` | `srx-01` returned no LLDP local port entries; the synthetic switch only models one possible answer |
| H2 | `ifIndex` values persist across reboots | Needs two comparable captures around a reboot; there is one capture |
| H3 | Chassis identifiers are unique and stable | One real device cannot show uniqueness or stability; HA clusters such as `srx-01`'s chassis cluster may share identifiers |
| H6 | A FortiSwitch in FortiLink mode answers SNMP on its own address, and with which tables | No managed FortiSwitch has been captured; `lab-sw-02` is synthetic and proves nothing about it |

H4 (`noSuchObject` versus `noSuchInstance` on a column probe) and H5
(GETBULK with 25 repetitions) were confirmed for `srx-01`'s model and
firmware only. See [docs/vendors/README.md](../docs/vendors/README.md).
