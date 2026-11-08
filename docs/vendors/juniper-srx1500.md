# Juniper SRX1500, firmware JUNOS 19.4R3.11

- Verified on: capture of 2026-11-03, 1 device (`srx-01` in the lab)
- Capture: anonymised and reviewed by the author; the anonymised data is
  `lab/snmpsim/data/srx-01.snmprec`, and the raw capture stays outside the
  repository
- SNMP version used for the capture: v2c

Everything below describes this model with this firmware on this capture
date only. It is not a description of Juniper devices in general, nor of
other SRX models or JUNOS versions.

## Query outcomes

"Not implemented" means the column probe (a GET on the column without
index) answered `noSuchObject`. "Supported but empty in this capture" means
it answered `noSuchInstance`: the device knows the object but had no rows
then, which says nothing about other moments or other devices.

| Object | Observed | Indicator | Notes |
|--------|----------|-----------|-------|
| `SNMPv2-MIB::system` | answered | - | `sysObjectID` in the Juniper enterprise (2636) |
| `IF-MIB::ifTable` | 259 rows | - | many logical units and `reth` interfaces of a chassis cluster |
| `IF-MIB::ifXTable` | 259 rows | - | `ifName` equals `ifDescr`; 64-bit counters and `ifHighSpeed` on every interface |
| `IP-MIB::ipAddrTable`, `IP-MIB::ipAddressTable` | 47 addresses | - | |
| `IP-MIB::ipNetToPhysicalTable` | 427 IPv4 entries | - | the current table is implemented |
| `IP-MIB::ipNetToMediaTable` | 427 entries | - | the deprecated table is implemented too |
| `ENTITY-MIB` | **not implemented** | `noSuchObject` | the model must come from `sysDescr` (inferred) or from a Juniper module later (RNF-08) |
| `LLDP-MIB` local system data | answered | - | chassis id subtype 4 (MAC address) |
| `LLDP-MIB::lldpLocPortTable` | no entries returned in this capture | - | nothing is concluded about local port numbering |
| `LLDP-MIB::lldpRemTable` | **supported but empty in this capture** | `noSuchInstance` | no LLDP neighbours at capture time; LLDP is not "unsupported" |
| `Q-BRIDGE-MIB::dot1qTpFdbTable` | **supported but empty in this capture** | `noSuchInstance` | |

A GET on a **table node** answered `noSuchObject` even for tables that
exist. The Net-SNMP fallback of the capture kit showed it for
`lldpRemTable` and `dot1qTpFdbTable`, whose column probes answered
`noSuchInstance`. NetScanner therefore never classifies with the table node
(design D4).

## Hypotheses

| Id | Result for this model and firmware | Evidence (anonymised) |
|----|------------------------------------|-----------------------|
| H1 | Not testable with this capture | no `lldpLocPortTable` entries were returned |
| H2 | Pending | one capture; needs two comparable captures around a reboot |
| H3 | Not testable with this capture | one device. Its chassis cluster (`reth` interfaces) is the kind of setup where nodes may share a chassis identifier |
| H4 | **Confirmed**: `noSuchObject` for unimplemented objects, `noSuchInstance` for implemented ones, on a column probe | ENTITY-MIB versus `lldpRemTable` and `dot1qTpFdbTable` |
| H5 | **Confirmed**: GETBULK works and is faster than GETNEXT; no errors up to 50 repetitions | 5,698 varbinds: GETNEXT 7.9 s; GETBULK 4.2 s (10), 2.5 s (25), 2.1 s (50). Hence the default of 25 and maximum of 50 (design D5) |
| H6 | Not applicable | not a FortiSwitch |

## Other behaviour

- With `ifName` equal to `ifDescr`, an LLDP port mapped by interface name
  and one mapped by description cannot be told apart on this device.
- The volume (259 interfaces, 427 IP-MAC entries) makes `srx-01` the
  realistic load case of the lab.
