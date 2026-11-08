# Verified vendor behaviour

NetScanner never assumes how a vendor implements a MIB. This folder records
behaviour that has been **verified** on real devices, with one file per
vendor, model and firmware version. For example, `fortinet-lab-model-7.2.md`
uses a model and version from the device, never its name, serial or
location.

Captures from the company network stay outside the repository and are never
given to AI tools (see [../confidentiality.md](../confidentiality.md)). Only
the anonymised conclusions below enter the repository. Use lab or
documentation addresses and fictitious names (`lab-sw-01`) in every example.

## Data to capture per model and firmware

| Object | Used to check |
|--------|---------------|
| `LLDP-MIB::lldpLocChassisIdSubtype`, `lldpLocChassisId` | H3, identity by chassis id |
| `LLDP-MIB::lldpLocPortTable` | H1, local port mapping |
| `LLDP-MIB::lldpRemTable` | neighbour entries |
| `LLDP-MIB::lldpRemManAddrTable` | management addresses |
| `IF-MIB::ifTable`, `IF-MIB::ifXTable` | H1, H2, interface names and speeds |
| `IP-MIB::ipAddressTable` or `IP-MIB::ipAddrTable` | device addresses |
| `SNMPv2-MIB::sysObjectID` | enterprise number and vendor registry |
| `SNMPv2-MIB::sysDescr` | model and version fragments, if any |
| `ENTITY-MIB::entPhysicalModelName` | observed model |

For each object, also note the query outcome (ok, empty, not available, no
response, partial, error) and the indicator returned (`noSuchObject`,
`noSuchInstance`, `endOfMibView` or end of subtree).

## Hypotheses

The status is per model and firmware. "Confirmed" holds only for the models
listed; every other model stays pending until it is captured.

| Id | Hypothesis | How to verify | Status |
|----|------------|---------------|--------|
| H1 | `lldpLocPortNum` may or may not equal `ifIndex` | Compare `lldpLocPortTable` with `ifXTable` on each model | Pending: not testable on the SRX1500 capture (no local port entries) |
| H2 | `ifIndex` values persist across reboots | Two comparable captures around a reboot; with only one capture it stays pending and is documented as a limitation | Pending: one capture only |
| H3 | Chassis identifiers are unique and stable | Uniqueness across the captured devices; stability needs comparable captures over time. Check HA clusters and virtual chassis, which may share one chassis id and model | Pending: one device captured (an SRX chassis cluster) |
| H4 | The agent distinguishes `noSuchObject` from `noSuchInstance` on a column probe | GET on columns of implemented and unimplemented objects, without index | Confirmed for Juniper SRX1500, JUNOS 19.4R3.11; pending elsewhere |
| H5 | GETBULK works, is faster than GETNEXT, and its limits on repetitions | Walk times and errors with 10, 25 and 50 repetitions against GETNEXT | Confirmed for Juniper SRX1500, JUNOS 19.4R3.11 (no errors up to 50); pending elsewhere |
| H6 | A FortiSwitch in FortiLink mode answers SNMP on its own address, and with which tables | Capture of a managed FortiSwitch on its own address | Pending: no FortiSwitch captured (not applicable to the SRX1500) |

Verified models: [Juniper SRX1500, JUNOS 19.4R3.11](juniper-srx1500.md).

Until a hypothesis is verified for a model, NetScanner keeps treating the
behaviour as an assumption. For H1, a port mapped by number is stored as
inferred with the method `lldp-portnum-equals-ifindex` (see
[../provenance.md](../provenance.md)).

## Template

Copy this into `docs/vendors/<vendor>-<model>-<firmware>.md`:

```markdown
# <Vendor> <model>, firmware <version>

- Verified on: <date>, <number of devices> device(s)
- Capture: anonymised, kept outside the repository
- SNMP versions tried: <v2c / v3>

## Query outcomes

| Object | Outcome | Indicator | Notes |
|--------|---------|-----------|-------|
| LLDP-MIB::lldpLocPortTable | ok | end of subtree | |

## Hypotheses

| Id | Result | Evidence (anonymised) |
|----|--------|-----------------------|
| H1 | lldpLocPortNum equals ifIndex: yes / no / partly | e.g. port 3 -> ifIndex 3 on all ports |
| H2 | pending / persisted across a reboot | |
| H3 | unique among the captured devices: yes / no; stable: pending | |

## Other behaviour

- <e.g. ifXTable missing, sysDescr format, vendor-specific tables>
```
