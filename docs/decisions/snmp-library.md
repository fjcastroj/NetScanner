# Decision: SNMP library

**Status:** Decided. PySNMP 7.1.32, pinned exactly in `backend/pyproject.toml`
and `uv.lock`. Reviewed again after the first run against real devices
(`add-admin-authentication`). Measured 2026-11-08 (design D2 of
`add-snmp-client-and-lab`).

## Options

| Option | For | Against |
|--------|-----|---------|
| **PySNMP** (lextudio, 7.x) | Pure Python and asyncio native; installs with `uv` on Windows and in the slim image without compilers | Changed maintainer and API recently, so the version is pinned and only `netscanner/snmp/pysnmp_client.py` imports it |
| Net-SNMP Python bindings | Reference implementation | C extension; difficult to build on Windows |
| Net-SNMP command-line tools | Reference implementation, no Python dependency | One process per request or walk, text parsing, and credentials on the command line, visible in the process list |

## Criteria

Measured on the lab, with Net-SNMP (`snmpbulkwalk`) as the reference:

1. The values are identical for every table of `srx-01` in the registry.
2. Every classification case gives the correct outcome.
3. Walk time is at most 2× Net-SNMP's.
4. It installs on Windows and in the container.

## Measurements

**Setup.** `srx-01` was served by snmpsim 1.2.2 under `docker-compose.lab.yml`.
Measurements ran from a container on `netscanner-lab` (Docker Desktop on
Windows), with Net-SNMP 5.9.4.pre2 and max-repetitions 25. The script is
`backend/tests/measure_snmp_library.py`, run as
`python -m tests.measure_snmp_library --host 10.99.0.13 --community netscanner-lab`.

### 1. Values

Every table of the registry was walked with the PySNMP client and with
`snmpbulkwalk`, and the registry's columns were compared row by row.

| Table | PySNMP outcome | Rows | Values equal to snmpbulkwalk |
|-------|----------------|------|------------------------------|
| `SNMPv2-MIB::system` | ok | 1 | yes |
| `IF-MIB::ifTable` | ok | 259 | yes |
| `IF-MIB::ifXTable` | ok | 259 | yes |
| `IP-MIB::ipAddrTable` | ok | 47 | yes |
| `IP-MIB::ipAddressTable` | ok | 47 | yes |
| `IP-MIB::ipNetToMediaTable` | ok | 427 | yes |
| `IP-MIB::ipNetToPhysicalTable` | ok | 427 | yes |
| `ENTITY-MIB::entPhysicalTable` | empty | 0 | yes |
| `LLDP-MIB::lldpLocalSystemData` | ok | 1 | yes |
| `LLDP-MIB::lldpLocPortTable` | empty | 0 | yes |
| `LLDP-MIB::lldpRemTable` | empty | 0 | yes |
| `LLDP-MIB::lldpRemManAddrTable` | empty | 0 | yes |
| `BRIDGE-MIB::dot1dBase` | ok | 1 | yes |
| `BRIDGE-MIB::dot1dBasePortTable` | empty | 0 | yes |
| `BRIDGE-MIB::dot1dTpFdbTable` | empty | 0 | yes |
| `Q-BRIDGE-MIB::dot1qTpFdbTable` | empty | 0 | yes |
| `Q-BRIDGE-MIB::dot1qVlanCurrentTable` | empty | 0 | yes |

All values are equal. The tables without rows are equal trivially. In
snmpsim they come out `empty` because the simulator never answers
`noSuchObject`, so on the real device ENTITY-MIB would be `not_available`
(see `docs/vendors/juniper-srx1500.md`).

### 2. Outcomes

The contract suite (`backend/tests/test_snmp_contract.py`) has 31 tests. It
ran unchanged against the PySNMP client and against a minimal Net-SNMP-based
implementation written only for this comparison
(`backend/tests/netsnmp_client.py`). On Linux, both passed all 31, 62 tests
in total.

It covers:
- `ok`, `empty`, `not_available` and an ambiguous probe answer;
- `no_response` from a silent agent;
- `partial` after a mid-walk timeout;
- non-increasing OIDs with and without rows;
- the error statuses `genErr` and `authorizationError`;
- a garbage datagram;
- the row limit;
- one request in flight per device, and the global device limit;
- the results contract;
- the lab tables, SNMPv3 authPriv, and walks of selected columns.

The cases that snmpsim cannot produce run against the scripted agent
(`backend/tests/snmp_agent.py`).

### 3. Walk time

Median of five whole-table walks:

| Walk | PySNMP median (s) | snmpbulkwalk median (s) | Ratio |
|------|-------------------|-------------------------|-------|
| `IF-MIB::ifTable` | 3.43 | 2.78 | 1.24 |
| `IF-MIB::ifXTable` | 3.05 | 2.41 | 1.26 |

These times come from snmpsim, not from the device. On the real SRX1500, a
GETBULK walk of 5,698 varbinds took 2.5 s with 25 repetitions (H5,
`docs/vendors/juniper-srx1500.md`).

### 4. Installation

| Environment | PySNMP | Net-SNMP |
|-------------|--------|----------|
| Windows 11 (development) | Installed by `uv sync` (pure-Python wheels; `cryptography` for SNMPv3 privacy has binary wheels); the whole test suite runs | Not available: `snmpget` is not installed and winget has no Net-SNMP package; it would need a third-party build or compiling from source |
| `python:3.12-slim` (backend image) | Installed by `uv sync --locked`, no compilers | `apt-get install snmp` works, but it adds system tools to the image only for this |

## Decision

PySNMP meets all four criteria:
- every value is identical;
- every outcome case passes;
- walk times are 1.24× and 1.26× Net-SNMP's, within the 2× limit;
- it installs cleanly on Windows and in the container.

Net-SNMP is kept as the reference for measurements only.

The decision is reopened before `add-device-discovery` if a PySNMP upgrade
fails the contract suite, or if the first real run shows a criterion
failing on real devices.
