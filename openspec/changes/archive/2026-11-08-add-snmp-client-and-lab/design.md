# Design

## Context

The store expects results with a precise contract (omitted field = not
retrieved, `None` = absent only in a complete query, explicit
`confirms_row`). This change provides the client that produces such results
and the lab to test it. Access to the real network is limited, so the lab
must carry development until the application runs end to end.

Evidence from the real capture of `srx-01` (Juniper SRX1500, JUNOS
19.4R3.11, captured 2026-11-03, anonymised and reviewed). Every finding
applies to that model, firmware and capture only; the capture is a lab
fixture, not a description of Juniper devices in general:

| Finding | Consequence |
|---------|-------------|
| GET on a column without index: `noSuchObject` for unimplemented objects, `noSuchInstance` for implemented ones (H4 confirmed for this model) | Classification by column probe (D4) |
| GET on a table node answers `noSuchObject` even when the table exists but is empty (the Net-SNMP fallback showed it for `lldpRemTable` and `dot1qTpFdbTable`, whose column probes answered `noSuchInstance`) | Never classify with the table node |
| GETBULK on 5,698 varbinds: 4.2 s with 10 repetitions, 2.5 s with 25, 2.1 s with 50; GETNEXT 7.9 s; no errors up to 50 (H5) | Default 25, maximum 50 (D5) |
| ENTITY-MIB not implemented on this SRX1500 with JUNOS 19.4R3.11 | Model from `sysDescr` (inferred) or a Juniper module later (RNF-08); not generalised to other Juniper devices |
| Both `ipNetToPhysicalTable` and `ipNetToMediaTable` implemented, 427 IPv4 entries | Discovery uses the current table and keeps the fallback |
| LLDP-MIB local data present; the remote table is supported (column probe `noSuchInstance`) but was empty in this capture, and no local port entries were returned | H1 and H3 cannot be tested with this capture; nothing is concluded about LLDP support beyond that |
| 259 interfaces, many logical units and `reth` interfaces of an SRX chassis cluster; `ifName` equals `ifDescr`; 64-bit counters and `ifHighSpeed` on all | HA cluster note for H3; realistic volume for tests |
| snmpsim answers `noSuchInstance` for everything that does not exist | Scripted test agent (D11) |

## Goals / Non-Goals

**Goals:** a read-only, bounded, testable client with reliable outcomes; a
lab that mixes real and synthetic data honestly; a library decision based
on measurements.

**Non-Goals:** MIB parsers and discovery, scope checks, credential storage,
polling, more captures from the real network.

## Decisions

### D1. Client interface and result types — Decision
`netscanner.snmp` exposes a `SnmpClient` protocol:
- `get(target, oids) -> GetResult` (values or per-OID exception indicator);
- `walk_table(target, table, columns=None) -> TableResult`.

`Target` holds address, port and a credential object. `TableSpec` comes from
a registry of the tables used in iteration 1 (OID, columns, probe column,
MIB object name as stored in `snmp_queries`). `TableResult` holds rows keyed
by index with only the columns received, outcome, `complete`, indicator,
error category, request count, start time and duration. Mapping results to
the store belongs to `add-device-discovery`.

### D2. SNMP library: PySNMP, pending measurement — Hypothesis
PySNMP is pure Python and asyncio-native, which fits the collector and
installs on Windows and in the slim image without compilers. Alternatives:
Net-SNMP Python bindings (C extension, difficult on Windows), or the Net-SNMP
command-line tools through subprocesses (text parsing, one process per walk,
credentials need a temporary config file). PySNMP changed maintainer and API
recently, so the version is pinned and the API used is wrapped in one module.

Verification: `docs/decisions/snmp-library.md` with measurements on the lab
against `snmpbulkwalk` as reference: identical values for every table of
`srx-01`, correct outcome for every classification case, walk time of
`ifTable` and `ifXTable`, installation result on Windows and in the
container. Criteria: values identical, outcomes all correct, walk time at
most 2x Net-SNMP. If PySNMP fails a criterion, the decision is reopened
before `add-device-discovery`.

### D3. Walk strategy — Decision
`columns=None` walks the whole table subtree with GETBULK (fewest requests);
a list of columns walks each column separately (used by polling later).
Completeness is per walk: a whole-table walk interrupted after the first
columns is not complete, and the columns not reached are not reported.
Walks stop at the end of the subtree, at `endOfMibView`, on a non-increasing
OID or at the row limit.

### D4. Outcome classification — Decision
1. Rows received and walk ended normally: `ok`.
2. Rows received and walk interrupted (timeout, error, non-increasing OID,
   row limit): `partial` with category.
3. No rows: GET of the probe column without index:
   `noSuchObject` → `not_available`; `noSuchInstance` → `empty`;
   anything else → `empty` with the actual answer as indicator
   (`endOfMibView`, or `value_returned` when the probe returns a value).
4. No answer to the first request: `no_response`.
5. Error status or undecodable response with no rows: `error`.
The probe counts in `request_count`. The table node is never queried.

### D5. Load control — Decision (values: Hypothesis)
Settings, validated at startup and listed in `.env.example`:
`NETSCANNER_SNMP_TIMEOUT` (default 3 s), `NETSCANNER_SNMP_RETRIES` (1),
`NETSCANNER_SNMP_MAX_REPETITIONS` (25, range 1–50),
`NETSCANNER_SNMP_MAX_ROWS` (200,000 per walk),
`NETSCANNER_SNMP_MAX_DEVICES` (8 concurrent devices). One `asyncio.Lock` per
device address serialises requests to that device; a global semaphore limits
devices. The mechanism is a decision; the numbers are initial lab values
(25 repetitions comes from one device) and are reviewed after the first real
run, with the result recorded in the evaluation.

### D6. Error categories — Decision
Short, fixed vocabulary stored in `snmp_queries.error_category`: `timeout`,
`error_status:<name>`, `decode_error`, `non_increasing_oid`, `row_limit`,
`transport_error`, and for SNMPv3 `v3_report:<counter>` (unknown user, wrong
digest, unsupported security level). Unlike SNMPv2c, SNMPv3 agents answer
wrong credentials with a report PDU, so that case can be named; for SNMPv2c
silence stays `no_response`. Exception texts are never stored. The store's
own categories follow the same style (`validation_error`, `database_error`,
`internal_error`); the earlier hyphenated names are replaced.

### D7. Credentials — Decision
`SnmpV2cCredential(community: SecretStr)` and
`SnmpV3Credential(user, level, auth_protocol, auth_key: SecretStr,
priv_protocol, priv_key: SecretStr)`. Allowed: SHA, SHA-224, SHA-256,
SHA-384, SHA-512; AES-128, AES-192, AES-256. Library credential objects are
built just before a request and not kept. Secret values are registered with
the existing log-masking filter while in use. PySNMP debug logging stays
off. Canary tests cover timeouts, error statuses, malformed responses and
v3 reports.

### D8. Read-only guarantee — Decision
The PySNMP module imports only the GET, GETNEXT and GETBULK command
functions. A test walks the AST of `netscanner.snmp` and fails if any
SET-related name is imported or referenced.

### D9. Lab layout and network — Decision
```
lab/
  README.md              origin, IP plan, limitations, pending hypotheses
  manifest.yaml          devices: label, origin, model, firmware, capture date,
                         management address, community file
  generate_synthetic.py  stdlib only, fixed seed, reads srx-01.snmprec
  snmpsim/
    Dockerfile           snmpsim in its own image, pinned versions, non-root
    requirements.txt     snmpsim and its dependencies, pinned with hashes
    data/srx-01.snmprec  real, anonymised (copied from the reviewed capture)
    data/lab-sw-01.snmprec, data/lab-sw-02.snmprec   synthetic
```
- `srx-01`: management address chosen by the generator among its own
  addresses in `ipAddrTable` (all already in 10.99.0.0/24).
- Origins in the manifest: `real-anonymised`, `synthetic` and, per value
  set, `derived-from: <device>` (for example the host MAC addresses and IP
  addresses that the switches take from `srx-01`).
- `lab-sw-01` (synthetic, Juniper-like `sysObjectID`, `sysDescr` containing
  "synthetic lab device"): LLDP with `lab-sw-02` (the neighbour advertises a
  management address), a neighbour advertising an address in 203.0.113.0/24,
  `dot1qTpFdbTable` with FDB ids mapped to VLANs through `dot1qVlanFdbId`,
  `dot1dBasePortIfIndex`, `self` and `mgmt` entries, about 30 host MAC
  addresses taken from `srx-01`'s IP-MAC table on access ports, and
  `srx-01`'s MAC on the uplink.
- `lab-sw-02` (synthetic, Fortinet-like `sysObjectID`, marked synthetic): no
  LLDP-MIB, no `ifXTable` (32-bit counters only), `dot1dTpFdbTable`, a few
  hosts, and an empty but supported `ipNetToPhysicalTable`.
- One address in the lab range where nothing answers.
- Compose override file `docker-compose.lab.yml`: one snmpsim container per
  device on network `netscanner-lab` (10.99.0.0/24, internal, dynamic
  addresses limited to 10.99.0.240/28) with a fixed address, and the
  collector attached to that network. Used as
  `docker compose -f docker-compose.yml -f docker-compose.lab.yml up`.
  Alternatives: a Compose profile (discarded because Compose cannot attach a
  network to a service only under a profile, so every stack would create the
  lab subnet and two stacks on one machine would overlap), or a second
  collector service inside a profile (discarded because two collectors would
  run). Lab community `netscanner-lab` (placeholder in `.env.example`,
  accepted only by lab data).
Using real vendor `sysObjectID` values in synthetic data is accepted because
`sysDescr` and the manifest mark them as synthetic.

### D10. Lab in tests — Decision
A pytest fixture starts snmpsim with `lab/snmpsim/data` on a free local port;
each device is selected by community (the data file name). snmpsim runs from
its own pinned tool environment (it depends on PySNMP and must not constrain
the project's version), and drops privileges when started as root. Tests
that need snmpsim are marked `lab` and skipped with a notice when it is not
available, except in CI where they are required (as with the database).

### D11. Scripted test agent — Decision
A test helper (`backend/tests/snmp_agent.py`), not production code: an asyncio
UDP server built on PySNMP's message encoders, answering SNMPv2c GET,
GETNEXT and GETBULK from a dict, with `noSuchObject` for OIDs outside every
known object type and `noSuchInstance` inside one. Behaviours per test:
delay, stop answering after N responses, error status, non-increasing OID,
garbage datagram. Alternative: a snmpsim variation module; discarded because
it cannot produce `noSuchObject` either and is harder to control per test.

### D12. Netmask rule in the confidentiality check — Decision
In files matching `lab/**/*.snmprec`, a line whose OID starts with
`1.3.6.1.2.1.4.20.1.3.` and whose value parses as a contiguous IPv4 netmask
is not reported. Nothing else changes; no global "looks like a mask" rule.

### D13. Vendor notes — Decision
`docs/vendors/juniper-srx1500.md` records the findings in the Context table
with model, firmware and capture date, scoped to that device, and the status
of H1–H6 for it (H4 and H5 confirmed for this model and firmware; H1 and H3
not testable with this capture; H2 pending; H6 not applicable).

### D14. Contract test suite — Decision
The client tests that do not depend on a specific library (outcomes,
completeness, columns reported, error categories, read-only surface) are
written once as a suite parameterised by implementation. The PySNMP client
runs it in CI; a Net-SNMP-based implementation written for the comparison
of D2 runs the same suite, which is part of the measured decision.

## Risks / Trade-offs

- [PySNMP API changes between versions] → pinned version, one wrapper
  module, measured decision (D2).
- [Synthetic switches could hide vendor behaviour] → marked synthetic,
  limitations documented; H1–H3 stay pending until a real switch is reachable.
- [snmpsim version conflicts with PySNMP] → separate tool environment and
  image (D9, D10).
- [srx-01's 427 IP-MAC entries make tests slower] → client tests use the
  tables they need; full walks only in a few integration tests.
- [The real switch is unreachable today] → the evaluation plan keeps a real
  run after `add-admin-authentication`; sistemas must fix the management path
  before then.

## Impact on data model and security

- Data model: migration `0003` adds the indicator `value_returned` to the
  check constraint of `snmp_queries.indicator` (D4); outcomes already exist,
  and the categories of D6 and the bridge MIB objects are added to the
  registries in code. The downgrade refuses to run while such rows exist.
- Security: read-only by construction, credentials in memory only, canary
  tests, no real network in tests, lab community only for lab data.
