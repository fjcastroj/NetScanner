# Proposal

## Why

The persistence layer is ready, but nothing talks to devices yet. Discovery
(next change) needs an SNMP client that is read-only, distinguishes every
query outcome reliably (RF-06), limits its load on production devices
(RNF-06) and never leaks credentials (RNF-01). It also needs a reproducible
lab, because access to the company network is limited: development and
tests must run without it, and the real network is used only for the final
evaluation.

The capture of one real device (a Juniper SRX1500 firewall, anonymised) on
2026-11-03 gave evidence that shapes this change:
- the device distinguishes `noSuchObject` from `noSuchInstance` when a
  column OID without index is queried (H4 confirmed for this model);
- a GET on a table node returns `noSuchObject` even for supported tables, so
  that answer must never be used to classify a table;
- GETBULK with 25 repetitions is about 3x faster than GETNEXT on a 5,698-row
  walk, and 50 repetitions adds only about 16%; no errors up to 50 (H5);
- snmpsim answers `noSuchInstance` for everything that does not exist, so it
  cannot reproduce `noSuchObject`.

## What Changes

- A project-owned SNMP client interface with a PySNMP implementation:
  GET, GETNEXT and GETBULK only, SNMPv2c and SNMPv3, timeouts, retries,
  max-repetitions, row limits and concurrency limits.
- Outcome classification for table walks based on probing a column, never
  the table node, with the indicator recorded for auditing.
- Credentials handled in memory only and proven absent from logs and errors.
- A lab with one real anonymised device (`srx-01`) and synthetic switches
  that complete a small network, all served by snmpsim through a Compose
  override file, and documented as real or synthetic.
- A small scripted SNMP test agent that reproduces what snmpsim cannot
  (`noSuchObject`, timeouts mid-walk, error statuses, non-increasing OIDs,
  malformed responses).
- A measured comparison of PySNMP with Net-SNMP on the lab, recorded as the
  library decision.
- A contextual exception in the confidentiality check for netmask values in
  lab data.

## Requirements covered

- RF-06 [E] outcome detection (the storage side was done in
  `add-data-provenance-model`).
- RNF-01 [E] SNMP credentials never exposed (client side; encrypted storage
  comes with `add-credentials-and-scope`).
- RNF-02 [E] read-only SNMP.
- RNF-04 [E] malformed responses never crash the process.
- RNF-06 [E] bounded number and rate of queries, GETBULK where possible.
- RNF-10 [E] automated tests with simulated data.

## Capabilities

### New Capabilities

- `snmp-client`: how NetScanner queries devices and classifies each outcome.
- `snmp-lab`: the simulated network used by development, tests and part of
  the evaluation, and the rules for adding devices to it.

### Modified Capabilities

- `data-confidentiality`: netmask values allowed only in the netmask column
  of lab data files.

## Out of Scope

- Discovery logic, MIB-specific parsers and the mapping of results to the
  store (`add-device-discovery`).
- Scope checks before querying an address (RNF-03) and encrypted credential
  storage (`add-credentials-and-scope`).
- Interface counter polling (`add-interface-polling`).
- Captures of more real devices: the real network is used again only when
  the application can run end to end, after `add-admin-authentication`.

## Impact

- New `netscanner.snmp` package and `pysnmp` dependency (exact version pinned
  in the lock file).
- New `lab/` content: snmpsim data, a synthetic data generator, a manifest,
  a README, and a Compose override file `docker-compose.lab.yml`.
- New test helper: scripted SNMP agent under `backend/tests/`.
- `scripts/check_confidentiality.py`: one contextual rule.
