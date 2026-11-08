# Tasks

Implement and verify block by block. Never query the real network; all tests
use the lab or the scripted agent.

## 1. Lab data

- [x] 1.1 Copy `local/capturas-anonimizadas/srx-01.snmprec` (reviewed by the author) to `lab/snmpsim/data/srx-01.snmprec`; do not copy anything else from `local/`
- [x] 1.2 Add the netmask rule of design D12 to `scripts/check_confidentiality.py` with tests (mask in the netmask column of a lab file passes; same value in another column, another file type or outside `lab/` is reported; non-contiguous value in the netmask column is reported); the check must pass on the whole repository including `srx-01.snmprec`
- [x] 1.3 `lab/generate_synthetic.py` (stdlib only, fixed seed) producing `lab-sw-01.snmprec` and `lab-sw-02.snmprec` as in design D9, consistent with `srx-01`'s addresses and MAC addresses; a test checks that running it twice gives identical files and that the output passes the confidentiality check
- [x] 1.4 `lab/manifest.yaml` and `lab/README.md` (origin of each device and of derived value sets, IP plan, what each synthetic device models, that real data is a fixture of one model and firmware, limitations, pending hypotheses H1–H3 and H6 with reasons)
- [x] 1.5 `lab/snmpsim/Dockerfile` (pinned snmpsim and dependencies, non-root) and Compose override file `docker-compose.lab.yml` with one container per device on `netscanner-lab` (10.99.0.0/24); the lab community placeholder in `.env.example`
- [x] 1.6 Manual check documented in the PR: `docker compose -f docker-compose.yml -f docker-compose.lab.yml up`, a walk of each device from the collector container answers

## 2. Test infrastructure

- [x] 2.1 Pytest fixture that starts snmpsim with the lab data on a free local port from its own pinned tool environment, marked `lab`, skipped with a notice when unavailable and required in CI
- [x] 2.2 Scripted SNMP agent of design D11 with its behaviours, and tests of the agent itself

## 3. SNMP client

- [x] 3.1 Settings of design D5 with validation and `.env.example` entries
- [x] 3.2 Credential models of design D7 (v2c, v3 with allowed protocols only); tests rejecting SNMPv1, MD5 and DES without echoing secrets
- [x] 3.3 `SnmpClient` protocol, `Target`, `TableSpec` registry for iteration-1 tables (system, ifTable, ifXTable, ipAddrTable, ipAddressTable, ipNetToMediaTable, ipNetToPhysicalTable, entPhysicalTable columns, LLDP local and remote tables, dot1dBase, dot1dTpFdbTable, dot1qTpFdbTable, dot1qVlanCurrentTable) with probe columns, and result types of design D1
- [x] 3.4 PySNMP implementation (pinned version): GET, GETBULK walks per design D3, classification per design D4, error categories per design D6, per-device lock and global semaphore per design D5
- [x] 3.5 Read-only AST test of design D8
- [x] 3.6 Contract test suite of design D14, parameterised by implementation, run for the PySNMP client
- [x] 3.7 Tests against snmpsim: `ok` with row counts on `srx-01` tables, `empty` (supported but empty table), SNMPv3 authPriv query, columns-only walk, row limit giving `partial`
- [x] 3.8 Tests against the scripted agent: `not_available` (`noSuchObject`), ambiguous probe answer, `no_response`, `partial` after a mid-walk timeout with rows returned and `complete` false, non-increasing OID with and without rows, error status, garbage datagram leaving the process running, one request in flight per device, out-of-range settings refused
- [x] 3.9 Canary tests: community and v3 keys absent from logs, exception texts and results in every failure case
- [x] 3.10 Results contract tests: column missing in a complete walk reported absent; columns not reached in a partial walk not reported

## 4. Decision and documentation

- [x] 4.1 Minimal Net-SNMP-based implementation for the comparison only (not used by the application), run against the contract suite; measurement script and `docs/decisions/snmp-library.md` per design D2 (values equal to `snmpbulkwalk` on every `srx-01` table, outcome cases, walk times of `ifTable` and `ifXTable`, installation on Windows and in the container, decision and status)
- [x] 4.2 `docs/vendors/juniper-srx1500.md` per design D13, scoped to the model, firmware and capture date, distinguishing "not implemented" (`noSuchObject`) from "supported but empty in this capture" (`noSuchInstance`), and update `docs/vendors/README.md` with the status of H1–H6
- [x] 4.3 `CHANGELOG.md` entry
- [x] 4.4 Run the full suite on Linux against PostgreSQL and the lab, the hooks, the stack test and `openspec validate --strict`; all green
