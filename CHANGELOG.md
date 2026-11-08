# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Read-only SNMP client (`add-snmp-client-and-lab`, RF-06, RNF-01, RNF-02,
  RNF-04, RNF-06): package `netscanner.snmp` with a project-owned client
  interface and a PySNMP 7.1.32 implementation. It uses GET and GETBULK
  only, supports SNMPv2c and SNMPv3 (SHA-family authentication, AES
  privacy) and refuses SNMPv1, MD5 and DES.
- Table walks classified by a column probe, never the table node: `ok`,
  `empty`, `not_available`, `partial`, `no_response` and `error`, with the
  indicator and a fixed vocabulary of error categories (timeouts, error
  statuses, SNMPv3 reports, non-increasing OIDs, row limit). Migration
  `0003` adds the indicator `value_returned`.
- Load limits: one request in flight per device, a global device limit,
  max-repetitions 25 (at most 50), timeout, retries and a row limit, set
  through `NETSCANNER_SNMP_*` settings. Credentials are held in memory only,
  masked in logs while in use, and proven absent by canary tests.
- SNMP lab (`lab/`):
  - the real, anonymised `srx-01` (Juniper SRX1500, JUNOS 19.4R3.11) and two
    synthetic switches generated reproducibly from it;
  - a manifest of origins and a README of limitations and pending
    hypotheses;
  - a pinned snmpsim image, and `docker-compose.lab.yml` putting each
    device on its own address in 10.99.0.0/24;
  - a pytest fixture, and a scripted SNMP agent for what snmpsim cannot
    reproduce.
- Library decision `docs/decisions/snmp-library.md`, measured against
  Net-SNMP. Vendor note `docs/vendors/juniper-srx1500.md`, with the status of
  hypotheses H1 to H6.
- Confidentiality check: contiguous netmasks allowed only in the
  `ipAdEntNetMask` column of lab data files.
- Data provenance model (`add-data-provenance-model`, RF-28, RF-06 storage,
  RF-29, RF-30, OE1, OE6): migration `0002` with collection runs, SNMP query
  records, devices, identity resolutions and conflicts, devices reached per
  run, device addresses, interfaces, LLDP/CDP neighbour entries, IP-MAC
  entries and evaluation snapshots.
- Every stored datum points to the query that first produced it and the one
  that last confirmed it, per group of fields, and is observed or inferred.
  Inferred data carries its method and evidence with snapshots; database
  constraints and composite foreign keys reject data without a source, from
  another device's query or inferred without evidence.
- Order-independent upsert rules (first and last seen moved with their
  queries, confirmed absence versus not retrieved, carried fields), per-row
  validation with rejected counts, and query outcomes `ok`, `empty`,
  `not_available`, `no_response`, `partial` and `error` with their
  indicators or error categories.
- Device identity by LLDP chassis id or address recorded as an inferred
  resolution; contradictions recorded as conflicts without merging devices.
  Vendor name inferred from the enterprise number (generic agents and
  unknown numbers stay unknown); model from ENTITY-MIB or inferred from
  `sysDescr` fragments.
- Reads with origin, source, method, age, staleness and presence; setting
  `NETSCANNER_STALE_AFTER` (default `P7D`). Stale data is never deleted.
- Run reports and evaluation snapshots taken at `REPEATABLE READ` under an
  advisory lock when a run closes.
- Data minimisation: no `sysContact`, `sysLocation`, serial numbers or
  secrets stored, proven by canary tests. `docs/provenance.md` and
  `docs/vendors/README.md` (template and pending hypotheses H1 to H3).

- Project skeleton (`setup-project-skeleton`): monorepo with `backend/`,
  `frontend/`, `scripts/` and `docs/`.
- Docker Compose deployment with `db` (`postgres:17-alpine`), a one-shot
  `migrate` step, `api`, `collector` and `web`; health checks, non-root
  containers, only `web` published (default `127.0.0.1:8080`, configurable
  with `NETSCANNER_WEB_BIND`), data in a named volume.
- Web image based on `nginxinc/nginx-unprivileged:1.30-alpine` (current
  stable nginx minor at the time of this change), proxying `/api` to `api`.
- Backend (Python 3.12, FastAPI): `GET /api/health` answering 200
  `{"status": "ok", "database": "ok"}` or 503
  `{"status": "degraded", "database": "unavailable"}`, recovery after a
  database restart, generic 500/503 error bodies.
- Collector placeholder that connects to the database, idles, reconnects with
  exponential backoff (1 s to 30 s) and stops cleanly on SIGTERM.
- Alembic with an empty baseline revision.
- Configuration through `NETSCANNER_*` environment variables and
  `.env.example`; required secrets have no default and the services refuse
  to start when they are missing, empty or still `change-me`. Secrets are
  masked in logs and never echoed in validation or database errors, proven
  by canary tests.
- Web interface shell (React, TypeScript, Vite) with application name,
  navigation area, API status indicator and Spanish/English translations
  (browser language detection, Spanish fallback, choice remembered).
- Confidentiality safeguards: `scripts/check_confidentiality.py` (IPv4,
  IPv6, MAC addresses, local confidential terms, narrow allowlist),
  gitleaks, ignore rules for raw network data and
  `docs/confidentiality.md`.
- Apache License 2.0 (`LICENSE`, `NOTICE`), SPDX headers with the UNIR TFE
  statement and `scripts/check_headers.py`.
- Pre-commit hooks, automated stack test (`scripts/stack_test.py`) and a
  GitHub Actions workflow running linting, tests, repository checks, the
  stack test and `openspec validate --all --strict`.
