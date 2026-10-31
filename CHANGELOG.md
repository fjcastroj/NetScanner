# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
