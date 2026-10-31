# Design

## Context

Empty repository, one developer working on Windows with VS Code and Claude
Code, deployment target a single Linux server with Docker. The repository is
private now and must be public for the final delivery, so everything
committed from the first day, including history, must be publishable.
The next change (`add-data-provenance-model`) defines the data model and is
mandatory before any discovery code; this change only prepares the place
where it will live.

## Goals / Non-Goals

**Goals:**
- A stack that starts with one command, migrates its database, passes its
  health checks and recovers from a database restart.
- Component boundaries from RNF-07 visible in the layout from day one.
- Secrets and confidential network data kept out of the repository by
  automated checks, not by discipline alone.
- Every later change can add code with tests without touching tooling.

**Non-Goals:**
- Any network functionality, business tables or authentication.
- Production hardening beyond the defaults described here (TLS termination,
  backups and similar are documented as deployment notes later).

## Requirement coverage and priorities

| ID | Priority | Covered here |
|----|----------|--------------|
| RNF-07 | E | Separate services and processes |
| RNF-09 | E | Docker Compose deployment |
| RNF-10 | E | Test tooling, stack test and CI |
| RNF-11 | E | Licence, headers, README |
| RNF-01 | E | Base only: secret handling in configuration (credential storage comes later) |
| RNF-12 | D | Translation mechanism only (see D9) |

## Decisions

### D1. Monorepo with `backend/`, `frontend/`, `lab/`, `docs/`, `scripts/` — Decision
One repository keeps specs, code and lab data versioned together, which the
TFE traceability needs. Alternative: separate repositories per component;
discarded as overhead for one developer.

### D2. Backend layout: one Python package, several entry points — Decision
`backend/src/netscanner/` with `api/` (FastAPI app), `collector/` (SNMP
collector process), `core/` (configuration, logging, database session).
`api`, `collector` and the migration step are separate processes started from
the same image with different commands. Alternative: one package per
component; discarded because they share the data model and configuration,
and separate processes already satisfy RNF-07.

### D3. Python tooling: uv with `pyproject.toml` and lock file — Decision
Reproducible installs on Windows and in Docker, fast. Alternatives: pip with
requirements files (no proper lock), Poetry (slower, heavier). Ruff for lint
and formatting, pytest with pytest-asyncio.

### D4. Images and versions — Decision
- Backend: `python:3.12-slim`, with a non-root user created in the Dockerfile.
- Database: `postgres:17-alpine`.
- Frontend build: `node:22-alpine`.
- Web server: `nginxinc/nginx-unprivileged`, Alpine variant, pinned to the
  current stable `major.minor` tag at implementation time (the exact tag is
  recorded in the Dockerfile and the CHANGELOG). It runs as a non-root user
  and listens on 8080 inside the container, so no root or capability is
  needed. Alternative: the official `nginx` image with a custom user;
  discarded because it needs extra configuration to drop root.
- Health checks: `pg_isready` for `db`; a short Python `urllib` call for
  `api` (the slim image has no curl); `wget` from BusyBox for `web`.

### D5. Exposure — Decision
Only `web` publishes a port, bound by default to `127.0.0.1:8080` and
configurable through `NETSCANNER_WEB_BIND`. `db` and `api` stay inside the
Compose network. Rationale: least exposure by default; an administrator opens
it deliberately.

### D6. Configuration and secret handling — Decision
- Pydantic Settings with prefix `NETSCANNER_`. Each secret is its own
  `SecretStr` field; the database connection is built in code from separate
  host, port, name, user and password settings, so no URL setting ever holds
  the password.
- Required secrets have no default; a validator rejects empty values and the
  placeholder `change-me` used in `.env.example`.
- `SecretStr` is not treated as sufficient, because secrets leak through
  other paths. Additional measures:
  - `hide_input_in_errors=True` so validation errors do not echo inputs.
  - A startup wrapper catches validation errors and prints only variable
    names and error types, then exits with a non-zero code.
  - Database errors are logged as a short category ("connection refused",
    "authentication failed", "timeout") without the exception text, which
    can contain connection details.
  - A logging filter replaces the current secret values with `***` in every
    record, as a last line of defence.
  - FastAPI exception handlers return generic bodies for 500 and 503.
- Proof: tests set canary values (random strings) as secrets and capture
  stdout, stderr, log records and HTTP responses in four situations (normal
  startup, invalid setting, unreachable or wrongly authenticated database,
  unhandled exception in a request), asserting the canaries never appear.

### D7. Migrations in a one-shot `migrate` service — Decision
Alembic with an empty baseline revision. A `migrate` service runs
`alembic upgrade head` and exits; `api` and `collector` depend on it with
`condition: service_completed_successfully`, and `migrate` depends on `db`
being healthy. Alternatives: running migrations inside the `api` entrypoint
(couples API start-up with schema changes and leaves the collector racing
the schema); creating tables from the ORM (no evolution path). Both
discarded.

### D8. Collector placeholder — Decision
The collector process loads the configuration, checks the database
connection, logs that it is idle and stays alive, handling SIGTERM cleanly.
This proves the process boundary, the restart behaviour and the reconnection
logic before SNMP exists.

### D9. Frontend: React + TypeScript + Vite, react-i18next — Decision
Translation files in `frontend/src/locales/{es,en}.json`. Language detection
from the browser with Spanish as fallback, choice stored in localStorage.
A Vitest test checks that both files have the same keys. No UI component
library is chosen yet. RNF-12 is desirable, but only its mechanism is built
here: adding it now costs a few files, while retrofitting it after several
screens would mean rewriting every visible string. This is the exception the
delivery rules allow, not a reason to pull other desirable work forward.

### D10. Licence headers and check — Decision
Header text (adapted per comment syntax):

```
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Francisco Javier Castro Jiménez
Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
Computer Engineering, Universidad Internacional de La Rioja (UNIR).
```

A small script, `scripts/check_headers.py`, checks tracked files by extension
with an exclusion list for lock files and generated output. Alternative: an
external licence-header tool; discarded to avoid a dependency for a short
check.

### D11. Confidentiality safeguards — Decision
Three layers:
1. **Placement.** Raw data from the company network lives outside the
   repository (recommended `C:\desarrollos\NetScanner-private\`), so neither
   Git nor AI tools working on the repository folder see it.
2. **Ignore rules.** `.gitignore` excludes `.env`, `*.pcap`, `*.pcapng`,
   `*.walk`, `*.snmpwalk`, `*.sql`, `*.dump`, `*.log`, `private/`, `local/`
   and `.confidential-terms`.
3. **Automated checks** via the `pre-commit` framework, locally and in CI:
   - `scripts/check_confidentiality.py` implements the rules of the
     `data-confidentiality` spec:
     - IPv4: candidates are dotted quads not preceded or followed by a digit
       or a dot, so OIDs and versions are skipped; each candidate is parsed
       with `ipaddress` and checked against the allowed networks.
     - IPv6: candidates are tokens of hexadecimal groups separated by colons
       with either `::` or at least seven colons, parsed with `ipaddress`;
       tokens that are valid MAC addresses or times are skipped. Allowed
       multicast is an explicit list of groups, not the whole link-scope
       multicast range.
     - MAC: colon, hyphen and dotted (Cisco) notations, normalised before
       checking the documentation range, the locally administered bit and
       the fixed list of allowed protocol addresses.
     - Terms: a local, Git-ignored `.confidential-terms` (an example with
       fictitious terms is committed); matches are reported by file and
       line only, never by printing the term.
     - Exceptions: a committed `.confidentiality-allowlist.yaml` where each
       entry has `value`, `paths` and `reason`. No wildcard values, no
       whole-file exclusions. `paths` may use globs so that an entry still
       applies after `openspec archive` moves the spec (for example
       `openspec/**/data-confidentiality/spec.md`). Stale entries are
       reported. Initial entries: the CIDR notations of the forbidden
       private, unique local and link-local blocks named in the
       `data-confidentiality` spec, allowed in that spec and in
       `docs/confidentiality.md` only (this design refers to them without
       quoting them, so it needs no entry).
     - The check's own tests build forbidden values at run time, so they need
       no exceptions.
   - gitleaks for secret patterns.

Alternative: only a manual checklist; discarded because one slip in a public
history is costly to undo.

Hypothesis: the generic patterns will produce some false positives in later
changes (for example sample data in comments). Verification: run the check
on every change and add narrowly scoped allowlist entries with a reason.

### D12. Recovery after database loss — Decision
SQLAlchemy engine with `pool_pre_ping=True`, so stale connections are
replaced after a database restart; the health endpoint opens a short query
with a timeout and maps any failure to 503. The collector wraps its loop in
a reconnect routine with exponential backoff (1 s doubling up to 30 s) and
logs only the error category.

### D13. Automated stack test — Decision
`scripts/stack_test.py` (Python, so it runs on Windows and in CI) uses a
temporary `.env` with random secrets, a separate Compose project name and a
free host port (found by binding a socket to `127.0.0.1:0` and passed as
`NETSCANNER_WEB_BIND`), so it never collides with a stack already running,
then: `docker compose up -d --build --wait`, checks health through the web
port, checks `docker compose port` returns nothing for `db` and `api`, stops
`collector` and checks health, restarts `db` and waits for health to return
to 200, writes a marker row and checks it survives `down` / `up` without
`-v`, and finally runs `docker compose down -v` in a `finally` block. CI runs
it in its own job on the GitHub-hosted runner. The marker uses a throwaway
table created and dropped by the test, not a business table.

### D14. CI with GitHub Actions — Decision
One workflow with jobs: backend (uv sync, ruff, pytest with a PostgreSQL
service container), frontend (npm ci, eslint, vitest, build), checks (header
check, confidentiality check, gitleaks, `openspec validate --all --strict`)
and stack (the stack test).

## Risks / Trade-offs

- [Docker Desktop on Windows behaves differently from Linux, e.g. line
  endings and file permissions] → `.gitattributes` forces LF; images do not
  depend on host file permissions.
- [The confidentiality check cannot know every confidential term] → the
  local term list plus keeping raw data outside the repository; the check is
  a safety net, not the only control.
- [The stack test is slow] → it runs in its own CI job and locally on
  demand, not in the pre-commit hook.
- [A secret committed by mistake survives in history] → documented recovery
  procedure: rewrite history before publishing and rotate the credential.

## Impact on data model and security

- Data model: none yet (empty Alembic baseline). The provenance model is the
  next, mandatory change.
- Security: establishes secret handling (D6), minimal exposure (D5),
  non-root containers (D4) and confidentiality safeguards (D11) that later
  changes inherit.
