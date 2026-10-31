# Proposal

## Why

The repository is empty. Before any discovery or monitoring feature can be
built, the project needs a runnable foundation: the component layout from
RNF-07, single-server deployment with Docker Compose (RNF-09), configuration
that keeps secrets out of the repository, the open-licence and authorship
conventions required by UNIR (RNF-11), the multilingual base of the web UI
(RNF-12) and a test and CI setup (RNF-10). Doing this first keeps every later
change small and testable.

## What Changes

- Monorepo layout with `backend/`, `frontend/`, `lab/` and `docs/`.
- Backend skeleton (Python, FastAPI) with a health endpoint that reports API
  and database status, plus an SNMP collector process that starts, connects
  to the database and idles until later changes give it work.
- Frontend skeleton (React, TypeScript, Vite) with Spanish and English from
  the first screen, served by a web container that proxies `/api` to the API.
- Docker Compose stack: `db` (PostgreSQL), a one-shot `migrate` step,
  `api`, `collector` and `web`, with recovery after a database restart and
  an automated stack test.
- Configuration through environment variables only, with `.env.example`;
  the services refuse to start if a required secret is missing.
- Apache License 2.0 (`LICENSE`, `NOTICE`), SPDX headers with the UNIR TFE
  statement in every source file, and an automated check for them.
- `README.md`, `CHANGELOG.md`, `.gitignore`, `.gitattributes`,
  `.editorconfig`.
- Confidentiality safeguards from the first commit: the repository will be
  public and tests use a company network, so a pre-commit hook and CI check
  reject private addresses, real MAC addresses, secrets and terms from a
  local (ignored) list; raw data lives outside the repository.
- Test tooling (pytest, Vitest) and a GitHub Actions workflow that runs
  linting, tests, the header and confidentiality checks and
  `openspec validate --strict`.

## Requirements covered

RNF-07 [E], RNF-09 [E], RNF-10 [E], RNF-11 [E], RNF-01 [E] (configuration
base only) and RNF-12 [D] (translation mechanism only, justified in
design D9). No functional requirement is implemented.

## Capabilities

### New Capabilities

- `deployment`: how NetScanner is packaged, started and health-checked on a
  single server, and how its components are separated (RNF-07, RNF-09).
- `configuration`: how settings and secrets reach the services and how
  missing or invalid configuration is handled (RNF-01, partially).
- `repository-conventions`: licence, authorship headers, documentation and
  automated checks that every contribution must satisfy (RNF-10, RNF-11).
- `web-ui`: the web interface shell and its language support (RNF-12).
- `data-confidentiality`: safeguards that keep confidential information from
  the company test network out of the repository and its history.

### Modified Capabilities

None (first change).

## Out of Scope

- Business tables: the provenance data model is the next change,
  `add-data-provenance-model`, and it is mandatory before any discovery
  code.
- Migrations beyond an empty baseline, SNMP access, credentials,
  discovery and authentication: each has its own later change.
- The sFlow collector service: added in iteration 4.
- Topology and chart libraries: open decisions for later iterations.
- Making the GitHub repository public: required before the final delivery,
  not by this change.

## Impact

- New code in every top-level folder; no existing code is affected.
- New dependencies: FastAPI, Uvicorn, Pydantic Settings, SQLAlchemy, asyncpg,
  Alembic, pytest, Ruff (backend); React, Vite, TypeScript, react-i18next,
  Vitest, ESLint (frontend); PostgreSQL and Nginx container images.
- Developer prerequisites: Docker Desktop, Python 3.12+, uv, Node.js 22.
