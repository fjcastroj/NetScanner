# Tasks

Implement and verify block by block: do not start a block until the tests of
the previous one pass.

## 1. Repository base and confidentiality safeguards (first commit)

- [x] 1.1 Add `.gitattributes` (LF for text files), `.editorconfig` and `.gitignore` including `.env`, `*.pcap`, `*.pcapng`, `*.walk`, `*.snmpwalk`, `*.sql`, `*.dump`, `*.log`, `private/`, `local/`, `.confidential-terms`
- [x] 1.2 Add `LICENSE` (Apache License 2.0 full text) and `NOTICE` (author and UNIR TFE statement)
- [x] 1.3 Write `scripts/check_confidentiality.py` implementing the IPv4, IPv6, MAC, term and allowlist rules of design D11, plus `.confidential-terms.example` (fictitious terms) and `.confidentiality-allowlist.yaml` with the initial entries
- [x] 1.4 Tests for the confidentiality check, building forbidden values at run time: each spec scenario of `data-confidentiality` (private and public IPv4, lab and documentation IPv4, OIDs and versions, ULA, global and link-local IPv6, times and MACs not taken as IPv6, globally administered MAC, allowed MACs in all notations, term reported without printing it, missing term list, allowlisted CIDR in its file only, stale allowlist entry)
- [x] 1.5 Write `scripts/check_headers.py` with its exclusion list, and tests (missing header reported, excluded files skipped)
- [x] 1.6 Add `.pre-commit-config.yaml` running the confidentiality check, the header check, gitleaks and Ruff
- [x] 1.7 Add `docs/confidentiality.md`: raw data outside the repo, anonymisation before any data enters it, raw data never given to AI tools, leak recovery procedure
- [x] 1.8 Run the confidentiality and header checks over the whole repository, including `openspec/`; both pass

## 2. Configuration

- [x] 2.1 Create `backend/pyproject.toml` (uv, Python 3.12+), Ruff and pytest configuration
- [x] 2.2 Implement settings with Pydantic Settings: `NETSCANNER_` prefix, separate `SecretStr` fields, database connection built from separate settings, no defaults for required secrets, rejection of empty values and `change-me`, `hide_input_in_errors=True`
- [x] 2.3 Startup wrapper that reports invalid configuration by variable name and error type only, and a logging filter that masks current secret values
- [x] 2.4 Add `.env.example` with every variable, placeholders and comments
- [x] 2.5 Tests: missing secret names the variable, placeholder rejected, every settings field present in `.env.example`, and canary tests (design D6) for configuration printed or logged and for an invalid setting

## 3. Backend skeleton

- [x] 3.1 Create the package layout `backend/src/netscanner/{core,api,collector}` with source headers
- [x] 3.2 Database session (SQLAlchemy async, asyncpg, `pool_pre_ping=True`) and Alembic with an empty baseline revision
- [x] 3.3 FastAPI app with `GET /api/health` (200 ok / 503 degraded) and generic exception handlers for 500 and 503
- [x] 3.4 Collector process: load settings, connect with backoff (1 s doubling to 30 s), log idle state and connection loss by category, exit cleanly on SIGTERM
- [x] 3.5 Tests: health 200 with database reachable, 503 without details when unreachable, recovery to 200 after the database returns, collector starts and stops cleanly, and canary tests for database connection errors (unreachable host, wrong password) and an unhandled exception in a request

## 4. Frontend skeleton

- [x] 4.1 Create the Vite + React + TypeScript project in `frontend/` with ESLint and Vitest, headers in source files
- [x] 4.2 Configure react-i18next with `es.json` and `en.json`, browser detection, Spanish fallback, choice stored in localStorage
- [x] 4.3 Application shell: name, empty navigation area, language selector, API status indicator using `/api/health`
- [x] 4.4 Tests: both locale files have the same keys, language switch changes visible text, status indicator shows available and unavailable states

## 5. Containers and Compose

- [x] 5.1 Backend Dockerfile (python:3.12-slim, uv, non-root user) used by `migrate`, `api` and `collector` with different commands
- [x] 5.2 Frontend Dockerfile (node:22-alpine build, `nginxinc/nginx-unprivileged` Alpine pinned to the current stable minor tag, recorded in the CHANGELOG) with `/api` proxied to `api`
- [x] 5.3 `docker-compose.yml` with `db`, `migrate`, `api`, `collector`, `web`; health checks from design D4; `migrate` after healthy `db`; `api` and `collector` after successful `migrate`; named volume for PostgreSQL; only `web` published on `${NETSCANNER_WEB_BIND:-127.0.0.1:8080}`
- [x] 5.4 Write `scripts/stack_test.py` as in design D13 and run it locally until it passes

## 6. CI and documentation

- [x] 6.1 GitHub Actions workflow with the backend, frontend, checks and stack jobs from design D14
- [x] 6.2 `README.md`: UNIR TFE statement, purpose, prerequisites (Docker Desktop, Python 3.12+, uv, Node.js 22), quick start, how to run tests, the stack test and `pre-commit install`
- [x] 6.3 `CHANGELOG.md` (Keep a Changelog format) with an Unreleased entry for this change, including the pinned nginx tag
- [x] 6.4 Run the full test suite, the pre-commit hooks on all files, the stack test and `openspec validate --strict`; all green
