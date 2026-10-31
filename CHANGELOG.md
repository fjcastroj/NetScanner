# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
