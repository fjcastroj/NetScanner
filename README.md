# NetScanner

NetScanner was developed as part of the Final Degree Project (TFE) of the
Bachelor's Degree in Computer Engineering at the Universidad Internacional de
La Rioja (UNIR).

NetScanner is a self-hosted web application for SNMP-based discovery,
inventory, topology and basic monitoring of enterprise networks, plus traffic
analysis with sFlow v5. It records where every piece of data came from (which
device, MIB table or protocol), when it was obtained and whether it was
observed directly or inferred, so inferences are never presented as facts.
Nothing is installed on the monitored devices.

> **Status:** project skeleton. The stack starts, migrates its (still empty)
> database and reports its health; discovery and monitoring come in later
> changes (see `openspec/`).

## Components

| Service     | What it does                                                    |
|-------------|-----------------------------------------------------------------|
| `web`       | React interface (Spanish and English) served by nginx; proxies `/api` |
| `api`       | FastAPI backend (`GET /api/health`)                             |
| `collector` | SNMP collector process (idle placeholder for now)               |
| `migrate`   | One-shot step that runs the database migrations                 |
| `db`        | PostgreSQL                                                      |

Code lives in `backend/` (Python package `netscanner`), `frontend/`,
`scripts/` (repository checks and the stack test) and `docs/`. Specifications
and design decisions are in `openspec/`.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker
  Engine with the Compose plugin) to run the stack.
- For development: Python 3.12+, [uv](https://docs.astral.sh/uv/) and
  Node.js 22.

## Quick start

```sh
cp .env.example .env
# Edit .env: replace every "change-me" with a strong random value, e.g.
#   python -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose up -d --build --wait
```

Open <http://127.0.0.1:8080>. Only the web interface is published, on
`127.0.0.1:8080` by default; change `NETSCANNER_WEB_BIND` in `.env` to expose
it deliberately. The services refuse to start while a required secret is
missing or still `change-me`. Data is kept in the `db-data` volume across
restarts; `docker compose down -v` deletes it.

## Development

Backend:

```sh
cd backend
uv sync
uv run ruff check .. && uv run ruff format --check ..
uv run pytest                 # database tests are skipped without a server
uv run pytest ../scripts/tests
```

The database tests run when a PostgreSQL server is given through
`NETSCANNER_TEST_DB_HOST`, `NETSCANNER_TEST_DB_PORT`, `NETSCANNER_TEST_DB_NAME`,
`NETSCANNER_TEST_DB_USER` and `NETSCANNER_TEST_DB_PASSWORD`, for example a
throwaway container:

```sh
docker run -d --rm --name netscanner-test-db -p 127.0.0.1:55432:5432 \
  -e POSTGRES_USER=netscanner -e POSTGRES_DB=netscanner \
  -e POSTGRES_PASSWORD=<random> postgres:17-alpine
```

Frontend:

```sh
cd frontend
npm ci
npm run lint && npm test && npm run build
npm run dev                   # proxies /api to http://127.0.0.1:8000
```

### Stack test

Builds and runs the whole stack with throwaway secrets, its own Compose
project name and a free host port, checks health, exposure, non-root
containers, recovery after a database outage and data persistence, and
removes everything at the end:

```sh
python scripts/stack_test.py
```

### Repository checks

The repository will be public and NetScanner is tested on a real network, so
no confidential data may ever be committed. Read
[docs/confidentiality.md](docs/confidentiality.md) first, then install the
hooks once:

```sh
pip install pre-commit        # or: uv tool install pre-commit
pre-commit install
```

The hooks run the confidentiality check, the licence header check, gitleaks
and Ruff on every commit. Never bypass them with `--no-verify`. CI runs the
same checks plus all test suites, the stack test and
`openspec validate --all --strict`.

## Licence

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
Every source file carries an SPDX header with the authorship statement.
