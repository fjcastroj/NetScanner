# Spec Delta

## Purpose

Defines how NetScanner is packaged, started and health-checked on a single
server, and how its components are kept as separate processes.

## ADDED Requirements

### Requirement: RNF-09 Single-server deployment with Docker Compose
The system SHALL start on a single server with one Docker Compose command,
and SHALL NOT require installing any agent or software on the monitored
network devices.

#### Scenario: Clean start
- **WHEN** an administrator copies `.env.example` to `.env`, fills in the required secrets and runs `docker compose up`
- **THEN** the `db`, `api`, `collector` and `web` services start and report healthy
- **AND** the web interface is reachable in a browser on the configured host port

#### Scenario: Restart keeps data
- **WHEN** the stack is stopped and started again
- **THEN** the database content is preserved in a named volume

### Requirement: Database migrations before the services start
Database migrations SHALL run once, in a dedicated one-shot step, before the
API and the collector start. If the migrations fail, the API and the
collector SHALL NOT start.

#### Scenario: Fresh database
- **WHEN** the stack starts with an empty database
- **THEN** the migration step brings the schema to the latest revision and exits successfully before `api` and `collector` start

#### Scenario: Already migrated database
- **WHEN** the stack starts with a database already at the latest revision
- **THEN** the migration step makes no change and exits successfully

#### Scenario: Failed migration
- **WHEN** the migration step fails
- **THEN** `api` and `collector` are not started and the failure is visible in the migration step's logs

### Requirement: RNF-07 Independent components
The system SHALL run the web interface, the API, the SNMP collector and the
database as separate services, so that each one can be restarted or fail
without stopping the others.

#### Scenario: Collector failure does not stop the API
- **WHEN** the `collector` service stops or crashes
- **THEN** the `api` and `web` services keep answering requests

#### Scenario: API restart does not stop the collector
- **WHEN** the `api` service is restarted
- **THEN** the `collector` service keeps running

### Requirement: Recovery after a database outage
The API and the collector SHALL survive a temporary loss of the database and
resume normal operation when it returns, without being restarted.

#### Scenario: Database restarted
- **WHEN** the `db` service is restarted while the stack is running
- **THEN** the health endpoint answers 503 while the database is down and 200 again within 30 seconds of the database being healthy, without restarting `api`

#### Scenario: Collector waits for the database
- **WHEN** the database becomes unavailable while the collector is running
- **THEN** the collector logs the loss of connection, retries with increasing delays and continues once the database is back

### Requirement: Health endpoint
The API SHALL expose an unauthenticated health endpoint that reports whether
the API is running and whether the database is reachable, without revealing
versions, hostnames, connection strings or secrets.

#### Scenario: Database reachable
- **WHEN** a client requests `GET /api/health` and the database is reachable
- **THEN** the response status is 200 with `{"status": "ok", "database": "ok"}`

#### Scenario: Database unreachable
- **WHEN** a client requests `GET /api/health` and the database is not reachable
- **THEN** the response status is 503 with `{"status": "degraded", "database": "unavailable"}`
- **AND** the body contains no connection string, host name or error trace

### Requirement: Minimal network exposure
The default deployment SHALL publish only the web interface port on the
host. The database and the API SHALL be reachable only inside the Compose
network, and every container SHALL run as a non-root user.

#### Scenario: Database and API not published
- **WHEN** the stack runs with the default configuration
- **THEN** no host port is mapped to the `db` or `api` services

#### Scenario: API reached through the web service
- **WHEN** the browser requests a path under `/api/` on the web port
- **THEN** the web service forwards the request to the `api` service

### Requirement: Automated stack test
The repository SHALL include an automated test that builds and starts the
whole stack with throwaway secrets and verifies the deployment requirements
above, and that runs both locally and in CI.

#### Scenario: Stack test passes
- **WHEN** the stack test runs on a machine with Docker
- **THEN** it checks that all services become healthy, health answers 200 through the web port, `db` and `api` have no host ports, stopping `collector` leaves health at 200, restarting `db` recovers health to 200, and restarting the stack keeps data
- **AND** it removes the stack and its volumes when it finishes, even if a check fails
