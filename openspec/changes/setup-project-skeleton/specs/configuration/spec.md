# Spec Delta

## Purpose

Defines how settings and secrets reach the NetScanner services and how
missing or invalid configuration is handled, keeping secrets out of the
repository, the logs and the API.

## ADDED Requirements

### Requirement: Configuration from environment variables
Every service SHALL read its settings from environment variables with the
prefix `NETSCANNER_`, and the repository SHALL provide a `.env.example` that
lists every variable with a placeholder value and a comment, but no real
secret.

#### Scenario: Example file is complete
- **WHEN** a setting is added to the backend configuration
- **THEN** an automated test fails unless the variable appears in `.env.example`

#### Scenario: No real secrets committed
- **WHEN** the repository is checked
- **THEN** `.env` is ignored by Git and `.env.example` contains only placeholder values

### Requirement: Required secrets have no defaults
Required secrets (at least `NETSCANNER_SECRET_KEY` and the database password) SHALL
have no default value. A service SHALL refuse to start when one of them is
missing, empty or still set to the placeholder from `.env.example`.

#### Scenario: Missing secret
- **WHEN** the `api` or `collector` service starts without `NETSCANNER_SECRET_KEY`
- **THEN** the process exits with a non-zero code and a message naming the missing variable

#### Scenario: Placeholder secret
- **WHEN** a required secret still has the placeholder value from `.env.example`
- **THEN** the process refuses to start and says that the value must be changed

### Requirement: Secrets kept in separate settings
Each secret SHALL be its own setting. Secrets SHALL NOT be embedded in other
settings such as connection URLs, so that no non-secret value can carry a
secret into logs or error messages.

#### Scenario: Database connection settings
- **WHEN** the database connection is configured
- **THEN** host, port, database name, user and password are separate settings and the password is not part of any URL setting

### Requirement: Secrets never exposed (RNF-01 base)
Secret values SHALL NOT appear in standard output, standard error, log
records, API responses, HTTP error bodies or the text form of any object,
whatever the cause of the output. This SHALL be proven by tests that inject
known canary values as secrets and search all captured output for them;
using a masking type alone is not accepted as proof.

#### Scenario: Configuration printed or logged
- **WHEN** the loaded configuration object is converted to text or logged at startup
- **THEN** every secret field appears masked and the canary values do not appear

#### Scenario: Validation error
- **WHEN** a service starts with an invalid value for any setting, secret or not, while the secrets hold canary values
- **THEN** the error output names the invalid variable and the reason, does not echo the rejected input, and contains no canary value

#### Scenario: Database connection error
- **WHEN** a service cannot connect to the database because the host is unreachable or the password is wrong, with a canary value as password
- **THEN** the logged error and any API response describe the failure without the canary value, the connection string or a stack trace in the response body

#### Scenario: Unhandled exception in the API
- **WHEN** an unexpected exception occurs while the API handles a request
- **THEN** the client receives a generic 500 response without internal details, and the server log contains no canary value
