# inventory-api Specification

## Purpose

Defines the HTTP API used by the web interface for configuration, discovery
runs and the basic inventory.
## Requirements
### Requirement: Configuration endpoints
The API SHALL provide endpoints to read and save the discovery settings and to read the credential's non-secret description and replace the credential, validating all input and never returning a secret.

#### Scenario: Invalid settings
- **WHEN** settings with a malformed range, a seed outside the scope or a depth out of range are sent
- **THEN** the API answers 422 with the field and reason, without echoing secret values

### Requirement: Run endpoints
The API SHALL provide endpoints to start a discovery run, list runs, and read one run with its status, timing, progress counts computed from stored records and, when finished, its report.

#### Scenario: Following a run
- **WHEN** the client reads a running run
- **THEN** it receives the status and the counts of devices reached, candidates skipped per reason and queries sent so far

### Requirement: RF-11 Inventory endpoints
The API SHALL provide a device list with name, management address, vendor, model, software version, interface count and first and last seen, and a device detail with its attribute groups, addresses and interfaces, each value with its origin, method, source, age and staleness.

#### Scenario: Device list
- **WHEN** the device list is requested after the lab run
- **THEN** it returns the three lab devices with their summary fields and staleness

#### Scenario: Inferred value in the detail
- **WHEN** the detail of `srx-01` is requested
- **THEN** its model is returned as inferred with its method and its evidence fragments, and its interfaces as observed with their source table and age

### Requirement: Status reports authentication
The status endpoint SHALL report that authentication is enabled and whether an administrator account exists, and SHALL NOT reveal the user name or any session detail.

#### Scenario: Status without session
- **WHEN** the status endpoint is read without a session
- **THEN** it answers 200 with `authentication: true` and whether an administrator exists, and nothing else about the account

