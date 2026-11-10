# Spec Delta

## Purpose

Defines the HTTP API used by the web interface for configuration, discovery
runs and the basic inventory.

## ADDED Requirements

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

### Requirement: Lab mode until authentication
Until authentication exists, the application SHALL operate only in lab mode: it SHALL accept only lab ranges, as required by the scope's lab-only guard, and its status endpoint SHALL report lab mode without authentication. The recommended deployment binds the web service to the local host; this is a deployment recommendation, not a guarantee of the application.

#### Scenario: Lab mode reported
- **WHEN** the status endpoint is read
- **THEN** it reports that the application is in lab mode without authentication

#### Scenario: Deployment bound to another address
- **WHEN** the operator binds the web service to an address other than the local host
- **THEN** the application still accepts only lab ranges
