# Spec Delta

## Purpose

Defines how a discovery run proceeds from its seeds through the authorised
scope, what it collects from each device and what it records, including
why a candidate was not queried.

## ADDED Requirements

### Requirement: RF-02 Discovery settings
The system SHALL let the administrator configure seeds, allowed and excluded ranges, maximum depth, whether IP-MAC entries produce candidates (off by default), and the operational limits, validated when saved and copied into the parameters of each run.

#### Scenario: Valid settings
- **WHEN** the administrator saves seeds and ranges that satisfy the scope rules and a depth within the server's ceiling
- **THEN** the settings are stored and the next run copies them into its parameters

### Requirement: Runs executed by the collector
Discovery runs SHALL be created by the API as pending and executed by the collector, one at a time; a run requested while another is pending or running SHALL be refused.

#### Scenario: Second run requested
- **WHEN** a run is requested while another is running
- **THEN** the request is refused with a message saying a run is already in progress

#### Scenario: Collector restarted mid-run
- **WHEN** the collector restarts during a run
- **THEN** that run is marked interrupted and the next pending run can start

### Requirement: RF-03 RF-04 Collection per device
For each authorised candidate that answers, the system SHALL read the system group, `ifTable`, `ifXTable`, the device's address table, ENTITY-MIB model columns, LLDP local data, local ports, remote table and management addresses, the CDP cache, and the IP-MAC tables, recording every query with its outcome and storing results through the store's contract.

#### Scenario: Device in the lab
- **WHEN** `srx-01` is discovered from its seed
- **THEN** its 259 interfaces, its addresses and its IP-MAC entries are stored, and each query is recorded with its outcome

#### Scenario: Table not implemented
- **WHEN** a device answers `noSuchObject` to the probe of `entPhysicalTable`, as the scripted agent does
- **THEN** the query is recorded as `not_available`, the model is inferred from `sysDescr`, and discovery of that device continues

#### Scenario: Partial walk
- **WHEN** a walk of `ifXTable` ends as `partial`
- **THEN** only the received columns are stored, as not retrieved for the rest, and no interface is considered absent because of that walk

#### Scenario: IP-MAC fallback
- **WHEN** `ipNetToPhysicalTable` is `not_available` or `empty`, as in `lab-sw-02`
- **THEN** `ipNetToMediaTable` is read as well and its entries record that table as their source

### Requirement: Identification and model
The system SHALL resolve each answering device's identity with the store's identity rules, using the LLDP chassis identifier when present, and SHALL infer the model from `sysDescr` only when ENTITY-MIB provides none.

#### Scenario: Device reached twice through different addresses
- **WHEN** a device is reached as a seed and another of its addresses, already read from its address table, is advertised by a neighbour
- **THEN** it is stored once and the second address is recorded with reason `already_known`, not queried

### Requirement: RF-05 Candidates and depth
The system SHALL take candidates from LLDP and CDP management addresses and, if enabled, from IP-MAC entries, SHALL query each only once per run, and SHALL not query candidates beyond the maximum depth from the seeds.

#### Scenario: Neighbour within depth
- **WHEN** `lab-sw-01` is a seed (depth 0), advertises 10.99.0.3 over LLDP and the maximum depth is 1
- **THEN** `lab-sw-02` is queried at depth 1

#### Scenario: Beyond the maximum depth
- **WHEN** the same run has maximum depth 0
- **THEN** 10.99.0.3 is recorded with reason `max_depth` and not queried

#### Scenario: Own address learned from IP-MAC
- **WHEN** IP-MAC candidates are enabled and `srx-01`'s IP-MAC table contains one of `srx-01`'s own addresses
- **THEN** that address is recorded with reason `already_known` and not queried

### Requirement: Reason for every candidate not queried
Every candidate recorded in a run SHALL have, in the run's device records, how it was found and either the device it led to or exactly one reason: `out_of_scope`, `excluded`, `special_address`, `already_known`, `max_depth` or `limit_reached` when it was not queried; `no_response` when every attempt timed out; `auth_failed` when an SNMPv3 report rejected the credential; `query_error` when the system group answer was an error status, could not be decoded or the client failed; with the technical detail kept only in the query record.

#### Scenario: Error answer to the system group
- **WHEN** a device answers the system group query with an error status
- **THEN** the candidate is recorded with reason `query_error`, the query keeps the error category, and the run continues

#### Scenario: Run summary
- **WHEN** a run in the lab finishes
- **THEN** its report lists devices discovered, new devices, and the count of candidates per reason, all computed from stored records

### Requirement: End-to-end discovery of the lab
A discovery run over the lab with seeds `srx-01`, `lab-sw-01` and the silent address 10.99.0.9, the lab range allowed and maximum depth 1, SHALL discover `srx-01` and `lab-sw-01` as seeds and `lab-sw-02` through LLDP, record 203.0.113.10 as `out_of_scope` and 10.99.0.9 as `no_response`, and finish as completed.

#### Scenario: Lab run in tests
- **WHEN** the end-to-end test runs this discovery against the lab simulated in the test process
- **THEN** the three devices are stored with their interfaces and provenance, and the run report matches the lab manifest

#### Scenario: Lab run in Compose
- **WHEN** the stack test starts the stack with the lab override file `docker-compose.lab.yml`, saves these settings and starts a run through the API
- **THEN** the run finishes as completed and the device list returns the three lab devices
