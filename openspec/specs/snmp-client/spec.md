# snmp-client Specification

## Purpose
TBD - created by archiving change add-snmp-client-and-lab. Update Purpose after archive.
## Requirements
### Requirement: RNF-02 Read-only operations
The SNMP client SHALL offer only GET, GETNEXT and GETBULK operations and SHALL contain no code path that can send a SET request.

#### Scenario: No SET available
- **WHEN** the client package is inspected by an automated test
- **THEN** it exposes no write operation and imports no SET function from the SNMP library

### Requirement: Library behind a project interface
All SNMP access SHALL go through a client interface owned by the project, so that the SNMP library can be replaced without changing the code that uses the client.

#### Scenario: Replaceable implementation
- **WHEN** the tests of the code that uses the client run with a fake implementation of the interface
- **THEN** they pass without importing the SNMP library

#### Scenario: Same contract tests for every implementation
- **WHEN** a second implementation of the interface is added (for example one based on Net-SNMP for the comparison)
- **THEN** the same contract test suite (outcomes, completeness, columns reported, error categories) runs against it unchanged

### Requirement: SNMP versions and credentials
The client SHALL support SNMPv2c with a community and SNMPv3 with authNoPriv or authPriv using SHA-family authentication and AES privacy, and SHALL reject SNMPv1, MD5 and DES.

#### Scenario: Unsupported security
- **WHEN** a credential with MD5 authentication or DES privacy is given to the client
- **THEN** the client refuses it with a validation error that does not contain the secret

#### Scenario: SNMPv3 query
- **WHEN** the client queries the lab with a valid SNMPv3 authPriv credential
- **THEN** the query succeeds

### Requirement: RNF-01 Credentials never exposed by the client
Community strings and SNMPv3 keys SHALL be held only in memory as secret values and SHALL NOT appear in logs, exception messages, query records or the text form of any object, which tests SHALL prove with canary values.

#### Scenario: Failed query with a canary community
- **WHEN** a query with a canary community times out, fails with an error status or receives a malformed response
- **THEN** no log record, exception text or stored query record contains the canary

### Requirement: RF-06 Classification of table walks
The client SHALL classify a table walk by its rows and, when it returns none, by a GET on the table's first column without index: `noSuchObject` means not available and `noSuchInstance` means supported but empty. A GET on the table node SHALL NOT be used to classify, because devices answer `noSuchObject` there even for supported tables.

#### Scenario: Supported table with rows
- **WHEN** a walk of a table returns rows and ends normally
- **THEN** the outcome is `ok` with the row count

#### Scenario: Supported but empty table
- **WHEN** a walk returns no rows and the column probe answers `noSuchInstance`
- **THEN** the outcome is `empty` with the indicator `noSuchInstance`

#### Scenario: Table not implemented
- **WHEN** a walk returns no rows and the column probe answers `noSuchObject`
- **THEN** the outcome is `not_available` with the indicator `noSuchObject`

#### Scenario: Ambiguous probe answer
- **WHEN** the column probe answers `endOfMibView` or an unexpected value
- **THEN** the outcome is `empty` and the indicator records the actual answer, so the case can be reviewed per vendor

### Requirement: RF-06 Failure outcomes
The client SHALL report `no_response` when no answer arrives within the timeout and retries, `partial` when a walk stops after returning rows, and `error` for SNMP error statuses, undecodable responses or non-increasing OIDs, always with a short error category.

#### Scenario: Silent agent
- **WHEN** the agent never answers
- **THEN** the outcome is `no_response`, with no claim about the cause

#### Scenario: Agent stops answering mid-walk
- **WHEN** a walk receives rows and then a request times out
- **THEN** the outcome is `partial`, the rows received are returned and the result says it is not complete

#### Scenario: Non-increasing OIDs
- **WHEN** an agent returns an OID that is not greater than the previous one
- **THEN** the walk stops, with outcome `partial` if rows were received or `error` otherwise, and category `non_increasing_oid`

#### Scenario: Error status
- **WHEN** an agent answers with an SNMP error status such as `genErr` or `authorizationError`
- **THEN** the outcome is `error` with the error status as category

### Requirement: RNF-06 Bounded load
The client SHALL use GETBULK for walks with SNMPv2c and SNMPv3, with configurable max-repetitions (initially 25, at most 50), per-request timeout and retries, at most one request in flight per device, a global limit of concurrent devices and a maximum number of rows per walk; the initial values are lab defaults to be reviewed after the first real run.

#### Scenario: One request at a time per device
- **WHEN** several walks are requested for the same device at the same time
- **THEN** the agent never receives a new request from the client before answering or timing out the previous one

#### Scenario: Row limit reached
- **WHEN** a walk reaches the configured maximum number of rows
- **THEN** the walk stops with outcome `partial` and category `row_limit`

#### Scenario: Out-of-range settings
- **WHEN** the configured max-repetitions is greater than 50 or the timeout is not positive
- **THEN** the service refuses to start and names the setting

### Requirement: Results usable by the store
Walk results SHALL report, for each row, only the columns actually received, together with the outcome, completeness, indicator, number of requests sent, start time and duration, so that callers can apply the store's contract (omitted means not retrieved, `None` means absent only in a complete query).

#### Scenario: Column missing in a complete walk
- **WHEN** a complete walk returns a row without one of the requested columns
- **THEN** the result marks the walk as complete and the column as absent for that row

#### Scenario: Column not reached in a partial walk
- **WHEN** a walk stops before reaching a column
- **THEN** the result marks the walk as not complete and does not report that column for any row

### Requirement: RNF-04 Malformed responses
The client SHALL treat undecodable or unexpected responses as query errors and SHALL never let them stop the calling process.

#### Scenario: Garbage datagram
- **WHEN** the agent answers with bytes that are not a valid SNMP message
- **THEN** the query ends with outcome `error` or `no_response` and the process keeps running

### Requirement: Measured library decision
The choice of SNMP library SHALL be recorded with measurements taken on the lab against Net-SNMP as reference: equality of the values returned, correctness of every outcome, walk time and installation on Windows and in the container.

#### Scenario: Decision recorded
- **WHEN** the change is completed
- **THEN** `docs/decisions/snmp-library.md` contains the measurements, the criteria and the decision with its status
