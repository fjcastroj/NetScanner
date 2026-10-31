# Spec Delta

## Purpose

Records every collection run and every individual query with its outcome,
so that each datum can point to the query that produced it and the
evaluation can be computed from stored records instead of logs.

## ADDED Requirements

### Requirement: Collection runs
The system SHALL record each collection run with its kind (discovery, rediscovery or polling), its status, when it was requested, started and finished, and a copy of the parameters it used without any secret.

#### Scenario: Run lifecycle
- **WHEN** a run is created, started and finished
- **THEN** its status moves from pending to running to completed, failed or interrupted, and each transition stores its time

#### Scenario: Parameters without secrets
- **WHEN** a discovery run is created with seeds, allowed ranges, exclusions, maximum depth and a credential
- **THEN** the stored parameters include the seeds, ranges, exclusions, depth and a reference to the credential, but never the community or any key

#### Scenario: Run interrupted by a restart
- **WHEN** the collector starts and finds runs left in running state by a previous process
- **THEN** those runs are marked as interrupted with the time this was detected

### Requirement: RF-06 Outcome of every query
The system SHALL store one record per SNMP query with the target address, the device if already identified, the MIB object, the operation, the outcome, the number of rows, the number of requests sent, the start time and the duration.

#### Scenario: Table with rows
- **WHEN** a walk of `LLDP-MIB::lldpRemTable` returns rows
- **THEN** the query is stored with outcome `ok` and the number of rows

#### Scenario: Supported but empty table
- **WHEN** a table is supported by the device but has no rows
- **THEN** the query is stored with outcome `empty`

#### Scenario: Information not available
- **WHEN** the device reports that the object does not exist
- **THEN** the query is stored with outcome `not_available`

#### Scenario: No answer
- **WHEN** the device does not answer within the timeout and retries
- **THEN** the query is stored with outcome `no_response`

#### Scenario: Answer interrupted
- **WHEN** a walk returns some rows and then stops answering or returns an error
- **THEN** the query is stored with outcome `partial`, the rows received are kept, and they are not used to mark other data as absent

#### Scenario: Error answer
- **WHEN** the device answers with an SNMP error status or the response cannot be decoded
- **THEN** the query is stored with outcome `error` and an error category

### Requirement: No answer is not a diagnosis
The system SHALL record a missing answer as `no_response` without attributing it to a wrong credential, an unreachable host or a filter, because SNMPv2c gives no way to tell them apart.

#### Scenario: Wrong community
- **WHEN** a query is sent with a community the device does not accept and the device stays silent
- **THEN** the query is stored as `no_response`, with no claim that the community was wrong

### Requirement: Auditable outcome classification
The system SHALL store, for every query classified as empty or not available, the indicator the classification was based on (noSuchObject, noSuchInstance, endOfMibView or end of subtree), so that the classification can be checked for each vendor.

#### Scenario: Classification checked per vendor
- **WHEN** the queries of a run are reviewed
- **THEN** each empty or not available outcome shows the indicator returned by the device

### Requirement: Errors without sensitive detail
Query and run records SHALL store errors as a short category and SHALL NOT store credentials, raw exception text or full responses.

#### Scenario: Error recorded
- **WHEN** a query fails with an exception whose text contains connection details
- **THEN** only the category is stored, and a test with canary values confirms that no secret is stored

### Requirement: Complete queries
The system SHALL treat a query as complete only when its outcome is ok or empty and it has no rejected rows, and only complete queries SHALL be used to decide that a datum is absent.

#### Scenario: Query with rejected rows
- **WHEN** a walk returns all its rows but one of them is rejected by validation
- **THEN** the query keeps outcome `ok` with its rejected count, the valid rows are stored, and the query is not complete for deciding absence

### Requirement: Devices reached by each run
The system SHALL record every device reached in a run, whether new or already known, with how it was reached (seed, LLDP, CDP or IP-MAC table), its depth, the first query that reached it and whether it answered.

#### Scenario: Second run over a known network
- **WHEN** a second discovery run reaches the same ten devices as the first
- **THEN** the second run records ten devices reached, even though none of them is new

#### Scenario: Device that did not answer
- **WHEN** a candidate address within the allowed ranges does not answer
- **THEN** the run records it as reached without answer, with the way it was found

### Requirement: Records for the evaluation (OE6)
The stored records SHALL allow computing, for each run and without reading logs, the devices it reached and how, the devices that were new, the time from the start of the run to its end, and the count of each query outcome by vendor and MIB object.

#### Scenario: Evaluation figures from the records
- **WHEN** a completed discovery run is analysed
- **THEN** a database query over the stored records returns its duration, the devices reached, the new devices and the outcome counts per vendor and MIB object

### Requirement: Evaluation snapshots
When a snapshot is requested at the start of a run, the system SHALL generate it as part of closing the run, with a consistent read during which no other run can write observations, so that the run can be evaluated later even after the data changes.

#### Scenario: Evaluating an old run
- **WHEN** a snapshot was requested for a run and later runs change interfaces and neighbours
- **THEN** reading the snapshot returns the devices, interfaces, neighbour entries and IP-MAC entries as they were when the run closed, with their provenance

#### Scenario: Data updated by another run before closing
- **WHEN** a datum seen in the run was confirmed again by another run before this run closed
- **THEN** the snapshot marks that datum with the run that last confirmed it, instead of attributing the newer value to this run

#### Scenario: Snapshot not requested
- **WHEN** an evaluation asks for the snapshot of a run that did not request one
- **THEN** the system reports that the run cannot be reconstructed retrospectively

#### Scenario: Snapshot without secrets or excluded data
- **WHEN** a snapshot is taken
- **THEN** it contains no credential and none of the attributes excluded by data minimisation
