# Spec Delta

## MODIFIED Requirements

### Requirement: RNF-06 Bounded load
The client SHALL use GETBULK for walks with SNMPv2c and SNMPv3, with configurable max-repetitions (initially 25, at most 50), per-request timeout and retries, at most one request in flight per device, a global limit of concurrent devices, a maximum number of rows per walk and an optional datagram budget per call; retries SHALL be performed by the client's library-independent walker, not by the SNMP library, so that every datagram sent can be counted; the initial values are lab defaults to be reviewed after the first real run.

#### Scenario: One request at a time per device
- **WHEN** several walks are requested for the same device at the same time
- **THEN** the agent never receives a new request from the client before answering or timing out the previous one

#### Scenario: Row limit reached
- **WHEN** a walk reaches the configured maximum number of rows
- **THEN** the walk stops with outcome `partial` and category `row_limit`

#### Scenario: Out-of-range settings
- **WHEN** the configured max-repetitions is greater than 50 or the timeout is not positive
- **THEN** the service refuses to start and names the setting

#### Scenario: Retries by the walker
- **WHEN** a silent agent is queried with timeout T and R retries
- **THEN** it receives exactly R + 1 datagrams for that request, and the call takes about T × (R + 1), with both client implementations

#### Scenario: Request not covered by the budget
- **WHEN** the remaining datagram budget does not cover every attempt of the next request
- **THEN** the request is not sent; a walk that already has rows ends as `partial` with category `request_limit`, a walk without rows whose subtree needs more requests than were reserved ends as `error` with category `request_limit`, and a call that has sent nothing returns without querying

#### Scenario: SNMPv3 engine discovery in the budget
- **WHEN** an SNMPv3 call is made with a datagram budget
- **THEN** the result reports the datagrams the client observed, and the budget consumed is those plus one for the library's engine discovery, so the budget covers the real traffic

### Requirement: Results usable by the store
Walk results SHALL report, for each row, only the columns actually received, together with the outcome, completeness, indicator, number of datagrams sent (every attempt, including retries and probes), start time and duration, so that callers can apply the store's contract (omitted means not retrieved, `None` means absent only in a complete query).

#### Scenario: Column missing in a complete walk
- **WHEN** a complete walk returns a row without one of the requested columns
- **THEN** the result marks the walk as complete and the column as absent for that row

#### Scenario: Column not reached in a partial walk
- **WHEN** a walk stops before reaching a column
- **THEN** the result marks the walk as not complete and does not report that column for any row

#### Scenario: Datagrams counted
- **WHEN** a walk needs one retry and a probe
- **THEN** its reported datagram count includes the retried attempt and the probe
