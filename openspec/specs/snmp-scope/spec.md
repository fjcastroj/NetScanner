# snmp-scope Specification

## Purpose

Defines which addresses NetScanner may query, how that is enforced below
every SNMP use, and the operational limits of a run.
## Requirements
### Requirement: RNF-03 Authorised scope
The system SHALL query only IP addresses that are inside an allowed range and outside every excluded range, with exclusion taking precedence, and SHALL query nothing when no allowed range is configured.

#### Scenario: Deny by default
- **WHEN** a run starts with no allowed range
- **THEN** no SNMP request is sent and the run fails with the reason that the scope is empty

#### Scenario: Excluded inside allowed
- **WHEN** the lab range is allowed, 10.99.0.3/32 is excluded and `lab-sw-01` advertises 10.99.0.3 over LLDP
- **THEN** `lab-sw-02` is not queried and the candidate is recorded with reason `excluded`

#### Scenario: Candidate outside the scope
- **WHEN** `lab-sw-01` advertises 203.0.113.10, outside every allowed range, and the test transport sends that address to a scripted agent holding a canary community
- **THEN** the agent receives no request at all, and the candidate is recorded with reason `out_of_scope`

### Requirement: Seeds inside the scope
Seeds SHALL be IP addresses inside the scope, and configuration with a seed outside it SHALL be rejected when saved.

#### Scenario: Seed outside the scope
- **WHEN** the administrator saves a seed outside the allowed ranges or inside an excluded range
- **THEN** the configuration is rejected with a message naming the seed

#### Scenario: Host name as seed
- **WHEN** a seed is a host name instead of an IP address
- **THEN** the configuration is rejected

### Requirement: Special addresses never queried
The system SHALL never query multicast, limited broadcast, unspecified or link-local addresses, nor the network and broadcast addresses of an allowed IPv4 range with a prefix of /30 or shorter, and SHALL query loopback addresses only when a loopback range is explicitly allowed.

#### Scenario: Point-to-point ranges
- **WHEN** 10.99.0.4/31 or 10.99.0.6/32 is the allowed range
- **THEN** every address in it may be queried, since such ranges have no network or broadcast address

#### Scenario: Multicast candidate
- **WHEN** an IP-MAC entry contains a multicast address inside an allowed range
- **THEN** it is not queried and is recorded with reason `special_address`

### Requirement: Enforcement below every SNMP use
The SNMP client's public interface SHALL accept only authorised targets created by the scope policy, and only the internal SNMP adapter SHALL import the SNMP library, so that no other component can send an SNMP request without passing the scope check; architecture tests SHALL fail otherwise.

#### Scenario: Library imported elsewhere
- **WHEN** any module outside the internal SNMP adapter imports the SNMP library
- **THEN** an architecture test fails and names the module

#### Scenario: Authorised target built outside the policy
- **WHEN** code outside the scope policy constructs an authorised target directly
- **THEN** construction fails, and an architecture test checks that no production module attempts it

#### Scenario: Retries and probes
- **WHEN** a request times out and is retried, or a table probe follows a walk
- **THEN** they use the same authorised target and no request is ever sent to another address

### Requirement: Scope frozen per run
Each run SHALL store the scope and limits it started with and SHALL use only those until it ends, whatever changes are saved meanwhile.

#### Scenario: Configuration changed during a run
- **WHEN** the allowed ranges are changed while a run is in progress
- **THEN** the running run keeps using its stored scope, and the new scope applies to the next run

### Requirement: RNF-06 Operational limits
Each run SHALL be bounded by a maximum number of candidates recorded, of devices queried and of SNMP datagrams sent (including retries and probes), and by the maximum depth, each configurable in the discovery settings up to a ceiling fixed in the server's environment and copied into the run's parameters when the run is created; reaching a limit SHALL stop the work that limit governs, record the limit in the run summary and finish the run as completed. Concurrency SHALL remain bounded by the SNMP client's server-side setting and SHALL NOT be configurable from the interface.

#### Scenario: Limit above the ceiling
- **WHEN** the administrator saves a candidate limit above the server's ceiling
- **THEN** the settings are rejected with a message giving the ceiling

#### Scenario: Stored limits above the ceiling at run start
- **WHEN** a run starts whose stored limits exceed the server's current ceilings, for example after the database was edited or a ceiling was lowered
- **THEN** no SNMP request is sent and the run fails with reason `limits_not_allowed`

#### Scenario: Run without frozen limits
- **WHEN** a discovery run starts whose parameters carry no limits, for example one not created through the API
- **THEN** no SNMP request is sent, the server's ceilings are not used in their place, and the run fails with reason `limits_not_allowed`

#### Scenario: Candidate limit reached
- **WHEN** a run has recorded its maximum number of candidates
- **THEN** no further candidate is recorded or queued, and the run summary names the limit and how many further distinct addresses were found in tables already read

#### Scenario: Device limit reached
- **WHEN** a run has queried its maximum number of devices
- **THEN** candidates already recorded and not yet queried get reason `limit_reached`

#### Scenario: Datagram limit reached in the middle of a device
- **WHEN** the remaining datagram budget no longer covers every attempt of the next request of a walk that has already received rows
- **THEN** the request is not sent, the walk ends as `partial` with category `request_limit`, what was received is stored, the device's remaining tables are not queried, and remaining candidates get reason `limit_reached`

#### Scenario: Datagrams reserved for the probe
- **WHEN** the remaining budget covers the first request of a walk but not also the attempts of its classification probe
- **THEN** the walk does not start, so a walk that receives no rows can always be classified

#### Scenario: Retries counted
- **WHEN** a request times out and is retried
- **THEN** each attempt counts as one datagram against the budget, and a request is never interrupted between attempts

#### Scenario: Datagram budget exhausted before a candidate
- **WHEN** the datagram budget is already exhausted when a recorded candidate's turn comes
- **THEN** no request is sent and no query is recorded for it, and the candidate gets reason `limit_reached`, not `no_response`

