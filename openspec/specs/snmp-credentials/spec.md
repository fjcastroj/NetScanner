# snmp-credentials Specification

## Purpose

Defines how the SNMP credential set is stored and used: encrypted at rest,
write-only through the API and decrypted only by the SNMP adapter.

## Requirements
### Requirement: RF-01 One write-only credential set
The system SHALL keep one SNMP credential set (SNMPv2c community, or SNMPv3 user with its protocols and keys) that can be created and replaced but never read back; reads SHALL return only its version, type, non-secret fields and update time.

#### Scenario: Reading the credential
- **WHEN** the credential is requested through the API
- **THEN** the response contains whether it is configured, its SNMP version, the v3 user and protocols if any, and when it was updated, but no community or key

#### Scenario: Replacing the credential
- **WHEN** a new credential is saved
- **THEN** it replaces the previous one, and runs already in progress keep the credential they started with

### Requirement: RNF-01 Encrypted at rest
Secret values SHALL be stored only encrypted with a key derived from `NETSCANNER_SECRET_KEY`, together with a non-secret identifier of that key, so that a credential stored with another key is reported as unusable without decrypting it.

#### Scenario: Database content
- **WHEN** the database is inspected after saving a canary community
- **THEN** no table contains the canary in clear text

#### Scenario: Secret key changed
- **WHEN** `NETSCANNER_SECRET_KEY` changes and a run needs the stored credential
- **THEN** the credential endpoint reports it as unusable by comparing key identifiers, without decrypting it, and a run started anyway fails with reason `credential_unreadable` before any datagram is sent

#### Scenario: Corrupted token
- **WHEN** the key identifier matches but the stored token cannot be decrypted
- **THEN** the adapter refuses to open the session and the run fails with reason `credential_unreadable`

### Requirement: Secrets used only by the SNMP adapter
Discovery and every other component SHALL refer to the credential by identifier only; the secret SHALL be decrypted only within the SNMP adapter's session boundary, which SHALL register the secret values with the log-masking filter before using them, and SHALL NOT appear in run parameters, query records, logs, API responses or snapshots, which canary tests SHALL prove.

#### Scenario: SNMPv3 rejected by one device
- **WHEN** one device answers an SNMPv3 request with a report for an unknown user or wrong digest
- **THEN** that candidate is recorded with reason `auth_failed`, the report counter is kept on the query, and the run continues with the other devices

#### Scenario: Canary through a whole run
- **WHEN** a discovery run in the lab uses a canary community, including timeouts and errors
- **THEN** the canary appears in no log record, API response, run parameter, query record, snapshot or exception text

