# Spec Delta

## REMOVED Requirements

### Requirement: Lab mode until authentication
**Reason**: Authentication is implemented, so the lab-only mode ends.
**Migration**: The status endpoint reports authentication as described in the ADDED requirement below.

## ADDED Requirements

### Requirement: Status reports authentication
The status endpoint SHALL report that authentication is enabled and whether an administrator account exists, and SHALL NOT reveal the user name or any session detail.

#### Scenario: Status without session
- **WHEN** the status endpoint is read without a session
- **THEN** it answers 200 with `authentication: true` and whether an administrator exists, and nothing else about the account
