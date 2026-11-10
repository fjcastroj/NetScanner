# Spec Delta

## ADDED Requirements

### Requirement: Configuration screen
The web interface SHALL provide a screen to edit seeds, allowed and excluded ranges, depth, the IP-MAC option and limits, and to replace the credential through password fields that are never filled with stored values.

#### Scenario: Credential already configured
- **WHEN** the configuration screen opens with a credential stored
- **THEN** it shows that a credential is configured, its version and update time, and empty secret fields

#### Scenario: Validation error
- **WHEN** the API rejects the settings
- **THEN** the screen shows the reason next to the field concerned

### Requirement: Discovery screen
The web interface SHALL let the administrator start a run, see it progress until it finishes, and see the list of past runs with their result.

#### Scenario: Run in progress
- **WHEN** a run is running
- **THEN** the screen refreshes its status and counts every few seconds and disables the start button

### Requirement: RF-11 RF-29 Inventory screens
The web interface SHALL show a device list and a device detail in which every value shows whether it was observed or inferred and how old it is, with the method and source available on demand, and stale values marked.

#### Scenario: Inferred model
- **WHEN** the detail of `srx-01` is shown
- **THEN** the model appears marked as inferred, and the method and evidence fragments are visible on demand

#### Scenario: Stale value
- **WHEN** a value has not been confirmed within the staleness period
- **THEN** it is marked as stale with its last seen time

### Requirement: Lab mode notice
Until authentication exists, every screen SHALL show a notice that the application runs in lab mode without authentication.

#### Scenario: Notice visible
- **WHEN** any screen is open
- **THEN** the lab mode notice is visible in both supported languages
