# web-ui Specification

## Purpose

Defines the NetScanner web interface shell and its language support, so that
every later screen is built on the same layout and translation mechanism.

## Requirements

### Requirement: Application shell
The web interface SHALL provide a common layout with the application name,
a navigation area for the future sections and a status indicator that shows
whether the API is reachable, based on the health endpoint.

#### Scenario: API reachable
- **WHEN** the web interface loads and `GET /api/health` answers 200
- **THEN** the status indicator shows that the service is available

#### Scenario: API unreachable
- **WHEN** the web interface loads and the health request fails or answers 503
- **THEN** the status indicator shows that the service is unavailable, without a technical error trace

### Requirement: RNF-12 Multilingual interface
All user-visible text in the web interface SHALL come from translation files
kept separate from the code, with Spanish and English provided. Adding a
language SHALL require only a new translation file and its registration in
the language list.

#### Scenario: Language selection
- **WHEN** the user selects English or Spanish in the language selector
- **THEN** all visible text changes to that language without reloading the page
- **AND** the choice is remembered in the browser for the next visit

#### Scenario: Default language
- **WHEN** a user opens the interface for the first time
- **THEN** the browser's preferred language is used if it is supported, otherwise Spanish

#### Scenario: Missing translation key
- **WHEN** a key exists in Spanish but not in English
- **THEN** an automated test fails and names the missing key
