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

### Requirement: Login screen
The web interface SHALL show a login screen whenever there is no valid session, with user name and password fields, the browser's password manager hints, and a generic message on failure; when no administrator exists it SHALL explain that the account is created from the server console.

#### Scenario: Wrong password
- **WHEN** the login fails
- **THEN** the screen shows a generic message that does not say whether the user name or the password was wrong, and the password field is emptied

#### Scenario: Too many attempts
- **WHEN** the API answers 429
- **THEN** the screen says when the next attempt is possible

### Requirement: Session expiry handling
When any API call answers 401, the web interface SHALL return to the login screen, discard the data shown, and after login return to the page that was open.

#### Scenario: Session expired while browsing
- **WHEN** the session expires and the administrator opens a device
- **THEN** the login screen appears, and after logging in the device page is shown

### Requirement: Logout
The header SHALL show the administrator's user name and a logout button that ends the session and shows the login screen.

#### Scenario: Logout
- **WHEN** the administrator presses logout
- **THEN** the login screen appears and the previous page cannot be reopened with the browser's back button without logging in again

