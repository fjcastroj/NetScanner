# Spec Delta

## REMOVED Requirements

### Requirement: Lab mode notice
**Reason**: Lab mode ends with authentication.
**Migration**: The notice is removed from the layout. Its place in the header shows the logged-in administrator and the logout button.

## ADDED Requirements

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
