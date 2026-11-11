# Spec Delta

## Purpose

Defines how the single local administrator authenticates and how the API is
protected, so that real credentials and real network data are only reachable
with a valid session.

## ADDED Requirements

### Requirement: RNF-05 Single local administrator
The system SHALL have at most one administrator account, identified by a user name and a password stored only as an Argon2id hash, and SHALL NOT have a default account, a default password or a registration screen.

#### Scenario: Fresh installation
- **WHEN** the application starts with no administrator account
- **THEN** every protected route answers 401, the login screen says that the administrator must be created from the server console, and no account can be created through the API

#### Scenario: Password stored
- **WHEN** the administrator account is created with a canary password
- **THEN** the database holds only an Argon2id hash, and the canary appears in no table, log record or API response

### Requirement: Administrator managed from the server console
The administrator account SHALL be created and its password reset only through a console command run on the server, which reads the password twice without echo (or once from standard input for automation) and never from a command-line argument; resetting the password SHALL end every open session.

#### Scenario: Create twice
- **WHEN** the create command runs while an account already exists
- **THEN** it refuses and tells the operator to use the reset command

#### Scenario: Reset ends sessions
- **WHEN** the password is reset while sessions are open
- **THEN** every open session stops being valid at once

### Requirement: Password rules
Passwords SHALL have between 12 and 128 characters and SHALL differ from the user name; no composition rules are imposed.

#### Scenario: Short password
- **WHEN** a password of 11 characters is given to the create command
- **THEN** it is refused with the reason, and the password is not echoed

### Requirement: Server-side sessions
A successful login SHALL create a session stored in the database by the hash of a random token, sent to the browser only in an `HttpOnly`, `SameSite=Strict` cookie with path `/`, marked `Secure` by default; the `Secure` attribute MAY be turned off only when the configured web bind address is a loopback address, and the API SHALL refuse to start otherwise. A session SHALL end after 8 hours without use, 24 hours after login, on logout, or on password reset.

#### Scenario: Secure off with a non-local bind address
- **WHEN** `NETSCANNER_SESSION_COOKIE_SECURE` is false and `NETSCANNER_WEB_BIND` is not a loopback address
- **THEN** the API refuses to start and names both settings

#### Scenario: Idle expiry
- **WHEN** a session has not been used for more than the idle period
- **THEN** the next request answers 401 and the session is deleted

#### Scenario: Absolute expiry
- **WHEN** a session is used continuously for more than the absolute period
- **THEN** it stops being valid even though it was never idle

#### Scenario: Token not stored
- **WHEN** the sessions table is inspected after a login
- **THEN** it holds the token's hash, never the token sent in the cookie

#### Scenario: Logout
- **WHEN** the administrator logs out
- **THEN** the session is deleted on the server and the cookie is cleared

### Requirement: Every administrative route protected
Every route under `/api` SHALL require a valid session, except `GET /api/health`, `GET /api/status`, `POST /api/auth/login` and `POST /api/auth/logout`, and a test SHALL enumerate every route of the application and fail if any other route answers without a session.

#### Scenario: Request without session
- **WHEN** any settings, credential, run or inventory route is called without a session
- **THEN** it answers 401 with a generic body and performs no action

#### Scenario: New route added without protection
- **WHEN** a developer adds a route outside the public list without the session dependency
- **THEN** the route enumeration test fails and names the route

### Requirement: Cross-site request protection
Requests that change state (`POST`, `PUT`, `PATCH`, `DELETE`) SHALL be refused with 403 unless they carry the header `X-NetScanner-Request: 1` and, when an `Origin` header is present, it is one of the allowed origins: the value of `NETSCANNER_PUBLIC_ORIGIN` when it is set, otherwise `http://localhost:<port>` and `http://127.0.0.1:<port>` for the port of the web bind address. Allowed origins SHALL never be derived from forwarded headers.

#### Scenario: Form from another site
- **WHEN** a page on another site submits a form to start a run while the administrator is logged in
- **THEN** the request is refused and no run is created

#### Scenario: Behind a TLS proxy
- **WHEN** `NETSCANNER_PUBLIC_ORIGIN` is `https://netscanner.example.org` and the browser sends that origin through the proxy
- **THEN** the request is accepted, and a request with origin `http://netscanner.example.org` is refused

### Requirement: Password guessing limited
After 5 failed logins from one source address within 15 minutes, further login attempts from that address SHALL answer 429 with a retry time until the window passes, without locking the account; the source address SHALL be the last entry of `X-Forwarded-For` parsed as an IP address, or the connection address when that entry is absent or not a valid address; every login attempt SHALL be logged with time, source address and result, never with the password.

#### Scenario: Repeated failures
- **WHEN** a sixth wrong password is sent from the same address within the window
- **THEN** the answer is 429 and the password is not checked

#### Scenario: Forged forwarding header
- **WHEN** a client sends `X-Forwarded-For` with invented first entries, spaces around the last one, an IPv6 address, or a malformed value
- **THEN** only the last entry added by nginx is used, normalised as an IP address, and a malformed value falls back to the connection address

#### Scenario: Unknown user and wrong password look the same
- **WHEN** a login uses an unknown user name, and another uses the right user name with a wrong password
- **THEN** both answer 401 with the same body, and each performs exactly one Argon2id verification, against the stored hash or a fixed dummy hash

#### Scenario: Attempt logged
- **WHEN** a login fails with a canary password
- **THEN** the log records the attempt and its result, and the canary is absent from it

### Requirement: No caching of protected responses
Responses of protected routes SHALL carry `Cache-Control: no-store`.

#### Scenario: Device detail
- **WHEN** the device detail is read with a session
- **THEN** the response has `Cache-Control: no-store`
