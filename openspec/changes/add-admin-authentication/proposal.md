# Proposal

## Why

Until now NetScanner runs only in lab mode: the API has no authentication,
so the scope is restricted to the lab range and the application must not
store real credentials or real network data (project rule in
`openspec/config.yaml`). The evaluation of OE6 needs the first run against
the real network, and that requires a protected application first.

This change adds the local administrator account required by RNF-05 and,
only once every administrative route is shown to refuse requests without a
session, removes the lab-only guard.

## What Changes

- One local administrator account, created and reset only from the server
  console, with the password stored as an Argon2id hash.
- Server-side sessions in the database, sent as an `HttpOnly`,
  `SameSite=Strict` cookie, `Secure` by default, with idle and absolute expiry, logout
  and revocation on password reset.
- Every route under `/api` requires a session except health, status, login
  and logout. A test enumerates all routes, so a future route cannot be left
  open by mistake.
- Protection against cross-site requests (custom request header and origin
  check) and against password guessing (rate limit per source address).
- Login screen, session expiry handling and logout in the web interface.
- Removal of the lab-only scope guard and of the lab mode notice, together
  with the end-to-end tests the project rule requires.
- Change of order: `add-admin-authentication` goes before
  `add-interface-polling`, because the first real run needs it and polling
  does not.

## Requirements covered

- RNF-05 [E] local administrator with hashed password.
- RNF-01 [E] (extended) session tokens and passwords never exposed.
- RNF-04 [E] (extended) validation of login input.
- RF-01, RF-02 [E] unchanged, now usable with real ranges and credentials.

## Capabilities

### New Capabilities

- `admin-authentication`: administrator account, sessions, route protection,
  cross-site request and guessing protection.

### Modified Capabilities

- `snmp-scope`: the lab-only guard is removed.
- `inventory-api`: lab mode ends; the status endpoint reports authentication.
- `web-ui`: login screen, session handling, no lab mode notice.
- `deployment`: administrator commands; the stack test checks authentication.

## Out of Scope

- Several users, roles, LDAP or Active Directory, single sign-on.
- TLS termination. The documentation states that exposing NetScanner beyond
  the local machine requires a reverse proxy with TLS in front of `web`.
- Password recovery by e-mail; multi-factor authentication.

## Impact

- Migration `0005`: `admin_account`, `sessions`, `login_attempts`.
- New package `netscanner.auth`; console module `netscanner.admin`.
- New dependency `argon2-cffi`, already in the planned stack.
- New settings for sessions and `NETSCANNER_PUBLIC_ORIGIN`; Compose passes
  `NETSCANNER_WEB_BIND` to the `api` service.
- Frontend: login page, API client handling of 401, logout.
