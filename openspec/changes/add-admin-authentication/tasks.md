# Tasks

Prerequisite: `add-discovery-and-basic-inventory` archived and merged. Use
only lab data. Do not read, list or search anything under `local/` or outside
the repository. Write files with LF line endings.

## 1. Data model

- [x] 1.1 Migration `0005` per the Migration Plan, with upgrade and downgrade tests against PostgreSQL, including the one-row constraint of `admin_account`

## 2. Passwords and account

- [x] 2.1 `netscanner.auth` password hashing per design D2 (`argon2-cffi` pinned), rehash on outdated parameters, password and user name rules
- [x] 2.2 `netscanner.admin` commands per design D10; tests: create, create twice refused, reset ends every session, short password refused without echo, password never accepted as an argument
- [x] 2.3 Canary test: a created password appears in no table, log record or command output

## 3. Sessions and login

- [x] 3.1 Session store per design D3, settings with validation and `.env.example` entries; `NETSCANNER_WEB_BIND` passed to the `api` service; startup refused with `Secure` off and a non-loopback bind address (tests: `127.0.0.1:8080` and `[::1]:8080` accepted; `0.0.0.0:8080`, `[::]:8080` and a bare port such as `8080`, which publishes on every interface, refused)
- [x] 3.2 Login, logout and current session routes per design D5; tests for idle and absolute expiry, token stored only as a hash, new session on each login, logout clearing the cookie
- [x] 3.3 Equal answer for unknown user and wrong password: a test that every path performs exactly one Argon2id verification (stored or dummy hash), plus a median-of-several-runs timing comparison with a generous tolerance
- [x] 3.4 Guessing limit per design D7; tests: 429 with `Retry-After` on the sixth failure, success not counted, source address taken from the last `X-Forwarded-For` entry, a forged first entry ignored, spaces around the last entry, an IPv6 entry, a malformed entry falling back to the connection address, old rows deleted, log records without the password

## 4. Route protection

- [x] 4.1 `require_session` on the `/api` router with the public list of design D4, `Cache-Control: no-store` on protected responses
- [x] 4.2 Route enumeration test of design D4, failing on any route it cannot call and naming it
- [x] 4.3 Cross-site check of design D6 with `NETSCANNER_PUBLIC_ORIGIN` (validated at startup as a bare origin: scheme `http` or `https`, host and optional port only; `https://netscanner.example` and `https://netscanner.example:8443` accepted, a path, user information, query or fragment refused) and the local default origins; tests: missing header, wrong `Origin`, each local origin, no `Origin`, a configured `https` public origin accepted and its `http` variant refused, forwarded headers never changing the allowed origins
- [x] 4.4 Architecture tests of design D1 extended (only `netscanner.auth` imports `argon2` or reads the cookie)

## 5. Removing lab mode

- [x] 5.1 Remove the lab-only guard per design D9 from settings validation and `ScopePolicy`, and the lab mode fields from status; replace the guard tests by the route enumeration test
- [x] 5.2 Tests: a real-looking range (documentation range 198.51.100.0/24) is accepted when saved with a session and refused with 401 without one; the out-of-scope and excluded-address tests still pass
- [x] 5.3 Replace the guard rule in `openspec/config.yaml` and update the planned change sequence (authentication before interface polling, with the reason)

## 6. Web interface

- [x] 6.1 `api.ts` per design D8: custom header on every request, 401 notification
- [x] 6.2 Login page, return to the previous page after login, logout in the header, banner removed, es and en
- [x] 6.3 Component tests: generic failure message, password field emptied, 429 message with time, no-account message, return to the previous page, logout

## 7. Deployment and documentation

- [x] 7.1 Stack test per the deployment delta: create the administrator with `--password-stdin`, 401 before login through the web port, lab run after login, 401 after logout, cross-site check through the web port
- [x] 7.2 README: official local address `http://localhost:8080`, create and reset commands, TLS proxy requirement beyond local use with `NETSCANNER_PUBLIC_ORIGIN`, the `Secure` cookie setting and its loopback-only exception, what lab mode was and why it ended; `docs/architecture.md` section on authentication (what is guaranteed, how it is tested, what is not covered)
- [ ] 7.3 Manual check, documented in the PR: log in from the author's browser at `http://localhost:8080` and confirm the `Secure` cookie is kept (open question of the design)
- [x] 7.4 `CHANGELOG.md` entry
- [x] 7.5 `scripts/check_confidentiality.py --all`, the full suite on Linux after the last edit, the hooks, the stack test and `openspec validate --all --strict`; all green
