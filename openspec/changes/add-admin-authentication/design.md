# Design

## Context

The API is reached only through nginx in the `web` container, which forwards
`/api/` to the `api` service inside the Compose network; only `web`
publishes a port, on `127.0.0.1:8080` by default (`NETSCANNER_WEB_BIND`). The
API has no authentication. The lab-only guard in `netscanner.scope`
(`LAB_RANGES`, `check_lab_guard`) stops real ranges from being saved or run,
and the status endpoint reports `lab_mode: true`.

Facts from the code that shape this design:

| Fact | Consequence |
|------|-------------|
| nginx sends `Host $host`, which drops the port, and the API cannot know the scheme seen by an outer TLS proxy | Allowed origins come from configuration, not from the request (D6) |
| nginx sends `X-Forwarded-For $proxy_add_x_forwarded_for`, which appends to a value the client may set | The source address for rate limiting is the last entry, the one nginx adds (D7) |
| All routes are mounted from one router in `netscanner.api.routes` | Protection is a dependency on that router plus an explicit public list (D4) |
| The frontend client in `frontend/src/api.ts` is the only place that calls `fetch` | The custom header and the 401 handling go there once (D8) |
| `argon2` is already in the planned stack in `openspec/config.yaml` | `argon2-cffi`, no new technology |
| The collector never receives HTTP requests | Nothing in the collector changes |

## Goals / Non-Goals

**Goals:** a single administrator, sessions that can be ended from the
server, every route closed by default, protection against cross-site requests
and password guessing, and the removal of lab mode under the condition the
project set.

**Non-Goals:** several users or roles, directory integration, TLS
termination, multi-factor authentication, password recovery.

## Decisions

### D1. Package layout — Decision
- `netscanner.auth`: password hashing, session store, rate limiter, the
  FastAPI dependency that requires a session, and the cross-site check.
- `netscanner.admin`: console commands (`create`, `reset-password`),
  run as `python -m netscanner.admin`.
- `netscanner.api.routes.auth`: login, logout and current session.
The architecture tests of the previous changes are extended: only
`netscanner.auth` imports `argon2`, and no module outside `netscanner.auth`
reads the session cookie.

### D2. Account storage — Decision
Table `admin_account` with one row at most (a CHECK on a constant key):
`username`, `password_hash`, `created_at`, `password_changed_at`. Argon2id
with the `argon2-cffi` RFC 9106 low-memory profile. On a successful login,
if the stored hash uses older parameters it is rehashed. User names: 1 to 64
characters, letters, digits, `.`, `_` and `-`.

Alternative: account in environment variables. Discarded, because the hash
would live in `.env` next to other secrets and a reset would need a restart.

### D3. Sessions — Decision
Table `sessions`: `id`, `token_hash` (SHA-256 of a 32-byte random token,
unique), `created_at`, `last_used_at`, `expires_at` (absolute),
`source_address`. The cookie `netscanner_session` holds the token, with
`HttpOnly`, `SameSite=Strict`, `Secure`, `Path=/`, no `Max-Age` (it ends
with the browser; the server decides expiry). `last_used_at` is updated at
most once a minute to avoid a write on every request.

Settings, with validation and `.env.example` entries:
`NETSCANNER_SESSION_IDLE` (8 h), `NETSCANNER_SESSION_MAX_AGE` (24 h),
`NETSCANNER_SESSION_COOKIE_SECURE` (true). The values are initial and may be
reviewed.

`Secure` by default is a deliberate choice: plain HTTP from another machine
does not keep the cookie, so the application cannot be used insecurely
across the network by accident. Whether a browser keeps a `Secure` cookie
set over `http://localhost` is a separate rule from treating localhost as a
secure context: current Chromium and Firefox do, and Safari does not
(MDN). This is a **hypothesis** for the author's browser, checked in task
7.3. The official local address is `http://localhost:8080`, although Docker
listens on `127.0.0.1:8080`.

`NETSCANNER_SESSION_COOKIE_SECURE=false` is accepted only when
`NETSCANNER_WEB_BIND` is a loopback address; otherwise the API refuses to
start. Compose passes `NETSCANNER_WEB_BIND` to the `api` service for this
check. The check prevents a configuration mistake, it does not guarantee the
real binding: someone editing the `ports:` of the Compose file by hand is
not detected.

Alternative: JWT in the browser's storage. Discarded: it cannot be revoked
on logout or password reset, and it is readable by scripts on the page.

### D4. Route protection — Decision
`require_session` is a dependency on the `/api` router, with an explicit
public list: `GET /api/health`, `GET /api/status`, `POST /api/auth/login`,
`POST /api/auth/logout`. A test builds the application, enumerates every
route in it and calls each one not in the list without a cookie, expecting
401; a route the test cannot call (unknown method or path parameters) makes
the test fail rather than be skipped. The 401 body is generic and the same
for a missing, unknown or expired session.

`GET /api/auth/session` (protected) returns the user name and the session
expiry for the interface.

### D5. Login and logout — Decision
`POST /api/auth/login` takes `username` and `password`. With no account, or
a wrong user name, the password is still checked against a fixed dummy hash
so that timing does not reveal which part was wrong. The test checks the
mechanism (exactly one Argon2id verification on every path) and, as an
additional check, compares the median of several runs with a generous
tolerance, so that CI does not fail on timing noise. On success, a new
session is created (never reused), and any session cookie sent with the
request is ignored. `POST /api/auth/logout` deletes the session if there is
one and always clears the cookie.

### D6. Cross-site requests — Decision
For `POST`, `PUT`, `PATCH` and `DELETE` the API requires the header
`X-NetScanner-Request: 1` and, if `Origin` is present, that it is an allowed
origin. Allowed origins come from configuration only, never from forwarded
headers: `NETSCANNER_PUBLIC_ORIGIN` (a single `scheme://host[:port]`,
validated at startup) when it is set, otherwise `http://localhost:<port>` and
`http://127.0.0.1:<port>` with the port of `NETSCANNER_WEB_BIND`. Comparing
with the request's own scheme and `Host` would reject legitimate requests
behind a TLS proxy, where the browser sends `https://…` and the API sees
HTTP, and OWASP advises against trusting forwarded headers to rebuild the
target origin.

A page on another site cannot add a custom header to a form, and a
cross-origin `fetch` with it triggers a preflight that the API never allows
(no CORS). With `SameSite=Strict` this gives two independent barriers. The
stack test covers the check through the web port. nginx keeps sending the
`Host` it does today; it is no longer used for this check.

### D7. Guessing limit — Decision
Table `login_attempts`: `at`, `source_address`, `succeeded`. Five failures
from one address in 15 minutes give 429 with `Retry-After` until the oldest
failure leaves the window; no account lockout, which would let anyone lock
the administrator out. The source address is the last entry of
`X-Forwarded-For` (the one nginx adds), stripped and parsed as an IP address;
when the header is absent or that entry is not a valid address, the
connection address is used. Rows older than a day are deleted on each login. Log
records: time, source address, result and the user name only when it
matches the account; never the password.

### D8. Web interface — Decision
`api.ts` adds `X-NetScanner-Request: 1` to every request and, on 401,
notifies the application, which clears its data, remembers the current page
and shows the login screen. The login form uses `autocomplete="username"`
and `"current-password"`. The header shows the user name and a logout
button. The lab mode banner is removed. Spanish and English.

### D9. Removing lab mode — Decision
Removed together, in the same change, after the protection tests exist:
`LAB_RANGES` restriction in settings validation and in `ScopePolicy`,
`scope_not_allowed` as a failure caused by the guard (the category stays
for a scope the policy cannot build), the lab mode banner, and
`lab_mode: true` in status. Status becomes `{"authentication": true,
"admin_exists": <bool>}`. The rule in `openspec/config.yaml` about the
guard is replaced by one stating that the guard was removed by this change
and why. The test that asserted the guard is replaced by the route
enumeration test of D4.

### D10. Console commands — Decision
`python -m netscanner.admin create --username <name>` and
`python -m netscanner.admin reset-password`, run with
`docker compose run --rm api python -m netscanner.admin ...`. The password is
read twice with `getpass`, or once from standard input with
`--password-stdin` for the stack test. It is never accepted as an argument,
so it cannot end up in the shell history or the process list. Reset deletes
every session in the same transaction.

## Risks / Trade-offs

- **No TLS in the application.** Credentials and cookies travel in clear
  over HTTP. Accepted for local use; the README requires a TLS proxy for any
  other use, and the `Secure` cookie makes plain HTTP across the network
  fail instead of working insecurely.
- **One administrator.** If the password is lost, it is reset from the
  server console; no recovery through the network by design.
- **Rate limiting per address.** Several addresses can each try five times
  per window. Accepted for a single-server tool; Argon2id keeps each attempt
  expensive.
- **Rate limiting behind an outer TLS proxy.** The last `X-Forwarded-For`
  entry will then be the proxy's address, so every client shares one window.
  With a single administrator this only means a guessing attacker can delay
  the administrator's login for up to 15 minutes; accepted and documented.
- **`last_used_at` granularity.** Idle expiry can be up to a minute late.

## Migration Plan

Migration `0005`: `admin_account`, `sessions`, `login_attempts`, with
upgrade and downgrade. No data migration; after upgrading, the operator
creates the administrator.

## Open Questions

- Whether the author's browser keeps a `Secure` cookie on
  `http://localhost:8080` (D3, task 7.3).
- Trusting an outer proxy's `X-Forwarded-For` for rate limiting is deferred
  until such a proxy is actually used.
