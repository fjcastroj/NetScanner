# Architecture notes

This page records architectural guarantees that the code alone does not make
obvious. Each section says what is guaranteed, how it is tested and what is
not covered. Design decisions are in the OpenSpec changes under `openspec/`.

## Scope enforcement and credential handling

From `add-discovery-and-basic-inventory` (RF-01, RNF-01, RNF-03, RNF-06).
Scope and credentials are security preconditions of discovery, so no SNMP
request is sent without both.

### Packages and dependency direction

| Package | Role | May not |
|---------|------|---------|
| `netscanner.scope` | Scope policy, authorised targets, lab guard, settings validation. Pure code, no I/O | — |
| `netscanner.credential_store` | Encrypted credential table, write-only service, `CredentialResolver` | be used for decryption outside `netscanner.snmp` |
| `netscanner.snmp` | Client interface and walker; `pysnmp_client` is the only module importing PySNMP | take a plain address |
| `netscanner.discovery` | Run engine, mapping to the store, CDP parsing | import PySNMP or decrypt credentials |
| `netscanner.vendors` | Vendor rules, one module per vendor (only Juniper's `sysDescr` model rule today) | apply to a vendor without a verified capture |
| `netscanner.collector` | Claims pending runs and runs them | — |
| `netscanner.api` | Settings, credential, runs, inventory, status | obtain an SNMP client |

### Scope: what is guaranteed

- **Deny by default.** An address may be queried only if it is inside an
  allowed range and outside every exclusion. Unspecified, loopback (unless
  allowed), multicast, limited broadcast, link-local addresses and the
  network and broadcast addresses of allowed ranges of /30 or shorter are
  refused. The checks run in a fixed order, giving `special_address`, then
  `excluded`, then `out_of_scope`.
- **Frozen per run.** A run uses the scope and limits copied into its
  parameters when it was created, never the current settings.
- **One way to the transport.** The SNMP client takes only an
  `AuthorizedTarget`, which `ScopePolicy.authorize` alone can build: the
  constructor requires a private token. The target keeps a reference to the
  run's policy, and the adapter checks that policy again before every
  datagram, including retries and probes. The address sent is always the
  target's address.
- **Test mapping cannot widen the scope.** The optional `endpoint_for`
  argument, which maps lab addresses to local ports in tests, is applied
  after the scope check, and production code never passes it.
- **No lab-only guard any more.** Until `add-admin-authentication`,
  allowed ranges had to be inside 10.99.0.0/24 or loopback. That change
  removed the guard, because every administrative route now needs a session
  (see the authentication section below); every other rule here is unchanged.
- **Checks before any datagram.** A run fails before sending anything when
  its scope is empty (`empty_scope`), cannot be built from its stored ranges
  (`scope_not_allowed`),
  without frozen limits or with limits above the current ceilings
  (`limits_not_allowed`), or when its credential cannot be decrypted
  (`credential_unreadable`).
- **Bounded load.** Candidates, devices queried, SNMP datagrams (retries and
  probes included) and depth are limited per run, below ceilings set in the
  server's environment.

### Credentials: what is guaranteed

- **Encrypted at rest.** The secret fields are stored as a Fernet token.
  The encryption key and a key identifier are derived from
  `NETSCANNER_SECRET_KEY` with HKDF-SHA256. The identifier tells whether the
  stored token was made with the current key without decrypting it, and does
  not reveal the key.
- **Write-only through the API.** `PUT /api/settings/credential` takes the
  secret fields. `GET` returns only the version, the SNMPv3 user, level and
  protocols, the update time and `usable`. No response contains a secret.
  Validation errors name the field, never the value.
- **Decrypted only by the SNMP adapter.** `CredentialResolver.resolve` is
  called only from `netscanner.snmp`, when a device session opens. The
  resolver registers the secret values with the log-masking filter before it
  returns them.
- **Runs keep their own credential.** A run stores only the credential's
  identifier. Replacing the credential while a run is active keeps the old
  row, inactive, until no pending or running run references it, and then
  deletes it.
- **No device data in errors.** An exception while processing one device is
  recorded in the run summary with the target address, the stage and the
  exception's class name only. Its message, arguments and traceback are
  never stored nor logged.

### How it is tested

| Guarantee | Tests |
|-----------|-------|
| Scope rules and check order, over IPv4 and IPv6 | `backend/tests/test_scope.py` |
| No datagram to an out-of-scope address; retries and probes to the same address | `backend/tests/test_scope_enforcement.py`: an agent with a canary community behind an out-of-scope address receives zero datagrams |
| Dependency rules of the table above | `backend/tests/test_architecture.py`: AST rules over every production module, each also run against an offending sample |
| Run start checks before any datagram | `backend/tests/test_discovery_runs.py`: scripted agents count zero requests |
| Out-of-scope neighbour never queried in a whole lab run | `backend/tests/test_discovery_lab.py`: a canary agent behind 203.0.113.10 must receive nothing |
| No secret in clear text, logs, parameters, summaries, queries, reports, snapshots or any table | `test_credential_store.py` and the canary tests in `test_discovery_runs.py` |
| No secret in any API response | `test_api_routes.py`: every route read after a run with a canary community |
| Write-only screens | `frontend/src/pages.test.tsx`: secret fields start empty and are cleared after sending |
| The whole path in Compose | `scripts/stack_test.py` with `docker-compose.lab.yml` |

### What is not covered

- **Python cannot make a class unforgeable.** Reflection (`object.__new__`,
  reading the private token) can still build an `AuthorizedTarget`. The
  claim is "guaranteed by design and verified by automated tests", not
  "impossible".
- **Static analysis has limits.** The architecture tests forbid `importlib`
  and `__import__`, but `getattr` tricks or code generated at run time are
  not seen.
- **Routing is not checked.** The scope is about addresses. If the network
  routes or translates an allowed address to another host, NetScanner
  cannot tell.
- **Whoever has the administrator's session can query real networks.** Since
  the lab-only guard was removed, the scope rules above bound what a run may
  reach, and the session (next section) bounds who may start one.
- **Secrets in memory.** While a device session is open, the decrypted
  credential is in the process memory and inside PySNMP's objects. Python
  strings cannot be wiped.
- **The secret key is in the environment.** Whoever can read the
  containers' environment or the `.env` file can decrypt the stored
  credential. There is no key rotation: after changing
  `NETSCANNER_SECRET_KEY`, the credential is reported as `usable: false` and
  must be entered again.
- **No TLS** between the browser and the web service in the recommended
  local deployment.

## Administrator authentication

From `add-admin-authentication` (RNF-05, RNF-01, RNF-04).

### What is guaranteed

- **One administrator, managed from the server console.** `python -m
  netscanner.admin create` and `reset-password` read the password twice
  without echo, or once from standard input; it is never a command-line
  argument. No route creates or changes the account. The password is stored
  only as an Argon2id hash (RFC 9106 low-memory profile), rehashed on login
  when the parameters are outdated.
- **Every route closed by default.** The `/api` router requires a session for
  every route except `GET /api/health`, `GET /api/status`, `POST
  /api/auth/login` and `POST /api/auth/logout`. A new route added to it is
  protected without further code. Protected responses carry
  `Cache-Control: no-store`.
- **Server-side sessions.** The browser holds a random 32-byte token in the
  `netscanner_session` cookie (`HttpOnly`, `SameSite=Strict`, `Secure` by
  default, `Path=/`, no `Max-Age`); the database holds only its SHA-256. A
  session ends after 8 hours without use, 24 hours after login, on logout or
  on a password reset, which ends every session in the same transaction.
  Each login creates a new session.
- **The same answer whatever was wrong.** An unknown user name, a missing
  account and a wrong password give the same 401 body, and each performs
  exactly one Argon2id verification, against the stored hash or a fixed
  dummy hash.
- **Cross-site requests refused.** `POST`, `PUT`, `PATCH` and `DELETE` need
  `X-NetScanner-Request: 1` and, when `Origin` is sent, an allowed origin:
  `NETSCANNER_PUBLIC_ORIGIN` if set, otherwise `http://localhost:<port>` and
  `http://127.0.0.1:<port>` for the port of `NETSCANNER_WEB_BIND`. Allowed
  origins come from configuration only, never from forwarded headers. With
  `SameSite=Strict` this gives two independent barriers.
- **Guessing limited.** Five failed logins from one source address within
  15 minutes give 429 with `Retry-After`; the account is never locked. The
  source address is the last `X-Forwarded-For` entry, the one nginx appends,
  or the connection address when that entry is missing or invalid. Attempts
  are logged without the password.
- **No insecure cookie across the network by accident.** The API refuses to
  start with `NETSCANNER_SESSION_COOKIE_SECURE=false` unless
  `NETSCANNER_WEB_BIND` is a loopback address.
- **Only nginx reaches the API.** `web` is the only service that publishes a
  host port, and no service uses the host network, in both Compose files.
  The cookie, origin and source address rules above rely on it.

### How it is tested

| Guarantee | Tests |
|-----------|-------|
| Every route outside the public list answers 401 without a session, with `no-store`, and changes nothing | `backend/tests/test_auth.py`: the route enumeration test calls every route of the application; a route it cannot call fails the test and is named |
| Cookie attributes, token stored as a hash, new session per login, idle and absolute expiry, logout | `backend/tests/test_auth.py` |
| One Argon2id verification per login path, similar timing | `backend/tests/test_auth.py`: a counting hasher, and the median of several runs with a generous tolerance |
| Guessing limit and `X-Forwarded-For` parsing (forged first entries, spaces, IPv6, malformed values) | `backend/tests/test_auth.py` |
| Cross-site check, local origins, `NETSCANNER_PUBLIC_ORIGIN`, forwarded headers ignored | `backend/tests/test_auth.py` and `backend/tests/test_auth_settings.py` |
| Console commands, password rules, the password never echoed nor stored in clear | `backend/tests/test_admin_commands.py` (with a canary password over tables, logs and responses) |
| `Secure` off only with a loopback bind address | `backend/tests/test_auth_settings.py` |
| Only `argon2` in `netscanner.auth`; no other module reads the cookie | `backend/tests/test_architecture.py` |
| Only `web` publishes a host port | `backend/tests/test_deployment.py` reads both Compose files; the stack test checks the running stack |
| Real ranges need a session | `backend/tests/test_auth.py`: 198.51.100.0/24 answers 401 without a session and is saved with one |
| Login screen, generic failure, 429 time, no-account message, return to the page after expiry, logout | `frontend/src/login.test.tsx` |
| The whole sequence through the web port | `scripts/stack_test.py`: 401 before login, login, cross-site refusal, a lab run, logout, 401 again |

### What is not covered

- **No TLS in the application.** Credentials and cookies travel in clear over
  HTTP. Beyond the local machine a reverse proxy with TLS is required; the
  `Secure` cookie makes plain HTTP across the network fail instead of
  working insecurely.
- **Whether the browser keeps a `Secure` cookie on `http://localhost`.**
  Current Chromium and Firefox do and Safari does not; it is checked by hand
  in the author's browser (task 7.3 of the change).
- **The bind address check is about configuration.** A hand-edited `ports:`
  in the Compose file is not detected at start; the static deployment test
  and the stack test check the files and the running stack.
- **Rate limiting behind an outer proxy.** The last `X-Forwarded-For` entry is
  then the proxy's address, so every client shares one window: an attacker
  can delay the administrator's login for up to 15 minutes. Trusting an
  outer proxy's header is deferred until such a proxy is used.
- **Several addresses can each try five times per window.** Accepted for a
  single-administrator tool; Argon2id keeps each attempt expensive.
- **Idle expiry can be up to a minute late**, because the last use is written
  at most once a minute.
- **One administrator, no recovery through the network.** A lost password is
  reset from the server console, by design.
