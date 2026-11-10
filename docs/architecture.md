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
- **Lab-only guard.** Until `add-admin-authentication`, allowed ranges must
  be inside 10.99.0.0/24 or loopback. This is checked when settings are
  saved and again when a run starts (`scope_not_allowed`).
- **Checks before any datagram.** A run fails before sending anything when
  its scope is empty (`empty_scope`), outside the lab (`scope_not_allowed`),
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
- **No authentication yet.** Anyone who can reach the web port can replace
  the credential (but not read it), change the settings within the lab
  ranges and start runs. The recommended deployment binds the web service
  to the local host. That is a deployment recommendation, not a guarantee:
  the lab-only guard is what protects real networks until
  `add-admin-authentication`.
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
