# Design

## Context

The store (`add-data-provenance-model`) already persists runs, queries, run
devices, identity, observations with provenance, staleness (RF-30) and run
reports. `add-snmp-client-and-lab` adds a read-only SNMP client with reliable
outcomes, the credential models, the lab (`srx-01` real and anonymised,
`lab-sw-01` and `lab-sw-02` synthetic, 10.99.0.9 silent, 203.0.113.10
external) and the scripted agent. What is missing is the part that decides
**what may be queried**, **with which credential**, **in which order**, and
how the results reach the store and the user.

Facts from the code that shape this design:

| Fact | Consequence |
|------|-------------|
| `run_devices` records `reached_via`, `depth`, `answered`, but no reason for a candidate not queried | Migration 0004 adds `skip_reason` and `found_from_device_id` |
| `RunParameters` forbids unknown fields and already holds seeds, ranges, exclusions, `max_depth` and `credential_id` | New fields with defaults (`follow_ip_mac`, `limits`), so older runs still parse |
| `resolve_device` makes the queried address a management address and matches by chassis when given | Identification runs after the system group and `lldpLocalSystemData` |
| The client's `Target` carries the decrypted credential (D1/D7 of the previous change) | Replaced by `AuthorizedTarget` with a credential identifier; decryption moves into the adapter |
| `srx-01` has no LLDP neighbours, 20 own addresses in 10.99.0.0/24 and 40 IP-MAC entries there, one of them its own address | The lab run uses two seeds; IP-MAC following is tested separately and with low timeouts |
| The lab has no CDP data and snmpsim never answers `noSuchObject` | CDP and `not_available` are tested with the scripted agent |
| `NETSCANNER_WEB_BIND` can be changed by the operator | The protection before authentication is the lab-only scope guard, not the bind address |
| `collection_runs` has `summary` (JSONB) and `error_category` | Limits reached go in `summary`; run failure reasons are new error categories |
| The lab is started with the override file `docker-compose.lab.yml` (snmp-lab spec) | This change uses that file and its commands, not a Compose profile |
| The credential models live in `netscanner.snmp.credentials`; PySNMP only in `netscanner.snmp.pysnmp_client` | Credential storage is a separate package, `netscanner.credential_store`, to avoid two modules called "credentials" |
| PySNMP performs the retries itself (`UdpTransportTarget(retries=...)`) and `request_count` counts logical requests | Datagrams cannot be counted today; retries move into the library-independent walker (D6) |
| The store refuses an error category on `no_response` (`QueryRecord` rules) | The datagram budget must never cut a request between attempts (D6) |
| `cryptography` is already a backend dependency (SNMPv3 privacy) | No new dependency for encryption |

## Goals / Non-Goals

**Goals:** a discovery run that can only reach authorised addresses, uses a
credential that never leaves the adapter in clear, records why every
candidate was or was not queried, and shows the result with its provenance.

**Non-Goals:** FDB, end hosts, topology, polling, authentication,
rediscovery of a single device, scheduled runs, cancelling a run, several
credentials, key rotation.

## Decisions

### D1. Packages and dependency direction — Decision
- `netscanner.scope`: pure code (no I/O). `ScopePolicy`, `AuthorizedTarget`,
  `Rejection`, special address rules, the lab guard.
- `netscanner.credential_store`: credential table access, encryption, the
  write-only service used by the API, and `CredentialResolver` used by the
  SNMP adapter only.
- `netscanner.snmp`: public client API; `netscanner.snmp.pysnmp_client` is the only
  module that imports PySNMP.
- `netscanner.discovery`: the run engine, candidate extraction, mapping of
  `TableResult` to store calls; CDP parsing in its own module (RNF-08).
- `netscanner.collector`: loop that claims and runs pending runs.
- `netscanner.vendors`: vendor rules, one module per vendor (RNF-08), pure
  code. Only `netscanner.vendors.juniper` exists: a `sysDescr` model rule
  selected by enterprise 2636, based only on the format of the `srx-01`
  capture, used by the store's model inference after ENTITY-MIB and the
  generic pattern. Fortinet has no capture and no rule.
- `netscanner.api.routes`: configuration, runs, inventory.

Architecture tests (AST, no new dependency, same style as the read-only
test) inspect **every module of the production package** `netscanner` and
fail, naming the module, when:
- `pysnmp` (or any of its submodules) is imported outside
  `netscanner.snmp.pysnmp_client`, or `netscanner.snmp.pysnmp_client` is imported outside
  `netscanner.snmp`;
- `AuthorizedTarget` is called outside `netscanner.scope`;
- `endpoint_for` or `v3_context` (D3) is passed anywhere in production code,
  or the collector's test-only `client` argument (D7) is passed to
  `run_collector`;
- `CredentialResolver.resolve` or the decryption helper is referenced outside
  `netscanner.snmp` and `netscanner.credential_store`.
Static analysis cannot see dynamic imports; the tests also forbid
`importlib` and `__import__` in production code.

### D2. Authorised targets — Decision
`ScopePolicy.from_parameters(run_parameters)` builds an immutable policy
(allowed and excluded networks, lab guard applied). `policy.authorize(address,
port=161)` returns either an `AuthorizedTarget(address, port,
credential_id, policy)` or a `Rejection(reason)` with reason
`special_address`, `excluded` or `out_of_scope`, checked in that order.
`AuthorizedTarget.__init__` requires a module-private token held by
`netscanner.scope`, so a direct construction raises. The target keeps a
reference to the run's frozen policy, never to the current settings.

The client API becomes `get(target: AuthorizedTarget, ...)` and
`walk_table(target: AuthorizedTarget, ...)`. Before every datagram,
including retries and probes, the adapter calls
`target.policy.contains(target.address)` again (defence in depth). The
address sent is always `target.address`; the client has no parameter that
takes another one.

Python cannot make a class truly unforgeable. The claim for the memoria is
"guaranteed by design and verified by automated tests", not "impossible".

Alternative considered: a check inside discovery only. Discarded, because
any later caller of the client (polling, rediscovery) would have to remember
it.

### D3. Test transport mapping — Decision
The adapter takes an optional `endpoint_for(address, port) -> (host, port)`
argument, identity by default. The composition roots (collector, API) never
pass it; tests pass a mapping from lab addresses to loopback ports. The
scope check uses the logical address before the mapping, so the mapping
cannot widen the scope. No setting can enable it. A second test-only
argument, `v3_context` (empty by default, as real devices use), sets the
SNMPv3 context name because snmpsim serves SNMPv3 only under the context
named after its data file; composition roots never pass it either.

### D4. Lab in tests — Decision
A fixture starts one snmpsim process per lab device on its own loopback
port, each with its data file named after the lab community, so that one
credential serves the whole lab as in Compose. It extends the fixture of the
previous change instead of replacing it. CDP, `noSuchObject`, canary
credentials and a device that stops answering mid-run use the scripted
agent behind the same mapping.

### D5. Credentials — Decision
Table `snmp_credentials`: `id`, `version` (`v2c`/`v3`), v3 user, level and
protocols (non-secret), `secret` (`bytea`, Fernet token of a JSON object with
the secret fields), `key_id`, `created_at`, `active`. Saving inserts a new row and
makes it the only active one in one transaction; inactive rows are deleted
when no pending or running run references them. Runs store only
`credential_id`.

Keys: HKDF-SHA256 over `NETSCANNER_SECRET_KEY` (already required by the
settings) with two fixed `info` labels, one giving the 32-byte Fernet key and
the other a 16-byte value stored hex-encoded as `key_id`. The identifier
does not reveal the encryption key, provided `NETSCANNER_SECRET_KEY` has
enough entropy, and lets
the API report
`usable: false` by comparing identifiers, without decrypting anything.
`cryptography` is already a backend dependency. The settings currently
reject only an empty or placeholder secret key; this change also requires at
least 32 characters, and `.env.example` shows how to generate one with
`secrets.token_urlsafe(32)`. Length is a minimum, not proof of entropy, so
the documentation says the key must be generated, not chosen.

Failures: a `key_id` mismatch is detected at run start (the run fails with
`credential_unreadable` before any datagram); a token that fails to decrypt
with a matching identifier (corruption) raises `CredentialUnreadable` in the
adapter and the run fails the same way. An SNMPv3 report from one device
(unknown user, wrong digest) affects only that device: reason
`auth_failed`, the counter kept in the query's `v3_report:<counter>`
category.

`CredentialResolver.resolve(credential_id)` returns the existing
`SnmpV2cCredential`/`SnmpV3Credential` models of the previous change. It
registers the secret values with the log-masking filter **before
returning**, inside the same function that decrypts, so no later exception
can carry an unmasked value. The adapter calls it when it opens a device
session and drops the object when the session ends.

Alternative: pgcrypto in the database. Discarded, because the key would
travel in SQL statements and appear in database logs.

### D6. Settings and limits — Decision
Table `discovery_settings` with one row: seeds, allowed ranges, exclusions,
`max_depth`, `follow_ip_mac` (default false) and limits
(`max_candidates`, `max_devices`, `max_datagrams`). Concurrency is not among
them: it stays bounded by `NETSCANNER_SNMP_MAX_DEVICES` of the client and is
not configurable from the interface. Ceilings come from the environment:

| Setting | Default ceiling (Hypothesis) |
|---------|------------------------------|
| `NETSCANNER_DISCOVERY_MAX_DEPTH` | 5 (at most 32, the store limit) |
| `NETSCANNER_DISCOVERY_MAX_CANDIDATES` | 4096 |
| `NETSCANNER_DISCOVERY_MAX_DEVICES` | 256 |
| `NETSCANNER_DISCOVERY_MAX_DATAGRAMS` | 50000 |

The datagram ceiling is an estimate from the lab: the whole `srx-01`
capture holds about 15,000 values, roughly 600 GETBULK requests with 25
repetitions, so 50000 covers about eighty devices of that size. It is
reviewed after the first real run.

Freezing: saved value → validated against the ceiling → copied into
`RunParameters.limits` when the run is created. The run uses only the copy;
the check is repeated at run start, because the database can be edited
outside the API: a run whose stored limits exceed the current ceilings
fails with `limits_not_allowed` before any datagram. So does a discovery
run whose parameters carry no frozen limits (`limits` is optional only so
that parameters of earlier runs still parse): the API always freezes them,
and the ceilings are never used in their place.

Counters, exactly:
- **Candidate**: a distinct address recorded in `run_devices` for the run,
  seeds included. At `max_candidates` no further candidate is registered
  or queued; the summary stores
  `limits_reached: ["max_candidates"]` and `candidates_not_recorded`, the
  number of further distinct addresses in rows already received, obtained
  by going through and deduplicating those rows in memory (no extra
  queries or writes). Unread tables are not counted.
- **Device queried**: a candidate for which the first system group request
  was sent. At `max_devices`, recorded candidates not yet queried get
  `limit_reached`.
- **Datagram**: every SNMP request datagram sent, including retries and
  probes. To count them, retries move from PySNMP into the walker, which is
  library-independent: the transport is created with `retries=0` and the
  walker repeats a timed-out request up to `NETSCANNER_SNMP_RETRIES` times,
  so both implementations behave the same and the contract suite covers it.
  The run hands the client its remaining budget with each call, and a
  request is sent only when the budget covers all its attempts
  (`retries + 1`); until a walk has received rows, the attempts of its
  probe must be covered as well. A request is therefore never cut between
  attempts and a walk never ends unclassified.
  - Budget too small before an operation starts: no call is made and no
    query is recorded. A candidate whose system group was not sent gets
    `limit_reached`; a device already started stops before its next table.
  - Budget too small for the next request of a walk that already has rows:
    the walk ends as `partial` with category `request_limit`.
  - Budget too small for the next request of a walk that has no rows yet,
    because one of its subtrees needs more requests than were reserved (for
    example columns outside the registry before any registry row): the walk
    ends as `error` with category `request_limit`.
  In every case the device's remaining tables are not queried, and
  recorded candidates not yet queried get `limit_reached`.

  While a walk has no rows, the client reserves one request per subtree
  still to walk plus the probe. The run's budget is one shared pool, so
  devices of a level can run concurrently without exceeding it: each
  request reserves its attempts before it is sent and returns the unused
  ones afterwards.

  Two figures are kept. **Reported datagrams** are what the walker observes
  and what each result reports. **Budget consumed** adds one datagram per
  SNMPv3 call for the library's engine discovery, which the walker cannot
  see, so the limit covers the real traffic. The run summary shows both,
  with a short note explaining the difference.

The lab guard is a constant list (10.99.0.0/24, 127.0.0.0/8, ::1/128)
checked when settings are saved and in `ScopePolicy` construction, which
fails the run with `scope_not_allowed`. A test asserts that a non-lab range
is refused, so removing the guard means changing a test visibly.
`add-admin-authentication` may remove it only together with end-to-end
tests showing that settings, credential and run routes answer 401 without a
session; that condition is written into `openspec/config.yaml`.

### D7. Run lifecycle — Decision
The API creates the run as `pending` with the parameters copied from the
settings. A partial unique index on `collection_runs` over
`status IN ('pending','running')` for kinds `discovery` and `rediscovery`
makes a second request fail atomically; the API answers 409.

The collector marks interrupted runs at startup, then every
`NETSCANNER_COLLECTOR_POLL_INTERVAL` seconds (default 2) claims the oldest
pending run with `FOR UPDATE SKIP LOCKED`, starts it, runs it and closes it.
Progress is computed when read, from `run_devices` and `snmp_queries`; no
counters are stored. A run fails with one of the new error categories
`empty_scope`, `scope_not_allowed`, `limits_not_allowed` (limits above the
current ceilings, or no frozen limits; D6), `credential_unreadable` or
`database_error`, added to the store's vocabulary. The collector obtains its SNMP client through the factory
`netscanner.snmp.create_client`, the only entry point to the client outside
`netscanner.snmp`; the API only creates pending runs and never obtains a
client. `run_collector` takes a keyword-only `client` argument for tests,
so they can pass a client with the test mapping of D3; the entry point never
passes it, which the D1 tests check.

### D8. Discovery algorithm — Decision
Breadth first, one depth level at a time. Level 0 is the seeds. For each
candidate address, in this order:

1. Already in this run (as a target, or as an address read from a device
   reached in this run): `already_known`.
2. `policy.authorize`: `special_address`, `excluded`, `out_of_scope`.
3. Depth above `max_depth`: `max_depth`.
4. A limit reached: `limit_reached`, and the summary notes which.
5. Query the system group. Every attempt timed out: `no_response`. SNMPv3
   report: `auth_failed`. Error status, undecodable answer or client
   failure: `query_error`. The technical category stays in the query.

Devices of a level run concurrently under the client's existing device
limit. Per device, in order: system group (GET) and `lldpLocalSystemData`
→ `resolve_device` → address tables (`ipAddressTable`, `ipAddrTable` if the
first is `not_available` or `empty`) → `ifTable`, `ifXTable` →
`entPhysicalTable` model columns (`not_available` or no chassis row →
`infer_model_from_sysdescr`) → LLDP local ports (`map_local_ports`), remote
table, management addresses → CDP cache → `ipNetToPhysicalTable`, and
`ipNetToMediaTable` if the first is `not_available` or `empty`.

A device known from earlier runs is queried again when reached; this is
what keeps its data current. `already_known` applies only within a run.

Candidates for the next level: LLDP management addresses, CDP addresses of
type IP and, if enabled, IP-MAC entries whose type is not `invalid`.
Because levels are processed in order, an address is always first found at
its lowest depth, so a reason never needs to change.

Limits follow D6. An exception while processing one device after its
system group answered stops that device only: the device keeps what was
stored, and the run continues and fails only for the categories of D7.
The store cannot change a query already recorded, so the error is listed
in the run summary under `device_errors`, one entry per device with its
target address, a stable stage name (the logical table, such as
`IF-MIB::ifTable`, or the operation, such as `identification` or
`model_inference`) and the exception's class name. The exception's message,
`repr`, arguments and traceback are never stored nor logged, because they
may carry values read from the device; a test raises an exception whose
message holds a canary and checks logs, summary, report and every table.

### D9. Mapping results to the store — Decision
From each `TableResult`: a complete walk passes every expected column, with
`None` for a column missing in a row (absent); a partial walk passes only
the columns received (the rest not retrieved); every received row is passed
with `confirms_row=True`. Outcomes `empty`, `not_available`, `no_response`
and `error` are recorded on the query and store nothing. This is the
contract of `network-observations`; discovery adds no rule of its own.

### D10. API — Decision
Routers under `/api`: `GET/PUT /settings/discovery`,
`GET/PUT /settings/credential` (PUT body write-only, GET metadata and
`usable`), `POST/GET /runs`, `GET /runs/{id}`, `GET /devices`
(limit/offset, default 100), `GET /devices/{id}`, and `GET /status` with
`lab_mode: true`. Reads use `netscanner.store.reading`; responses never
include a field of the credential's secret part, checked by the canary
test. Validation errors give field and reason, never the submitted value.

### D11. Web interface — Decision
React Router (pinned) with four pages: Settings, Discovery, Devices, Device.
Polling with `fetch` every 2 s while a run is pending or running; no state
library. A `Provenance` component shows the observed/inferred badge, the age
as relative time through i18n and the stale mark, and opens method, source
and evidence on demand. The lab mode banner is part of the layout, so no
page can omit it. Spanish and English.

## Risks / Trade-offs

- **Forged target by future code.** Mitigated by D1 tests and the adapter's
  re-check; documented as a design guarantee.
- **Size of the change.** Migration, security, engine, collector, API and
  four screens. No scope is added while applying it.
- **Slow runs on silent addresses.** Each silent candidate costs timeout ×
  (retries + 1). IP-MAC following is off by default, and the lab test with it
  on uses a small timeout and candidate limit.
- **Lab guard bypassed through the database.** Checked again at run start.
- **Credential kept while a run uses it.** Accepted; the row is encrypted
  and deleted afterwards.
- **One snmpsim process per device in tests.** Slower start; accepted for
  realism (one credential, distinct addresses).

## Migration Plan

Migration `0004` (`0003_probe_value_indicator` belongs to `add-snmp-client-and-lab`): `snmp_credentials`; `discovery_settings` with its single
row; `run_devices.skip_reason` (nullable, checked against the reason
vocabulary of the `device-discovery` spec) and `run_devices.found_from_device_id` (nullable foreign key);
the partial unique index on active runs. Downgrade drops them.

## Open Questions

- Whether the switch's real management addresses come over LLDP as IPv4
  (subtype 1) or only as MAC-based chassis ids. Answered by the first real
  run; the lab covers IPv4.
- Ceiling values (D6), reviewed with the evaluation.
- PySNMP creates its engine per call, so SNMPv3 engine discovery repeats on
  every walk; reusing the engine per device session is deferred.
- Per-query SNMPv3 contexts (for example VLAN contexts for bridge tables)
  are deferred to iteration 2, as a parameter of each query rather than of
  the credential.
