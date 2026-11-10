# Tasks

Prerequisite: `add-snmp-client-and-lab` archived. Use only lab data. Do not
read, list or copy anything under `local/` or outside the repository.

## 1. Data model

- [x] 1.1 Migration `0004` per the Migration Plan of the design, with upgrade and downgrade tests against PostgreSQL
- [x] 1.2 `RunParameters`: add `follow_ip_mac` (default false) and `limits` (default none); test that parameters stored by earlier runs still parse and that unknown fields are still rejected
- [x] 1.3 `record_run_device` accepts `skip_reason` and `found_from_device_id`; querying an address clears its reason; tests for the reason vocabulary and the update rule of design D8

## 2. Scope

- [x] 2.1 `netscanner.scope`: `ScopePolicy`, `AuthorizedTarget` with the private token, `Rejection`, special address rules, check order of design D2; property-style tests over IPv4 and IPv6 (exclusion wins, deny by default, loopback only when allowed, multicast, limited broadcast, unspecified and link-local refused; network and broadcast addresses of allowed ranges of /30 or shorter refused, /31 and /32 fully usable)
- [x] 2.2 Lab guard of design D6 applied when settings are saved and when the policy is built (`scope_not_allowed`); test that a non-lab range is refused; the removal condition written into `openspec/config.yaml` for `add-admin-authentication`
- [x] 2.3 Settings ceilings of design D6 with validation and `.env.example` entries, marked as hypotheses; limits copied into `RunParameters` at run creation and checked again at run start

## 3. Credentials

- [x] 3.0 `NETSCANNER_SECRET_KEY` of at least 32 characters, with a test and the generation command in `.env.example` (design D5)
- [x] 3.1 `netscanner.credential_store`: encryption and `key_id` per design D5 (`cryptography` is already a dependency), write-only service, `CredentialResolver` registering secrets with the log-masking filter before returning, deletion of inactive rows not referenced by active runs
- [x] 3.2 Tests: canary community and v3 keys absent from every table in clear text; after changing `NETSCANNER_SECRET_KEY` the endpoint reports `usable: false` without calling the decryption helper, and a run fails with `credential_unreadable` before any datagram; corrupted token with matching `key_id`; replacement during a run keeps the run's credential

## 4. SNMP client adaptation

- [x] 4.1 Replace `Target` with `AuthorizedTarget` in the public client API; the adapter resolves the credential per device session and re-checks the policy before every datagram (design D2)
- [x] 4.2 Optional `endpoint_for` argument of design D3; composition roots never pass it
- [x] 4.3 Retries moved from PySNMP into the walker (transport with `retries=0`) and datagram budget of design D6: `get` and `walk_table` accept the remaining budget, count every attempt including retries and probes, send a request only when all its attempts (and, before the first rows, the probe's) are covered, and end a walk with rows as `partial`/`request_limit` otherwise; `request_limit` added to the client's and the store's error categories; contract tests for both implementations, including retry counts and timing of a silent agent (about `timeout × (retries + 1)`)
- [x] 4.4 Add the CDP cache table to the table registry, and the LLDP management address table if not already present
- [x] 4.5 Architecture tests of design D1, each naming the offending module on failure
- [x] 4.6 Tests: retries and probes go to the same address; an out-of-scope address mapped to a scripted agent with a canary community receives zero datagrams

## 5. Discovery

- [x] 5.1 Test fixture of design D4 (one snmpsim per lab device, scripted agent behind the same mapping)
- [x] 5.2 Engine per design D8: levels, candidate order and reasons, limits, per-device order of tables and fallbacks, error isolation per device
- [x] 5.3 Result mapping per design D9; CDP parsing in its own module
- [x] 5.4 Collector loop per design D7, with interrupted-run handling and `FOR UPDATE SKIP LOCKED`
- [x] 5.5 Tests with the scripted agent: `noSuchObject` on `entPhysicalTable` leads to `sysDescr` inference; CDP neighbour candidate; a device that stops answering mid-run gives `partial` and the run continues; error status on the system group gives `query_error`; SNMPv3 report gives `auth_failed` for that device only; empty scope fails the run before any datagram
- [x] 5.6 Lab tests: the end-to-end run of the `device-discovery` spec; `max_depth` 0; exclusion of 10.99.0.3; IP-MAC following on with a small timeout giving `already_known` and `no_response`; `max_candidates` reached with `candidates_not_recorded` in the summary; `max_devices` and `max_datagrams` reached giving `limit_reached`; every recorded candidate has a device or exactly one reason; run report counts match stored records
- [x] 5.7 Canary test of a whole run, including timeouts and errors, over logs, API responses, run parameters, queries and snapshots

## 6. API

- [x] 6.1 Routes of design D10 with Pydantic schemas; 409 for a second active run; 422 with field and reason without echoing values
- [x] 6.2 Tests for every route, including the device detail of `srx-01` with the inferred model and observed interfaces, and pagination of the device list

## 7. Web interface

- [x] 7.1 Router, layout with the lab mode banner, Settings, Discovery, Devices and Device pages per design D11, in Spanish and English
- [x] 7.2 `Provenance` component with badge, relative age, stale mark and details on demand
- [x] 7.3 Component tests: secret fields never prefilled, validation message next to its field, start button disabled while a run is active, inferred and stale values marked, banner present on every page

## 8. Deployment and documentation

- [x] 8.1 Stack test with the lab override file `docker-compose.lab.yml` (use exactly the commands and names that `add-snmp-client-and-lab` delivered), settings and credential through the API, a run until completed, three devices in the list
- [x] 8.2 `docs/architecture.md` section on scope enforcement and credential handling (what is guaranteed, how it is tested, what is not covered)
- [x] 8.3 `CHANGELOG.md` entry, and the planned change sequence in `openspec/config.yaml` updated (scope and credentials are part of this change)
- [x] 8.4 Full suite on Linux against PostgreSQL and the lab, hooks, stack test and `openspec validate --strict`; all green
