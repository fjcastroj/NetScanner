# Proposal

## Why

With the store and the SNMP client in place, NetScanner can now do what the
second delivery must show: start from a seed, discover devices within an
authorised scope, store what it learns with its provenance and show it in a
minimal web interface. Credentials and scope are not separate features but
security preconditions of discovery (RF-01, RNF-01, RNF-03), so they are
part of this change: no discovery code exists without them.

## What Changes

- Scope policy: allowed and excluded ranges, seeds inside the scope, deny
  by default, frozen per run, and an `AuthorizedTarget` that is the only way
  to reach the SNMP transport, enforced by architecture tests.
- Operational limits per run (candidates recorded, devices queried, SNMP
  datagrams sent, depth), set below ceilings fixed on the server, instead of
  a limit on the size of the authorised ranges. Concurrency stays bounded by
  the SNMP client's server-side setting and is not configurable from the
  interface.
- One SNMP credential set, encrypted at rest, write-only through the API,
  decrypted only by the SNMP adapter when a session needs it.
- A lab-only guard: until authentication exists (`add-admin-authentication`),
  the allowed ranges must be inside the lab range.
- Basic discovery run by the collector: seed, identification, system group,
  interfaces, addresses, LLDP and CDP neighbours, IP-MAC tables, candidates
  from neighbours and IP-MAC entries, depth limit, and a recorded reason for
  every candidate that was not queried.
- A minimal API and web interface: configuration, start a run, follow its
  progress, list devices and see a device with its interfaces, each value
  with its origin and age.

## Requirements covered

- RF-01 [E] credentials (one set, write-only).
- RF-02 [E] seeds, allowed ranges, exclusions, maximum depth.
- RF-03 [E] system group; RF-04 [E] interfaces.
- RF-05 [E] discovery through LLDP, CDP and IP-MAC tables within the scope.
- RF-11 [E] device inventory (basic list and detail).
- RF-29 [E] origin and age shown in the interface.
- RF-12 [E] IP-MAC collection only (its use for end hosts is iteration 2).
- RNF-01 [E] credentials encrypted and never exposed; RNF-03 [E] queries only
  within the authorised scope; RNF-06 [E] operational limits.
- RF-08 [D] rediscovery and RF-10 [O] scheduled discovery: out of scope.

## Capabilities

### New Capabilities

- `snmp-scope`: which addresses may be queried, how that is enforced below
  every SNMP use, and the operational limits of a run.
- `snmp-credentials`: storage and use of the SNMP credential set.
- `device-discovery`: how a discovery run proceeds and what it records.
- `inventory-api`: the HTTP API for configuration, runs and inventory.

### Modified Capabilities

- `web-ui`: configuration, discovery and inventory screens.
- `snmp-client`: retries performed by the walker, a datagram budget per call, and the datagram count reported in results.
- `snmp-lab`: `lab-sw-01` gains a small synthetic `ipNetToPhysicalTable`
  (entries for `srx-01`, `lab-sw-02` and the silent address 10.99.0.9),
  produced by the generator, so that IP-MAC following can reach a silent lab
  address in tests.
- `network-observations`: a narrow Juniper model rule (`netscanner.vendors.juniper`)
  for `sysDescr` values without the generic "model" keyword, selected by the
  Juniper enterprise number and based only on the format of the `srx-01` capture.

## Out of Scope

- FDB, end-host location and topology (iteration 2 and 3).
- Interface counter polling (`add-interface-polling`).
- Authentication (`add-admin-authentication`), which lifts the lab-only
  guard only once its tests show that every administrative route refuses
  requests without a session; rediscovery of a single device and scheduled
  discovery.
- Several credential sets or credentials per range.

## Impact

- Migration `0004` (`0003` is taken by `add-snmp-client-and-lab`): `snmp_credentials`, `discovery_settings`,
  `run_devices.skip_reason` and `run_devices.found_from_device_id`, and a
  partial unique index allowing one active discovery run.
- `netscanner.snmp`: `AuthorizedTarget` replaces the plain `Target` of
  `add-snmp-client-and-lab` in the public API.
- New packages `netscanner.scope`, `netscanner.credential_store`,
  `netscanner.discovery`, `netscanner.vendors`; API routes; frontend screens.
- Lab data: `lab-sw-01.snmprec` regenerated with its IP-MAC table; manifest
  and lab README updated.
- New settings for operational limits, listed in `.env.example`.
