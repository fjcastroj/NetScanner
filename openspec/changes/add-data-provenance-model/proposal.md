# Proposal

## Why

The key difference of NetScanner is that every datum says where it came from,
when it was obtained and whether it was observed or inferred (OE1). If
discovery code is written first, provenance ends up bolted on and partial.
This change defines the data model and the persistence rules before any SNMP
code exists, so that discovery, inventory, topology and traffic only have to
follow them. It also records the outcome of every query (RF-06) and the start
and end of every collection run, which the evaluation (OE6) needs.

## What Changes

- Provenance rules for every stored datum: source device, MIB object or
  protocol, collection run, first and last time seen, origin (observed or
  inferred), and method and evidence for inferred data.
- A precise definition of observed versus inferred, with examples, used by
  every later change; observed derivations keep their sources, and device
  identity is an explicit, inferred resolution with recorded conflicts.
- Records of collection runs (discovery and polling) and of every individual
  query with its outcome: ok, empty, not available, no response, partial or
  error.
- Persistence for the entities that iteration 1 needs: devices and their
  identity resolutions, device addresses, interfaces, LLDP/CDP neighbour
  entries and IP-MAC entries, with precise and order-independent rules for
  first and last seen, presence and absence.
- Records of the devices reached by each run and, on request, evaluation
  snapshots, so that any run can be evaluated without a full history.
- Staleness computed when data is read (RF-30), never by deleting data.
- Data minimisation: contact, location and serial numbers are never stored,
  and evidence keeps only the fragments a method used.
- Database migration and a persistence layer with tests against PostgreSQL.
  No SNMP access, no HTTP endpoints and no UI in this change.

## Requirements covered

- RF-28 [E] provenance of every datum: fully, for the entities in scope.
- RF-06 [E] distinguish and store query outcomes: storage side (the SNMP
  client that detects the outcomes comes in the next change).
- RF-30 [D] staleness: computed at read time; it costs almost nothing once
  last-seen times exist and avoids a later migration (delivery rules
  exception, see design D6).
- RF-29 [E] origin and age: provided by the persistence layer for the UI
  that comes later.
- OE1 (data model), OE6 (records needed to compute the evaluation measures).

## Capabilities

### New Capabilities

- `data-provenance`: the rules every stored datum follows: origin, time,
  source, observed versus inferred, evidence and staleness.
- `collection-records`: collection runs and the outcome of each query.
- `network-observations`: storage of devices, device addresses, interfaces,
  neighbour entries and IP-MAC entries, with device identity rules.

### Modified Capabilities

None.

## Out of Scope

- SNMP access, credentials, discovery logic and scope checks: later changes.
- Interface counter samples and rates (RF-07): `add-interface-polling`
  defines its time-series table following these rules.
- FDB entries, end hosts, links and sFlow data: iterations 2 to 4, which
  extend this model with the same rules.
- History of every change of every datum (RF-17 [D]): only first and last
  seen times are kept now.
- HTTP endpoints and screens.

## Impact

- New migration with the first business tables in PostgreSQL.
- New persistence package in the backend used by the collector and the API.
- One new setting for the staleness period, added to `.env.example`.
