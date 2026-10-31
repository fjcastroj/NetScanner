# Data provenance

Every datum NetScanner stores says where it came from, when it was seen and
whether it was **observed** or **inferred**. Inferences are never presented
as facts. This page describes the rules the persistence layer
(`backend/src/netscanner/store/`) enforces. They are specified in the
`data-provenance`, `collection-records` and `network-observations` specs and
decided in the design of `add-data-provenance-model`.

## Observed versus inferred

The rule is whether a standard guarantees the result. A datum is
**observed** when it was read from a device, or derived from read values by a
rule that a standard or MIB definition guarantees: decoding, unit conversion
or a cross-reference defined by the MIB. Anything that depends on a heuristic,
or on an assumption no standard guarantees, is **inferred**.

| Datum | Origin | Why |
|-------|--------|-----|
| Values read from any MIB object, decoded | observed | read directly |
| LLDP chassis identifier and subtype | observed | read directly; says nothing about stability or uniqueness |
| `sysObjectID` and its enterprise number | observed | read directly |
| Speed from `ifHighSpeed` when `ifSpeed` is saturated | observed, with sources | rule in IF-MIB |
| IP-MAC entry to interface via `ipNetToPhysicalIfIndex` | observed, with sources | MIB cross-reference |
| Bridge port to `ifIndex` via `dot1dBasePortIfIndex` (iteration 2) | observed, with sources | MIB cross-reference |
| LLDP local port to interface when the port id subtype is interfaceName and equals `ifName` | observed, with sources | 802.1AB subtype definition |
| Vendor name from the enterprise number | inferred | the enterprise owns the agent's OID, not necessarily the hardware (OEM, generic agents) |
| Device identity, by chassis identifier or by address | inferred | no standard guarantees stable, unique chassis identifiers (H3) or addresses |
| LLDP local port assumed equal to `ifIndex` | inferred | not guaranteed by 802.1AB |
| LLDP local port matched by description | inferred | heuristic |
| Model or version parsed from `sysDescr` | inferred | free text |
| Links from FDB, end-host location "probable" (later) | inferred | heuristic |

An observed datum derived from more than one query records its **method and
sources**. An inferred datum records its **method and evidence**, with a
snapshot of the values it used.

## Provenance by reference to the query

Every SNMP query is stored in `snmp_queries` with its run, target address,
device, MIB object, operation, outcome, indicator or error category, row and
rejected counts, request count, start time and duration. A datum does not
repeat these fields. It points to the query that first produced it and to the
one that last confirmed it.

The database enforces that a datum belongs to the device of its queries.
`snmp_queries` has a unique key on `(id, device_id)`, and every observation
table references its queries through the composite foreign keys
`(<g>_first_query_id, device_id)`, `(<g>_last_query_id, device_id)` and
`(<g>_last_complete_query_id, device_id)`. A query gets its device as soon as
the device is resolved, and before anything is stored from it. Queries are
never deleted while data points to them.

## Provenance groups and carried fields

Fields of one record that come from different queries, or that have
different origins, have their own provenance. A **group** is a set of columns
with a common prefix:

`<g>_origin`, `<g>_method`, `<g>_evidence`, `<g>_first_seen_at`,
`<g>_first_query_id`, `<g>_last_seen_at`, `<g>_last_query_id`,
`<g>_last_complete_query_id` and `<g>_carried`.

Tables with a single group use the names without a prefix. One helper,
`provenance_group()` in `store/groups.py`, generates the columns, checks and
foreign keys, so no table can forget them. Its check constraints are:

- a group is either fully set (origin, first and last times and queries) or
  completely empty;
- an inferred group needs a method and evidence with at least one snapshot;
- an observed group may have a method and sources, and evidence always needs a
  method;
- the last seen time is not earlier than the first.

| Table | Groups |
|-------|--------|
| `devices` | `system` (system group and enterprise number), `chassis` (LLDP chassis identifier), `vendor` (inferred vendor name), `model` (model and software version) |
| `interfaces` | `base` (`ifTable`), `ext` (`ifXTable`), `speed` (observed derivation with sources from both tables) |
| `neighbor_entries` | `entry` (`lldpRemTable` or CDP cache), `man_addr` (`lldpRemManAddrTable`), `local_map` (mapping to a local interface, with its own verification times and queries, plus a failure reason) |
| `device_addresses`, `ip_mac_entries`, `identity_resolutions` | one group each |

### Storing a datum again

Queries are ordered by `(started_at, id)`, so two queries with the same start
time have a deterministic order. For each group, storing a query's result:

- moves the first seen time and first query together, and only to an earlier
  query;
- moves the last seen time, last query, origin, method, evidence and values
  together, and only to a later (or the same) query. A late result from an
  older query leaves the values unchanged;
- moves `last_complete_query_id` to a complete query that is later than (or
  the same as) the stored one;
- never touches groups the query does not cover.

**Input contract for callers.** A field omitted from the values of an update
(or from an input row) was **not retrieved**. An explicit `None` means
**absent**, and only confirms the absence when the query is complete; in a
partial query it counts as not retrieved. A field therefore becomes empty
only when it is absent in a complete query. A field not retrieved, for
example because a walk stopped early, keeps its value.

**Row confirmation is explicit.** A caller that stores a row returned by the
query (a row of an SNMP table, or the management connection confirming an
address) passes `confirms_row=True`. A caller that derives or infers values
(vendor, speed, local port mapping, model from `sysDescr`, identity) leaves
it `False`. Row confirmation is never deduced from an update without fields.

**Creating a group.** A group is initialized only by an update that confirms
at least one field (a value, or `None` in a complete query; a `None` from a
partial query does not count) or that confirms the row. Otherwise:

- an **optional** group keeps its provenance columns null and `carried` empty;
- a **required** group is rejected with a `StoreError`, and nothing is
  written, instead of inventing an observation.

The single group of `device_addresses`, `ip_mac_entries` and
`identity_resolutions` is required. The groups of `devices`, `interfaces` and
`neighbor_entries` are optional, but a new interface or neighbour row must
initialize at least one of them. The rule is the same for a new row and for a
group of an existing row that was never populated.

### Field states and carried fields

A stored field is in one of three states:

| State | Stored as | Read as |
|-------|-----------|---------|
| value | the value | `value` |
| confirmed absence | `NULL`, confirmed by a complete query | `absent` |
| not retrieved | `NULL`, with `{"retrieved": false}` in `carried` | `unknown`, never `absent` |

Each group's `<g>_carried` map follows one invariant: **a field without an
entry has the group's last query, origin, method and evidence as its
provenance and holds a value or a confirmed absence.** The rules that keep it
are:

- An update **sets** a field when it retrieves its value or confirms its
  absence, unless precedence protects the field (see below). An update that
  sets no field is handled in one of three ways:
  - a **row observed again** (`confirms_row=True`) renews the row's
    observation: it moves `last_seen_at`, `last_query_id` and, when the query
    is complete, `last_complete_query_id`. Fields it does not set keep their
    value and provenance through `carried`;
  - an **inferred update fully blocked by precedence** changes nothing;
  - any other update **without fields** (`confirms_row=False`) changes
    nothing and never renews dates.

  In every case queries keep their order: a confirmation from a query older
  than the stored last query never moves `last_seen_at` or `last_query_id`,
  and can only move the first seen time and query.
- When an update moves the group's last query, every field it does not set
  (not retrieved, or protected) that held a value or a confirmed absence gets
  an entry with the **full provenance it had**:
  `{query_id, seen_at, origin, method, evidence}`. This is always recorded,
  whatever the new update's origin.
- A field that no query has retrieved yet, for example in a row first stored
  from a partial query, is recorded as `{"retrieved": false}`.
- An existing entry is kept as it is while the field is not set again, so
  several partial updates in a row do not replace its original provenance.
- When a later update, partial or complete, sets the field, its entry is
  removed and that update becomes its provenance. An update that sets every
  field of the group empties the map.

Reads use the carried entry for that field: its origin, method, evidence,
query, run, age and staleness. A field never retrieved is reported as
unknown, with no provenance. The evidence size limit (16 KiB) applies jointly
to the group's evidence plus every evidence in `carried`. Storing the same
query twice gives the same result as storing it once.

### Observed/inferred precedence per field

A field's **effective origin** is the origin in its carried entry if it has
one, otherwise the group's. An inferred update never changes a field whose
effective origin is observed: not its value, its provenance or its times. It
may still set the other fields of the group. The protected fields are then
carried with their observed provenance and keep ageing from their own query.
An observed update may replace inferred fields.

Rows are inserted or locked with `INSERT ... ON CONFLICT DO UPDATE`. The rules
above are applied on the locked row, so concurrent writers are serialised and
the result does not depend on the order of storage. Each row of a batch is
validated on its own. Invalid rows are counted in the query's
`rejected_count` without storing their values, and the rest is stored.

## Sources and evidence format

Sources and evidence share one JSONB format of at most 16 KiB. It is
validated before writing (`store/evidence.py`):

```json
{
  "method": "lldp-portnum-equals-ifindex",
  "method_version": 1,
  "inputs": [
    {"kind": "query", "id": 812, "mib_object": "LLDP-MIB::lldpLocPortTable"},
    {"kind": "record", "table": "interfaces", "id": 45,
     "snapshot": {"if_index": 7, "if_name": "lab-port-7"}}
  ]
}
```

The method must be registered with the origin of the datum, at its current
version. The sources of an observed derivation are references only. The
evidence of an inferred datum has at least one input with a `snapshot` of the
values used. Snapshot values are fragments (at most 1024 characters each),
never whole documents. The snapshot keeps explaining the inference after the
referenced record changes.

## Methods

Methods are registered in `store/registry.py` with their description,
assumptions and version. A test checks that this table lists every registered
method with its origin and version.

| Method | Origin | Version | What it does | Assumptions |
|--------|--------|---------|--------------|-------------|
| `ifhighspeed-when-ifspeed-saturated` | observed | 1 | Speed in bit/s from `ifHighSpeed` (Mbit/s) when `ifSpeed` is at its maximum | None beyond IF-MIB |
| `ipaddress-ifindex` | observed | 1 | Address linked to the interface whose `ifIndex` the address table names | None beyond IP-MIB |
| `ip-mac-ifindex` | observed | 1 | IP-MAC entry linked to the interface whose `ifIndex` the entry names | None beyond IP-MIB |
| `cdp-cache-ifindex` | observed | 1 | CDP entry linked to the interface whose `ifIndex` is its `cdpCacheIfIndex` | None beyond CISCO-CDP-MIB |
| `lldp-portid-ifname` | observed | 1 | LLDP local port mapped to the interface whose `ifName` equals the port id | None beyond 802.1AB (subtype interfaceName) |
| `lldp-port-description-match` | inferred | 1 | LLDP local port mapped to the only interface whose `ifDescr` equals `lldpLocPortDesc` | Descriptions are unique and copied verbatim |
| `lldp-portnum-equals-ifindex` | inferred | 1 | LLDP local port mapped to the interface whose `ifIndex` equals `lldpLocPortNum` | Not guaranteed by 802.1AB (hypothesis H1) |
| `enterprise-registry` | inferred | 1 | Vendor name from the enterprise number of `sysObjectID` | The OID owner made the hardware; false for OEM devices and generic agents |
| `sysdescr-model-pattern` | inferred | 1 | Model and version from `model <x>` and `version <y>` fragments of `sysDescr` | `sysDescr` labels them with these words |
| `chassis-id` | inferred | 1 | Observations attached to the device that reported the same LLDP chassis id | Chassis ids are unique and stable (hypothesis H3) |
| `address` | inferred | 1 | Observations attached to the device already known at the queried address | The address still belongs to the same device |

The LLDP local port mapping tries the rules in this order: name (observed),
description, then port number. If none applies, the entry keeps no local
interface and stores the reason (`no-rule-matched`).

### Vendor registry

The enterprise numbers 12356 (Fortinet), 2636 (Juniper), 9 (Cisco), 11 (HPE),
14823 (Aruba), 14988 (MikroTik) and 41112 (Ubiquiti) map to vendor names.
Generic agents such as Net-SNMP (8072) are marked as not identifying a
hardware vendor. For a generic agent, or a number outside the registry, the
vendor is stored as unknown (`vendor_status` `generic_agent` or
`not_in_registry`) together with the enterprise number, and is never guessed.

### Model precedence

The model and software version are observed when read from ENTITY-MIB and
inferred when taken from fragments of `sysDescr`. Precedence is per field. If
a partial ENTITY-MIB walk gives the model but not the version, the version
keeps its inferred provenance (method `sysdescr-model-pattern` and its
evidence) in `carried`, while the model is observed. A newer inference may
then update the version but never the observed model, which stays carried
with its observed provenance and its original age, and becomes stale when it
is not confirmed again. When both fields are observed, an inference sets
nothing and leaves the `model` group unchanged. When the pattern finds no
version fragment, the version is left unretrieved, not stored as absent.

## Device identity

Deciding that an answer comes from a known device is an inference, stored in
`identity_resolutions` with its method (`chassis-id` or `address`), key,
evidence and status. A device that reports a chassis identifier is matched by
it, even through a new address. Without LLDP, a device is matched by its
known addresses. Contradictions are never merged. Both devices are kept, the
conflict is stored in `identity_conflicts` with its evidence for review, and
the resolutions of the contested key are marked `conflicted`. Contradictions
are an address answering with a different chassis identifier, or one chassis
identifier with an incompatible `sysObjectID`.

## Query outcomes, presence and staleness

A query's outcome is `ok`, `empty`, `not_available`, `no_response`, `partial`
or `error`. Empty and not available outcomes store the indicator they are
based on (`noSuchObject`, `noSuchInstance`, `endOfMibView` or
`end_of_subtree`). Errors store only a category from the registry, never
exception text. `no_response` is stored without any diagnosis, because
SNMPv2c cannot tell a wrong community from a filter or a dead host.

A query is **complete** when its outcome is `ok` or `empty` and it has no
rejected rows. Only complete queries decide that a datum is absent.

**Presence** is computed when reading. A datum is present when its
`last_complete_query_id` is the latest complete query of the same device and
MIB object, found through the index `(device_id, mib_object, started_at
DESC)`. Partial confirmations do not change it. Without any complete query,
presence is unknown, not absent. When the latest query of the source was not
complete, the result also says so (`latest_attempt_complete = false`).

A datum is **stale** when `now - last_seen_at > NETSCANNER_STALE_AFTER`
(default `P7D`). Staleness is computed at read time. Stale data is kept and
readable, and nothing is deleted or modified because it is stale. Every read
returns, with each group, its origin, source device, MIB object, query and
run, method, first and last seen times, age, staleness, presence and carried
fields.

## Runs and evaluation

`collection_runs` records each run's kind, status (pending, running,
completed, failed or interrupted), times and parameters. The parameters
schema has no field for a secret: a credential is referenced by its
identifier, and unknown fields such as a community are rejected. Runs left
running by a previous process are marked interrupted when the collector
starts. `run_devices` records every device or candidate a run reached, new or
known, with how it was reached, its depth, its first query and whether it
answered. `run_report(run_id)` returns from these records the duration, the
devices reached and how, the new devices, the devices without answer, and
outcome counts by vendor and MIB object.

### Evaluation snapshots

A run asks for a snapshot through its parameters (`snapshot: true`).
`finish_run` then takes the observation advisory lock exclusively, which every
observation write takes in shared mode. It then closes the run and builds the
snapshot in one `REPEATABLE READ` transaction. The lock is taken before that
transaction starts, so the snapshot sees every write that finished before it.
Writers only wait while the snapshot is built.

The document holds the devices reached by the run, with their attributes,
identity resolutions, addresses, interfaces, neighbour entries and IP-MAC
entries and their provenance. Each group records the run of its last
confirming query (`last_run_id`, `confirmed_by_this_run`), so data confirmed
by another run before the close is attributed to that run. A run without a
requested snapshot cannot be reconstructed later, and `get_snapshot` says so.

## Data minimisation

- The system group input has no fields for `sysContact` or `sysLocation`.
  They are dropped before validation.
- Serial numbers are not queried or stored as attributes, and no table has a
  column for them.
- Evidence keeps only the fragments a method used. A method that cannot work
  with fragments produces no inferred value.
- Snapshots follow the same rules and leave out `sysDescr`.
- Errors are stored as categories, and validation messages never echo input
  values.

**Limitation:** `sysDescr` is stored because RF-03 requires the device
description. It may contain sensitive identifiers such as serial numbers. It
is treated as sensitive inventory data, never logged, never copied into
evidence or snapshots, and never committed to the repository. Inventory,
topology and traffic data are sensitive. Until `add-admin-authentication` is
implemented, the application is used only with lab data and bound to
localhost.
