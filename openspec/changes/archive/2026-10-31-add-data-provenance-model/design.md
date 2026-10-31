# Design

## Context

The skeleton provides PostgreSQL, Alembic with an empty baseline, async
SQLAlchemy and tests against a real database. No SNMP code exists yet. This
change creates the first business tables and a persistence layer; the SNMP
client and discovery changes will only call it. Lessons from the prototype
that shape the model: an empty or unsupported table is not an error, IP
addresses are not identities, `lldpLocPortNum` is not guaranteed to be the
`ifIndex`, and vendor behaviour must be verified per device.

## Goals / Non-Goals

**Goals:**
- Provenance stored by construction: the persistence layer cannot write a
  datum without its source query, nor an inferred datum without method and
  evidence (enforced in code and by database constraints).
- Precise, testable rules for first and last seen, presence and absence.
- The same rules reusable by later tables (FDB, end hosts, links, samples,
  sFlow aggregates) without redesign.
- Every OE6 measure computable from stored records for any run.

**Non-Goals:**
- SNMP access, discovery, scope checks, credentials (run parameters keep a
  credential identifier without a foreign key; the credentials change adds
  the table and the constraint).
- Full change history of each datum (RF-17). Only evaluation snapshots are
  kept, on request.
- HTTP endpoints or screens.

## Decisions

### D1. Provenance by reference to the query — Decision
Each datum points to the query that first produced it and the one that last
confirmed it. The query record holds the target device, MIB object,
operation, run and time. Alternative: repeating device, MIB object and run
columns on every row; discarded because it duplicates data and lets rows
disagree with their query. Queries are never deleted while data points to
them (foreign keys without cascade).

Device consistency is enforced by the database: `snmp_queries` has a unique
key on `(id, device_id)`, and every observation table references its queries
with composite foreign keys `(<g>_last_query_id, device_id)` and
`(<g>_first_query_id, device_id)`. A query gets its device assigned when the
device is resolved, before any observation is stored.

### D2. Current state with first and last seen — Decision
Observation tables keep one row per natural key, updated when seen again.
No row per poll. Alternative: append-only observations with a current-state
view; discarded for now because FDB and IP-MAC tables would grow by thousands
of rows per run with little value for the TFE. What the evaluation of a
specific run needs is covered by run–device records (D8) and evaluation
snapshots (D11), not by a full history. RF-17 [D] can later add a
change-history table fed by the same upserts.

### D3. Observed versus inferred — Decision
The rule is whether a standard guarantees the result:

| Datum | Origin | Why |
|-------|--------|-----|
| Values read from any MIB object, decoded | observed | read directly |
| LLDP chassis identifier and subtype | observed | read directly; says nothing about stability or uniqueness |
| `sysObjectID` and its enterprise number | observed | read directly |
| Speed from `ifHighSpeed` when `ifSpeed` is saturated | observed, with sources | rule in IF-MIB |
| IP-MAC entry to interface via `ipNetToPhysicalIfIndex` | observed, with sources | MIB cross-reference |
| Bridge port to `ifIndex` via `dot1dBasePortIfIndex` (iteration 2) | observed, with sources | MIB cross-reference |
| LLDP local port to interface when the port id subtype is interfaceName and equals `ifName` | observed, with sources | 802.1AB subtype definition |
| CDP entry to interface via `cdpCacheIfIndex` (method `cdp-cache-ifindex`) | observed, with sources | CISCO-CDP-MIB defines it as the local `ifIndex` |
| Vendor name from the enterprise number | inferred | the enterprise owns the agent's OID, not necessarily the hardware (OEM, generic agents) |
| Device identity, by chassis identifier or by address | inferred | no standard guarantees stable, unique chassis identifiers (H3) or addresses |
| LLDP local port assumed equal to `ifIndex` | inferred | not guaranteed by 802.1AB |
| LLDP local port matched by description | inferred | heuristic |
| Model or version parsed from `sysDescr` | inferred | free text |
| Links from FDB, end-host location "probable" (later) | inferred | heuristic |

An observed datum derived from more than one query records its method and
sources; an inferred datum records its method and evidence with snapshots.

The LLDP local port mapping tries its rules in a fixed order: interface name
(observed), then a description equal to exactly one `ifDescr` (inferred),
then the port number assumed equal to `ifIndex` (inferred, H1). If none
applies, the entry keeps no interface and stores the reason. The order puts
the standard rule first and the weakest assumption last; the evaluation will
show whether the description rule should stay before the port number one.

Model precedence: an inferred model or version (from `sysDescr`) never
replaces an observed one (ENTITY-MIB). Precedence is decided per field (D9):
an observed field keeps its value, provenance and times, ages and becomes
stale normally, while the inference may still update a field of the group
that is not observed. When both are observed, the inference sets nothing and
the `model` group is untouched. A pattern without a version fragment leaves
the version unretrieved. Alternative: letting a newer inference refresh an
older observation; discarded because it would present a heuristic as the
current fact. Alternative: precedence for the whole group; discarded because
a partial ENTITY-MIB walk that gives only the model would then either block
the version or overwrite its inferred provenance.

### D4. Provenance groups — Decision
A provenance group is a set of columns with a common prefix:
`<g>_origin`, `<g>_method`, `<g>_evidence`, `<g>_first_seen_at`,
`<g>_first_query_id`, `<g>_last_seen_at`, `<g>_last_query_id`,
`<g>_last_complete_query_id`, `<g>_carried`. Tables with a single group use unprefixed
names. Check constraints per group:
- inferred requires method and evidence with at least one snapshot;
- observed may have method and evidence (sources only, no snapshot
  required); if it has evidence it must also have a method;
- last seen is not earlier than first seen.

A reusable helper generates the columns, constraints and composite foreign
keys, so later tables cannot forget them.

Groups in this change:
- `devices`: `system` (system group fields and enterprise number),
  `chassis` (LLDP chassis identifier), `vendor` (inferred vendor name),
  `model` (model and software version).
- `interfaces`: `base` (`ifTable`), `ext` (`ifXTable`), `speed` (observed
  derivation with sources from both tables).
- `neighbor_entries`: `entry` (`lldpRemTable` or CDP cache), `man_addr`
  (`lldpRemManAddrTable`), `local_map` (mapping to a local interface, with
  its own verification times and queries, plus a failure reason).
- `device_addresses`, `ip_mac_entries`: one group each.

Required and optional groups (`GroupSpec.required`): a group is required
when its row cannot exist without it. The single group of
`device_addresses`, `ip_mac_entries` and `identity_resolutions` is required:
the row *is* that observation or decision, and its columns are `NOT NULL`.
The groups of `devices`, `interfaces` and `neighbor_entries` are optional:
an interface may be known from `ifTable` or `ifXTable` alone, a neighbour
entry from its remote table or its management addresses alone, and a device
row is created by identity resolution before any of its groups is stored.
A new `interfaces` or `neighbor_entries` row must still initialize at least
one group (D9).

### D5. Sources and evidence format — Decision
One JSONB format validated with a Pydantic model before writing, maximum
16 KiB:

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

For observed derivations, `inputs` contains references only. For inferred
data, at least one input carries a `snapshot` with the values used, and
snapshots keep only those values (fragments, not whole texts; see D10).
Alternative: a polymorphic evidence join table; it cannot have real foreign
keys either and loses the snapshot, so it was discarded. Every method is
registered in code with its description, assumptions and version, and
`docs/provenance.md` lists them for the report.

### D6. Staleness and presence — Decision
- Staleness is computed at read time:
  `stale = now - last_seen_at > NETSCANNER_STALE_AFTER` (a `timedelta`
  setting, default `P7D`, added to `.env.example`). RF-30 is desirable, but
  with last seen times in place it costs one setting and one expression,
  while adding it later would touch every read (delivery-rules exception).
- A query is complete when its outcome is `ok` or `empty` and
  `rejected_count = 0`.
- Presence uses `<g>_last_complete_query_id`, set only when the datum is
  stored from a complete query. Partial queries update last seen and last
  query but not this field. A datum is present when that field equals the
  latest complete query of the same device and MIB object, found through an
  index on `(device_id, mib_object, started_at DESC)`. If there is no
  complete query, presence is unknown. If the latest query of the source is
  not complete, the result says so.

### D7. PostgreSQL native types — Decision
`inet` for addresses, `macaddr` for MAC addresses, `jsonb` for evidence,
parameters and snapshots, `timestamptz` (UTC) for times, `bigint` identity
keys. The database validates addresses as a second barrier after Pydantic.

### D8. Tables — Decision

- `collection_runs`: kind, status (pending, running, completed, failed,
  interrupted), requested/started/finished times, `parameters` (JSONB
  validated against a schema without secret fields), `summary`,
  `error_category`.
- `snmp_queries`: run, target address, device (nullable until resolved),
  MIB object, operation, SNMP version, outcome, indicator, error category,
  row count, rejected count, request count, start time, duration; unique
  `(id, device_id)` for the composite foreign keys.
- `devices`: system group fields, enterprise number, chassis identifier and
  subtype, vendor name and `vendor_status` (`known`, `generic_agent` or
  `not_in_registry`, see D12), model and software version, with the groups
  of D4.
- `identity_resolutions`: device, method (`chassis-id` or `address`), key
  value, evidence, first and last seen with queries. One device can have
  several resolutions.
- `identity_conflicts`: the key in conflict, the devices involved, evidence,
  query and time of detection, review flag. A conflict is recorded when an
  address known for one device answers with a different chassis identifier,
  or when a chassis identifier already stored is reported with a different
  `sysObjectID`. The second criterion is a **heuristic pending evaluation**
  (see H3): devices that share a chassis identifier and also the model, such
  as HA pairs, are not separated by it.
- `run_devices`: run, device (nullable when the candidate did not answer),
  target address, how it was reached (seed, lldp, cdp, ip-mac), depth,
  first query, answered or not.
- `device_addresses`, `interfaces`, `neighbor_entries`, `ip_mac_entries`:
  as before, with the groups of D4. `device_addresses` has its `source`
  (address table or management connection) in the unique key
  `(device_id, address, source)`, so each source keeps its own row and
  provenance instead of overwriting the other. Interface `ifIndex` in
  1..2147483647;
  physical address stored as `macaddr` only when it is 6 bytes. The
  neighbour natural key excludes the LLDP time mark, which changes on every
  update.
- `evaluation_snapshots`: run, creation time, schema version, JSONB content.

String columns have explicit maximum lengths (255 for names, 1024 for
descriptions); longer input is a validation failure, not truncation.
MIB object and method names are stored as text and validated against
registries in code, so adding a vendor MIB needs no migration.

### D9. Upsert rules — Decision
Each row is inserted, or locked if it exists, with `INSERT ... ON CONFLICT
DO UPDATE` (a no-op update that takes the row lock). The rules below are then
applied in Python, per group, on the locked row, and written back with one
`UPDATE`. Queries are compared by `(started_at, id)` so that equal start
times have a deterministic order. Alternative: expressing every rule,
including the carried map, in the `DO UPDATE SET` clause; discarded because
those expressions would be hard to read and test. Cost: up to three
statements per row instead of one. This is acceptable for iteration 1, but
the per-row cost must be **measured in iteration 2 with FDB volumes** before
the FDB tables reuse it; a set-based variant can replace it then. The rules:
- if the new query is earlier than the stored first query: replace
  `first_seen_at` and `first_query_id` together;
- if the new query is later than or equal to the stored last query: replace
  `last_seen_at`, `last_query_id` and the group's values together;
  otherwise values are left unchanged;
- if the new query is complete and later than or equal to the stored
  `last_complete_query_id`: replace it;
- groups not covered by the query are not touched;
- input contract: a field omitted from an update's values was not
  retrieved; an explicit `None` means absent, and only confirms the absence
  when the query is complete (in a partial query it counts as not
  retrieved). A field becomes null only when it is absent in a complete
  query; not retrieved fields (partial query, interrupted walk) keep their
  value;
- an update **sets** a field when it retrieves its value or confirms its
  absence, subject to precedence. Precedence is per field: a field's
  effective origin is the origin in its `carried` entry if it has one,
  otherwise the group's, and an inferred update never changes a field whose
  effective origin is observed (not its value, provenance or times);
- a group is initialized only by an update that confirms at least one
  field (a value, or `None` in a complete query; a `None` from a partial query
  does not count) or that has `confirms_row`. Otherwise an optional group
  keeps its provenance columns null and `carried` empty, and a required
  group (D4) is rejected with a `StoreError`
  instead of inventing an observation. The same rule applies when an existing
  row's group was never populated and when a row is inserted; a new row in
  which no group at all would be initialized is rejected too. Such an update
  can still merge into a row that already exists;
- row confirmation is explicit: `GroupUpdate.confirms_row` (default false)
  is set only by callers storing a row returned by the query (a row of an
  SNMP table, the management connection confirming an address). An update
  that sets no field is then one of three cases: a row observed again
  (`confirms_row`) renews the observation, moving `last_seen_at`,
  `last_query_id` and, if the query is complete, `last_complete_query_id`,
  while the fields it does not set are carried as usual; an inferred update
  fully blocked by precedence changes nothing; any other update without
  fields changes nothing and never renews dates. The query order still
  applies: a confirmation older than the stored last query never moves
  `last_seen_at` or `last_query_id`, only the first seen time and query.
  Alternative: deducing a confirmation from an update without fields;
  discarded because a derived or blocked update would then renew dates it
  did not observe;
- each group has a `<g>_carried` JSONB map with one **invariant**: a field
  without an entry has the group's last query, origin, method and evidence
  as its provenance and holds a value or a confirmed absence. When an update
  moves the group's last query, every field it does not set (not retrieved,
  or protected by precedence) that held a value or a confirmed absence gets
  an entry `{query_id, seen_at, origin, method, evidence}` with the full
  provenance it had, always, without comparing with the new update. A field
  never retrieved (a fresh row from a partial query, or a field that stays
  unretrieved) is recorded as `{"retrieved": false}`. An existing entry is
  kept while the field is not set again; when a later update, partial or
  complete, sets the field, the entry is removed and that update becomes its
  provenance. An update that sets every field of the group empties the map.
  Reads use the carried entry for that field (origin, method, evidence,
  query, age and staleness), and report a field never retrieved as unknown,
  not as absent. Alternative: entries with only `query_id` and `seen_at`;
  discarded because every update replaces the group's origin, method and
  evidence, so a carried field would end up with provenance that is not its
  own (for example a version inferred from `sysDescr` shown as observed
  after a partial ENTITY-MIB walk);
- the 16 KiB evidence limit (D5) applies jointly to the group's evidence
  plus every evidence held in `carried`;
Row locks taken by `ON CONFLICT` serialise concurrent writers, and the
comparison makes the final state independent of storage order. Each batch
validates rows one by one; invalid rows are counted in `rejected_count`
without storing their raw values.

### D10. Data minimisation — Decision
- The system group input model has no fields for `sysContact` or
  `sysLocation`.
- Serial numbers are not queried or stored as attributes.
- `sysDescr` is stored because RF-03 requires the device description. It
  may contain identifiers such as serial numbers; it is treated as
  sensitive inventory data (protected by authentication, never in logs, and
  never in the repository), and evidence never copies it: methods store a
  reference to the stored description and only the fragments they matched.
  A method that cannot work with fragments produces no inferred value.
- Snapshots follow the same rules and leave out `sysDescr`: the evaluation
  does not need it, and a copy would spread a value that may hold
  identifiers.
- A test puts canary values in contact, location and the non-matched part
  of `sysDescr` evidence input, and searches every table (`row::text`) and
  every snapshot for those that must not be stored.

### D11. Evaluation snapshots — Decision
A run requests a snapshot through its parameters (`snapshot: true`) when it
is created. `finish_run` then builds it in the same transaction that closes
the run, at `REPEATABLE READ`, after taking an exclusive PostgreSQL advisory
lock that every observation write takes in shared mode. The read is
therefore consistent and no other run writes observations while it lasts;
writers only wait for the duration of the snapshot. The document holds the
devices reached by the run and their interfaces, neighbour entries and
IP-MAC entries with their provenance, and each datum records the run of its
last confirming query, so data confirmed by another run before the close is
marked as such. A run without a requested snapshot cannot be reconstructed
later, and `get_snapshot` says so. Later changes add links and end-host
locations with a schema version. Alternative: a snapshot taken at any time
from current data; discarded because it would attribute newer values to an
older run.

### D12. Vendor registry and evaluation report — Decision
- A small registry maps enterprise numbers to vendor names (Fortinet 12356,
  Juniper 2636, Cisco 9, HPE 11, Aruba 14823, MikroTik 14988, Ubiquiti
  41112) and marks generic agents (Net-SNMP 8072) as not identifying a
  hardware vendor. The vendor group is inferred (method
  `enterprise-registry`) in every case; for a generic agent or an
  unregistered number its name is empty and `vendor_status` says why
  (`generic_agent` or `not_in_registry`), with the enterprise number kept in
  the system group, so an unknown vendor is never guessed.
- `run_report(run_id)` returns from `run_devices` and `snmp_queries` the run
  duration, devices reached and how, new devices, devices without answer,
  and outcome counts by vendor and MIB object.

## Hypotheses to verify on real devices

Data to capture on Tuesday for each model and firmware (anonymised before
it enters the repository): `lldpLocChassisIdSubtype`, `lldpLocChassisId`,
`lldpLocPortTable`, `lldpRemTable`, `lldpRemManAddrTable`, `ifTable`,
`ifXTable`, `ipAddressTable` or `ipAddrTable`, `sysObjectID`, `sysDescr`
and `entPhysicalModelName`.

- **H1** `lldpLocPortNum` may or may not equal `ifIndex`. Verifiable on
  Tuesday by comparing `lldpLocPortTable` with `ifXTable` on each model.
- **H2** `ifIndex` values persist across reboots. One capture cannot prove
  it; without two comparable captures around a reboot it stays pending and
  is documented as a limitation.
- **H3** Chassis identifiers are unique and stable. Uniqueness across the
  captured devices can be checked on Tuesday; stability needs comparable
  captures over time and otherwise stays pending. HA clusters and virtual
  chassis (stacks) may share one chassis identifier and also the same model,
  so the conflict criterion of D8 (same chassis id, different `sysObjectID`)
  would not separate them; how each vendor reports chassis identifiers in
  these setups must be checked before the criterion is trusted.

Results go to `docs/vendors/` per vendor, model and firmware.

## Risks / Trade-offs

- [Identity conflicts in real networks, e.g. HA pairs or shared virtual
  addresses] → recorded, not merged; reported by the evaluation.
- [No full history] → run–device records and evaluation snapshots cover
  the evaluation; RF-17 remains possible later.
- [JSONB evidence has no referential integrity] → snapshots make each
  inference self-explanatory; queries are never deleted while referenced.
- [Wide tables from grouped provenance] → accepted for clarity and
  constraint enforcement; the helper generates them.
- [`sysDescr` may contain identifiers] → stored only because RF-03 requires
  it, treated as sensitive, never copied into evidence or logs.

## Impact on data model and security

- Data model: first business tables (migration `0002`).
- Repository: `ruff.toml` exempts `**/migrations/versions/**` from the line
  length rule (E501), so generated constraint SQL stays on one line as in the
  database.
- Security: no secrets in any table of this change; run parameters schema
  has no secret fields; errors stored as categories only; minimisation of
  contact, location and serial numbers; canary tests prove it.
