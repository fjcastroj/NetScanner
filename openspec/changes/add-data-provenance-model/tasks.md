# Tasks

Implement and verify block by block: do not start a block until the tests of
the previous one pass. All database tests run against PostgreSQL.

## 1. Provenance building blocks

- [x] 1.1 Registries in code: MIB object names used in iteration 1; methods (observed derivations and inferences) with description, assumptions and version; query outcomes and indicators; vendor enterprise numbers with generic agents marked (design D12)
- [x] 1.2 Sources and evidence model (Pydantic) with the format and 16 KiB limit of design D5: references only allowed for observed derivations, at least one snapshot required for inferred data
- [x] 1.3 Provenance group helper that generates the columns, check constraints and composite foreign keys of designs D1 and D4, including `last_complete_query_id`
- [x] 1.4 Setting `NETSCANNER_STALE_AFTER` (timedelta, default `P7D`) and its entry in `.env.example`
- [x] 1.5 Tests: sources and evidence accepted and rejected (wrong format, unknown method, inferred without snapshot, oversized), registries reject unknown names, settings test still finds every field in `.env.example`

## 2. Schema

- [x] 2.1 ORM models for `collection_runs`, `snmp_queries`, `devices`, `identity_resolutions`, `identity_conflicts`, `run_devices`, `device_addresses`, `interfaces`, `neighbor_entries`, `ip_mac_entries` and `evaluation_snapshots` as in design D8, with the groups of design D4
- [x] 2.2 Alembic migration `0002` with tables, constraints and indexes, including the unique `(id, device_id)` on `snmp_queries`, the composite foreign keys and `(device_id, mib_object, started_at DESC)`; downgrade drops them
- [x] 2.3 Point Alembic `target_metadata` to the models and add a test that the migrated schema matches the models (no pending autogenerate differences)
- [x] 2.4 Tests at database level: inferred row without method or evidence rejected, observed row with evidence but no method rejected, last seen earlier than first seen rejected, observation referencing a query of another device rejected, invalid `inet` and `macaddr` rejected, migration upgrade and downgrade run cleanly

## 3. Runs and queries

- [x] 3.1 `start_run`, `finish_run`, `mark_interrupted_runs` and `record_query`, with the run parameters schema (no secret fields, credential stored as an identifier only) and the complete-query rule of design D6
- [x] 3.2 Assign the device to the queries of a target address once the device is resolved; `record_run_device` for every device or candidate reached (design D8)
- [x] 3.3 Tests: run lifecycle including interrupted runs; one test per query outcome (`ok`, `empty`, `not_available`, `no_response`, `partial`, `error`) with its indicator or error category; `no_response` stored without any diagnosis; query with rejected rows not complete; second run over known devices records them all; candidate without answer recorded; canary test proving an error with sensitive text stores only its category

## 4. Observations

- [x] 4.1 Device upserts for the `system`, `chassis`, `vendor` and `model` groups; identity resolution by chassis identifier or address with evidence, and conflict recording without merging (design D3, D8)
- [x] 4.2 Upserts for addresses, interfaces (`base`, `ext` and the `speed` derivation with sources), neighbour entries (`entry`, `man_addr` and `local_map` groups, failure reason) and IP-MAC entries (invalid entries skipped, interface resolved by `ifIndex` with sources)
- [x] 4.3 Upsert rules of design D9 and per-row validation with `rejected_count`
- [x] 4.4 Tests for every scenario of `network-observations`: identifiers stored as observed; resolution by chassis identifier through a new address, by address, and conflicts kept with evidence; vendor inferred from a known enterprise, unknown for generic agents and unknown numbers; model observed and inferred from fragments; own address table versus neighbour advertisement; missing `ifXTable`; saturated `ifSpeed` with both sources; one-sided neighbour; management address outside ranges stored without any query; management addresses with their own query; local port mapped by name with both sources and unmappable with reason; IP-MAC from both tables; invalid entry skipped; batch with one bad row
- [x] 4.5 Tests for the `data-provenance` recording rules: datum of another device rejected; observed derivation with sources; first seen and first query move together on a late older result while last values stay; same query twice is idempotent; equal start times resolved by query id independently of storage order; group not queried left untouched; field absent in a complete query becomes empty; partial query that updates one field and does not retrieve another keeps the second with its own query and time in the carried map; carried map emptied when a later query retrieves the whole group; age of a carried field computed from its own query; neighbour confirmed without re-evaluating its mapping keeps the mapping's verification times; inferred evidence keeps its snapshot after the source record changes

## 5. Reading, presence, evaluation

- [x] 5.1 Read functions returning devices with groups and resolutions, addresses, interfaces, neighbours and IP-MAC entries, each with origin, source device, MIB object, method, first and last seen, age, staleness and presence
- [x] 5.2 Presence from `last_complete_query_id` (design D6) with the "latest attempt did not complete" flag and unknown without a complete query
- [x] 5.3 `run_report(run_id)`, snapshot generation inside `finish_run` with the advisory lock and `REPEATABLE READ` of design D11, and `get_snapshot` reporting runs without a snapshot
- [x] 5.4 Tests: stale and not stale around the period, stale data still readable; presence true after a later partial confirmation, false when missing from the latest complete query, unknown without a complete query, flag when the latest attempt was partial or had rejected rows; report figures on a small fixture with a second run; snapshot unchanged after later runs modify the data; datum confirmed by another run before closing marked with that run; snapshot of a run that did not request one reported as not reconstructible; an observation write waits while a snapshot is being built; data-minimisation canary test over every table and snapshot (design D10)

## 6. Documentation and checks

- [x] 6.1 `docs/provenance.md`: observed versus inferred rule with the table of design D3, provenance groups and carried fields, sources and evidence format, presence and staleness rules, snapshots, list of methods with their assumptions, and the explicit limitation that `sysDescr` may contain sensitive identifiers and is stored only because RF-03 requires it
- [x] 6.2 `docs/vendors/README.md` with the template to record verified behaviour per vendor, model and firmware, the data to capture listed in the design, and hypotheses H1 to H3 as pending checks
- [x] 6.3 `CHANGELOG.md` entry
- [x] 6.4 Run the full test suite on Linux against PostgreSQL, the pre-commit hooks, the stack test and `openspec validate --strict`; all green
