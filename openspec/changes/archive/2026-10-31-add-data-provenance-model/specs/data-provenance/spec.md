# Spec Delta

## Purpose

Defines the provenance rules that every datum stored by NetScanner follows:
where it came from, when it was seen, whether it was observed or inferred, on
what sources and evidence, and whether it is still current.

## ADDED Requirements

### Requirement: RF-28 Provenance of every stored datum
The system SHALL store, for every datum, the device that reported it, the MIB object or protocol it was read from, the query and collection run that produced it, the times it was first and last seen, and whether it is observed or inferred.

#### Scenario: Datum recorded from a query
- **WHEN** an interface is stored from a successful IF-MIB::ifTable query on lab-sw-01 at 10.99.0.11
- **THEN** reading it back returns lab-sw-01 as reporting device, `IF-MIB::ifTable` as source, the query and run identifiers, its first and last seen times and the origin `observed`

#### Scenario: Datum without a source
- **WHEN** code tries to store a datum without a reference to the query that produced it
- **THEN** the store rejects it and nothing is written

### Requirement: Datum belongs to the device of its source query
The system SHALL reject any datum whose device differs from the device of the query that produced or confirmed it.

#### Scenario: Mismatched device
- **WHEN** code tries to store an interface for lab-sw-02 referencing a query sent to lab-sw-01
- **THEN** the store rejects it and nothing is written

### Requirement: Observed data
The system SHALL classify a datum as observed only when it was read from a device, or derived from read values by a rule that a standard or MIB definition guarantees: decoding, unit conversion or a cross-reference defined by the MIB.

#### Scenario: Cross-reference defined by the MIB
- **WHEN** an IP-MAC entry is linked to an interface through its `ipNetToPhysicalIfIndex`
- **THEN** the link to the interface is stored as observed

#### Scenario: Value read directly
- **WHEN** an LLDP chassis identifier is read from `lldpLocChassisId`
- **THEN** the identifier is stored as observed, which does not by itself establish that it is stable or unique

### Requirement: Sources of observed derivations
When an observed datum is derived from more than one query, the system SHALL store the derivation method and references to every source it combined.

#### Scenario: LLDP port mapped by interface name
- **WHEN** an LLDP local port with the interface name subtype is mapped to the interface whose `ifName` matches it
- **THEN** the mapping is stored as observed with its method and references to the LLDP local port query and the `ifXTable` query

### Requirement: Inferred data
The system SHALL classify as inferred any datum that depends on a heuristic or on an assumption that no standard guarantees, and SHALL store with it the name and version of the method used and evidence with a snapshot of the values used.

#### Scenario: Assumption about LLDP port numbers
- **WHEN** an LLDP local port is mapped to an interface by assuming that `lldpLocPortNum` equals `ifIndex`
- **THEN** that mapping is stored as inferred with the method name and the values it used

#### Scenario: Model parsed from free text
- **WHEN** the model of a device is extracted from the free text of `sysDescr`
- **THEN** the model is stored as inferred with the method name and, as evidence, a reference to the stored description and only the fragments the method matched

#### Scenario: Inferred datum without evidence
- **WHEN** code tries to store an inferred datum without a method or without evidence
- **THEN** the store rejects it and nothing is written

### Requirement: Evidence that survives later changes
The evidence of an inferred datum SHALL identify the stored records and queries it is based on and include a snapshot of the values used, so that the inference can still be explained after those records change.

#### Scenario: Source record changes later
- **WHEN** an inferred datum was based on an interface description that is later updated
- **THEN** the evidence still shows the description as it was when the inference was made, and the reference to the interface record

#### Scenario: Malformed or oversized evidence
- **WHEN** code tries to store sources or evidence that do not follow the evidence format or exceed the size limit
- **THEN** the store rejects them with a validation error

### Requirement: Provenance per group of fields
The system SHALL store provenance, including first and last seen times and queries, separately for each group of fields of a record that come from different queries or have different origins.

#### Scenario: Interface built from two tables
- **WHEN** an interface record combines fields from `IF-MIB::ifTable` and `IF-MIB::ifXTable`
- **THEN** each group of fields reports its own source query and times

#### Scenario: Neighbour entry updated without checking its mapping
- **WHEN** an LLDP neighbour entry is confirmed by a new remote table query but its local interface mapping is not evaluated again
- **THEN** the entry's last seen time changes and the mapping keeps its own last verification time

### Requirement: Paired update of first and last seen
Storing a datum that already exists SHALL update each time together with its query: first seen time and first query move only to an earlier query, last seen time, last query and current values move only to a later one, and no duplicate is created.

#### Scenario: Same entry in a later run
- **WHEN** an interface already stored is reported again by a later query
- **THEN** there is still one interface record, its first seen time and first query are unchanged, and its last seen time, last query and values are the new ones

#### Scenario: Late result from an older query
- **WHEN** results from a query that started before the stored first query are stored after newer ones
- **THEN** first seen time and first query both move to the older query, while last seen time, last query and values stay unchanged

#### Scenario: Same query stored twice
- **WHEN** the results of one query are stored twice
- **THEN** the stored data is identical to storing them once

#### Scenario: Queries with the same start time
- **WHEN** two queries with the same start time confirm the same datum
- **THEN** the query with the higher identifier is taken as the later one, so the result does not depend on the order of storage

### Requirement: Confirmed absence versus not retrieved
Storing a query result SHALL change only the groups the query covers, and SHALL empty a field only when its absence is confirmed by a complete query; a field not retrieved because the query was partial or the row was rejected SHALL keep its previous value and provenance.

#### Scenario: Group not queried
- **WHEN** an `ifTable` result is stored for an interface whose `ifXTable` fields were stored earlier
- **THEN** the `ifXTable` group keeps its values, times and queries

#### Scenario: Absence confirmed by a complete query
- **WHEN** a complete `ifXTable` query returns an interface without its alias
- **THEN** the alias becomes empty and the group's last query is the new one

#### Scenario: Field not retrieved in a partial query
- **WHEN** a partial `ifXTable` query returns the name of an interface but stops before reaching its alias
- **THEN** the name is updated from the partial query, the alias keeps its previous value, and reading the interface shows the alias with the query and time it actually came from

#### Scenario: Field never retrieved
- **WHEN** an interface is first stored from a partial `ifXTable` query that did not retrieve its alias
- **THEN** the alias is recorded as not retrieved and reading it reports it as unknown, not as absent

### Requirement: Group provenance with carried fields
The provenance of a group SHALL point to the latest query that updated any of its fields; every field without a carried entry SHALL have that query, origin, method and evidence as provenance and hold a value or a confirmed absence, every field kept from an earlier query SHALL record the full provenance it had (query, time, origin, method and evidence), and every field never retrieved SHALL be recorded as not retrieved.

#### Scenario: Confirmed absence carried
- **WHEN** a complete `ifXTable` query confirmed that an interface has no alias and a later partial query does not retrieve the alias
- **THEN** the alias stays empty and keeps the complete query and its time as provenance

#### Scenario: Carried field keeps its own origin
- **WHEN** the version of a device was inferred from `sysDescr` and a later partial ENTITY-MIB query gives the model as observed but not the version
- **THEN** reading the device shows the model as observed and the version as inferred, with its method and evidence

#### Scenario: Inferred update does not change an observed field
- **WHEN** an inferred update covers a field whose own origin is observed, and another field of the same group that is inferred
- **THEN** the inferred field is updated, and the observed field keeps its value, its observed provenance and its original age

#### Scenario: Row observed again without new fields
- **WHEN** a management connection to a known address of a device succeeds again, and the address row has no field the connection can retrieve
- **THEN** the row's last seen time and last query move to the new query, and its interface fields stay unknown

#### Scenario: Inferred update blocked by precedence
- **WHEN** every field an inferred update covers is observed
- **THEN** the group is left untouched, including its last seen time, last query and last complete query

#### Scenario: Update without fields that confirms no row
- **WHEN** an update sets no field of a group and does not store a row returned by its query
- **THEN** the group is left untouched and none of its dates is renewed

#### Scenario: Group never observed is not created
- **WHEN** a new or existing record receives, for a group never populated, an update that confirms no field and no row, such as one with only empty values from a partial query
- **THEN** that group keeps no provenance and no carried fields

#### Scenario: New record without an observation
- **WHEN** a new record would have its required group, or no group at all, initialized by an update that confirms no field and no row
- **THEN** the store rejects it and nothing is written

#### Scenario: Late row confirmation
- **WHEN** a row is confirmed by a query that started before the group's stored last query
- **THEN** the last seen time and last query do not move, and only the first seen time and query may move to the older query

#### Scenario: Evidence size of a group with carried fields
- **WHEN** the evidence of a group together with the evidence held in its carried entries exceeds the size limit
- **THEN** the store rejects the update with a validation error

#### Scenario: Carried query kept across partial updates
- **WHEN** two consecutive partial queries update the name of an interface and neither retrieves its alias
- **THEN** the alias keeps the query and time of the query that last retrieved it, not those of the intermediate partial query

#### Scenario: Carried field retrieved again
- **WHEN** a later query, partial or complete, retrieves a carried field or confirms its absence
- **THEN** the field is no longer carried and takes that query as its provenance

#### Scenario: Group completed again
- **WHEN** after a partial update a later query retrieves every field of the group
- **THEN** no field is recorded as carried and the whole group points to the later query

#### Scenario: Age of a carried field
- **WHEN** a field has been carried from an older query
- **THEN** its age and staleness are computed from that older query, not from the group's last update

### Requirement: Presence in the latest complete collection
When data is read, the system SHALL report whether each datum appeared in the latest complete query of its source on its device, where complete means outcome ok or empty with no rejected rows, independently of later partial confirmations.

#### Scenario: Present in the latest complete query, confirmed again by a partial one
- **WHEN** an entry appeared in the latest complete LLDP query and appeared again in a later partial one
- **THEN** it is reported as present

#### Scenario: Missing from the latest complete query
- **WHEN** a neighbour entry was not returned by the latest complete LLDP query of its device
- **THEN** it is reported as not present

#### Scenario: Latest attempt did not complete
- **WHEN** the latest query of the source had outcome no response, partial or error, or had rejected rows
- **THEN** presence is evaluated against the latest complete query and the result also says that the latest attempt did not complete

#### Scenario: No complete query yet
- **WHEN** the source has never had a complete query on that device
- **THEN** presence is reported as unknown, not as absent

### Requirement: RF-30 Staleness computed when reading
The system SHALL report a datum as stale when it has not been confirmed within a configurable period, and SHALL NOT delete or modify data because it is stale.

#### Scenario: Datum older than the period
- **WHEN** a datum was last seen longer ago than `NETSCANNER_STALE_AFTER`
- **THEN** reading it returns it marked as stale, with its last seen time

#### Scenario: Default period
- **WHEN** `NETSCANNER_STALE_AFTER` is not set
- **THEN** the period is 7 days

#### Scenario: Stale data kept
- **WHEN** data becomes stale
- **THEN** it remains stored and readable

### Requirement: RF-29 Origin and age available on every read
Every read of stored data SHALL return, with each datum or group of fields, its origin, source device and MIB object, method if any, first and last seen times, age, staleness and presence, so that the interface can show them without further queries.

#### Scenario: Reading a device with its interfaces
- **WHEN** a device and its interfaces are read through the persistence layer
- **THEN** each device attribute group and each interface carries its provenance, age, staleness and presence in the result

### Requirement: Data minimisation
The system SHALL NOT store `sysContact`, `sysLocation`, serial numbers queried separately or any credential, and evidence SHALL contain only the fragments a method used, never a full copy of a value it was extracted from.

#### Scenario: System group with contact and location
- **WHEN** the result of a system group query includes `sysContact` and `sysLocation`
- **THEN** those values are not stored anywhere in the database

#### Scenario: Evidence from free text
- **WHEN** a method extracts a model from a `sysDescr` that also contains other identifiers
- **THEN** the evidence holds only the matched fragments, and if the method cannot work with fragments it produces no inferred value
