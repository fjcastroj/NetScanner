# network-observations Specification

## Purpose

Stores what the collector observes on network devices during iteration 1:
devices and how their identity is resolved, their addresses, interfaces,
LLDP and CDP neighbour entries and IP-MAC entries, following the provenance
rules.
## Requirements
### Requirement: Identifiers stored as observed
The system SHALL store the LLDP chassis identifier and its subtype, the `sysObjectID` and the enterprise number it contains as observed values of the device that reported them.

#### Scenario: Chassis identifier reported
- **WHEN** a device reports `lldpLocChassisIdSubtype` and `lldpLocChassisId`
- **THEN** both are stored as observed attributes of that device with their query

### Requirement: Identity resolution
The decision that several observations belong to the same device SHALL be stored as an identity resolution with its method (chassis identifier or address), evidence and status, because no standard guarantees that chassis identifiers are stable and unique.

#### Scenario: Same chassis identifier through another address
- **WHEN** a device answers on an address not yet associated with any device and reports a chassis identifier already stored for an existing device
- **THEN** the observations are attached to the existing device, and the resolution records the method `chassis-id`, the identifier and both addresses as evidence

#### Scenario: Device without LLDP
- **WHEN** a device does not report a chassis identifier
- **THEN** it is matched by its known addresses and the resolution records the method `address`

#### Scenario: Conflicting identity
- **WHEN** an address associated with one device is reported by a device with a different chassis identifier, or two devices report the same chassis identifier with incompatible data
- **THEN** the devices are not merged, both are kept, and the conflict is recorded with its evidence for review

### Requirement: RF-03 Device attributes
The system SHALL store for each device the name, description, object identifier and uptime from the system group, and the model and software version when available, each group with its provenance.

#### Scenario: Model from a standard table
- **WHEN** the model is read from `ENTITY-MIB::entPhysicalModelName`
- **THEN** it is stored as observed

#### Scenario: Model only in free text
- **WHEN** the model can only be extracted from `sysDescr`
- **THEN** it is stored as inferred with method and evidence made of the matched fragments

#### Scenario: Observed model takes precedence
- **WHEN** the model and version have been read from ENTITY-MIB and a later `sysDescr` would give an inferred model and version
- **THEN** the model group is left unchanged, with its values, times, last query and last complete query, and it becomes stale normally once the staleness period has passed

#### Scenario: Precedence decided per field
- **WHEN** a partial ENTITY-MIB query gave the model as observed but not the version, which was inferred from `sysDescr`, and a newer `sysDescr` gives another model and version
- **THEN** the inferred version is updated, and the observed model keeps its value, its observed provenance and its original age

### Requirement: Vendor name inferred from the enterprise number
The system SHALL store the vendor name derived from the enterprise number as inferred, with the registry method, because the enterprise number identifies the organisation that owns the agent's object identifier, not necessarily the manufacturer of the hardware.

#### Scenario: Known enterprise number
- **WHEN** the enterprise number is in the vendor registry
- **THEN** the vendor name is stored as inferred with the method `enterprise-registry` and the enterprise number as evidence

#### Scenario: Generic agent
- **WHEN** the enterprise number belongs to a generic SNMP agent such as Net-SNMP
- **THEN** no hardware vendor is inferred and the vendor is stored as unknown together with the enterprise number

#### Scenario: Unknown enterprise number
- **WHEN** the enterprise number is not in the registry
- **THEN** the vendor is stored as unknown together with the enterprise number, not guessed

### Requirement: Device addresses
The system SHALL store each address of a device with the interface it belongs to when known and its source, which is either the device's own address table or a successful management connection to that address.

#### Scenario: Addresses from the device's own table
- **WHEN** a device's IP address table lists 10.99.0.11 on interface 3 and 10.99.0.65 on interface 7
- **THEN** both addresses are stored for the device with their interfaces and the address table as source

#### Scenario: Address advertised by a neighbour
- **WHEN** another device advertises 10.99.0.12 as the management address of a neighbour
- **THEN** that address is stored only in the neighbour entry, not as an address of any device, until a device answers on it

### Requirement: RF-04 Interfaces
The system SHALL store each interface of a device, identified by its `ifIndex`, with name, alias, description, type, speed, physical address, administrative status, operational status and last change, keeping the provenance of `ifTable` and `ifXTable` fields separately.

#### Scenario: Device without ifXTable
- **WHEN** `IF-MIB::ifXTable` is not available on a device
- **THEN** the interfaces are stored with the `ifTable` fields and their provenance, and the `ifXTable` fields are empty with no provenance

#### Scenario: Speed above 4 Gbit/s
- **WHEN** `ifSpeed` is at its maximum value and `ifHighSpeed` is available
- **THEN** the stored speed comes from `ifHighSpeed` converted to bits per second, recorded as an observed derivation with both sources

### Requirement: Neighbour entries
The system SHALL store each LLDP or CDP neighbour entry reported by a device as observed, with protocol, local port, remote chassis and port identifiers with their subtypes, remote system name, remote port description and capabilities, and the advertised management addresses as a separate group.

#### Scenario: Neighbour seen from one side only
- **WHEN** lab-sw-01 reports lab-sw-02 as a neighbour but lab-sw-02 does not report lab-sw-01
- **THEN** the entry reported by lab-sw-01 is stored as observed

#### Scenario: Management address outside the allowed ranges
- **WHEN** a neighbour entry advertises a management address outside the allowed ranges
- **THEN** the entry and the address are stored; storing never triggers a query

#### Scenario: Management addresses from their own table
- **WHEN** the management addresses come from `lldpRemManAddrTable` and the entry from `lldpRemTable`
- **THEN** each group records its own query and times

### Requirement: Local port mapping
The system SHALL store the mapping of a neighbour entry's local port to an interface as its own group, with origin, method, sources or evidence, its own first and last verification times, and the reason when no mapping is possible.

#### Scenario: Mapped by the interface name
- **WHEN** the local port identifier has the interface name subtype and matches the `ifName` of one interface
- **THEN** the mapping is stored as observed with its method and both source queries

#### Scenario: Port that cannot be mapped
- **WHEN** no rule can map the local port to an interface
- **THEN** the entry is stored without a local interface and with the reason the mapping failed

### Requirement: IP-MAC entries
The system SHALL store each IP-MAC entry with the reporting device, the interface, the IP address, the MAC address, the entry type and the table it came from, and SHALL NOT store entries that the device marks as invalid.

#### Scenario: Entry from the current table
- **WHEN** an entry is read from `IP-MIB::ipNetToPhysicalTable`
- **THEN** it is stored with that table as source, for IPv4 and IPv6 addresses alike

#### Scenario: Entry from the deprecated table
- **WHEN** a device only provides `IP-MIB::ipNetToMediaTable`
- **THEN** the entry is stored with that table as source

#### Scenario: Invalid entry
- **WHEN** an entry has type invalid
- **THEN** it is not stored

### Requirement: RNF-04 Validation of stored values
The persistence layer SHALL reject malformed values, such as invalid addresses or MAC addresses, out-of-range indexes and oversized strings, record each rejection and continue storing the rest of the batch.

#### Scenario: One bad row in a batch
- **WHEN** a batch of 100 interface rows contains one row with an invalid physical address
- **THEN** 99 rows are stored, the bad row is rejected, the rejection is counted in the query record without storing the raw value, and that query is not used to declare any interface absent

### Requirement: RF-11 RNF-08 Juniper model from the captured sysDescr format
The system SHALL infer a Juniper device's model and software version from `sysDescr` with a vendor rule in its own module only when the `sysObjectID` is in the Juniper enterprise (2636), ENTITY-MIB gave no model and the generic `model`/`version` pattern found nothing. The rule SHALL match only the format observed in the `srx-01` capture (`<model> internet router, kernel JUNOS <version>`), SHALL store model and version as inferred with its own method name and only the matched fragments as evidence, never the whole `sysDescr`, and SHALL infer nothing for any other format. No such rule SHALL exist for a vendor without a verified capture.

#### Scenario: srx-01
- **WHEN** `srx-01`, whose `sysDescr` has no `model` keyword and which has no ENTITY-MIB, is discovered
- **THEN** its model `srx1500` and version `19.4R3.11` are stored as inferred with the method `juniper-sysdescr-pattern`, and the evidence holds the two matched fragments only

#### Scenario: Juniper sysDescr in another format
- **WHEN** a device in the Juniper enterprise has a `sysDescr` in another format, such as `lab-sw-01`'s synthetic one
- **THEN** no model is inferred

#### Scenario: Captured format under another enterprise
- **WHEN** a device whose `sysObjectID` is outside the Juniper enterprise has a `sysDescr` in the captured format
- **THEN** no model is inferred

#### Scenario: Generic pattern first
- **WHEN** a Juniper `sysDescr` contains a `model <x>` fragment
- **THEN** the generic method `sysdescr-model-pattern` is used and the Juniper rule is not applied

