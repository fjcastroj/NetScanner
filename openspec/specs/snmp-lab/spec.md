# snmp-lab Specification

## Purpose
TBD - created by archiving change add-snmp-client-and-lab. Update Purpose after archive.
## Requirements
### Requirement: Origin of every lab device and value
Every lab device SHALL be listed in a manifest with its origin: real and anonymised, synthetic, or synthetic with values derived from a real device, in which case the manifest names which values (for example MAC addresses or IP addresses) and from which device. Real devices also record model, firmware, capture date and the anonymisation applied, without any real address, name or identifier.

#### Scenario: Real device in the lab
- **WHEN** the manifest is read
- **THEN** `srx-01` appears as real and anonymised, Juniper SRX1500 with JUNOS 19.4R3.11, captured on 2026-11-03

#### Scenario: Synthetic device in the lab
- **WHEN** a synthetic switch is listed
- **THEN** it is marked as synthetic and the README explains which behaviours it models and which hypotheses it does not prove

#### Scenario: Synthetic device with derived values
- **WHEN** a synthetic switch uses MAC addresses taken from `srx-01`'s IP-MAC table
- **THEN** the manifest marks those values as derived from `srx-01`, so a reader can tell real, derived and invented data apart

### Requirement: Small network for iteration 1
The lab SHALL form a small network: the real firewall `srx-01`, a synthetic switch with LLDP towards a second synthetic switch, forwarding entries for MAC addresses taken from the firewall's IP-MAC table, and a second synthetic switch without LLDP-MIB and with 32-bit counters only.

#### Scenario: Consistent addresses across devices
- **WHEN** the synthetic switches are generated
- **THEN** the MAC addresses of their forwarding entries and the addresses of their neighbours match those in `srx-01` and in each other, so that later changes can locate hosts and infer links

#### Scenario: Edge cases present
- **WHEN** the lab is queried
- **THEN** it includes a neighbour advertising a management address outside the lab range, an address in the lab range where no agent answers, a table that is supported but empty, and a device without `ifXTable`

### Requirement: Reproducible synthetic data
Synthetic data SHALL be produced by a generator in the repository from a fixed seed and the anonymised real data, so that running it again gives byte-identical files.

#### Scenario: Regenerating
- **WHEN** the generator runs twice
- **THEN** the files are identical, and an automated test checks it

### Requirement: Lab runnable with one command
The lab SHALL start with a Compose override file in which each device has its own address in 10.99.0.0/24 on a dedicated network, and the tests SHALL be able to start the same data locally without Compose.

#### Scenario: Compose lab file
- **WHEN** `docker compose -f docker-compose.yml -f docker-compose.lab.yml up` runs
- **THEN** every lab device answers SNMP on its address, and the collector can reach them

#### Scenario: Tests without Compose
- **WHEN** the client tests run on a developer machine or in CI
- **THEN** they start snmpsim with the lab data on local ports and do not depend on Compose or on the real network

### Requirement: Scripted test agent for what snmpsim cannot do
The tests SHALL include a scripted SNMP agent that answers from a small data set with standard semantics (`noSuchObject` for unknown object types, `noSuchInstance` for unknown instances) and can be told to delay, stop answering mid-walk, return an error status, return non-increasing OIDs or send malformed datagrams.

#### Scenario: Classification tested against both agents
- **WHEN** the classification tests run
- **THEN** the cases that snmpsim can reproduce run against snmpsim, and `noSuchObject`, mid-walk timeouts, error statuses, non-increasing OIDs and malformed responses run against the scripted agent

### Requirement: Real data scoped to the captured device
Behaviour observed in real lab data SHALL be recorded as an observation of that model and firmware on that capture date, never as general behaviour of the vendor, and missing data SHALL be recorded as what was observed, not as lack of support, unless the column probe answered `noSuchObject`.

#### Scenario: Unimplemented MIB
- **WHEN** `srx-01` answers `noSuchObject` for ENTITY-MIB
- **THEN** the vendor note says that ENTITY-MIB was not implemented on that SRX1500 with JUNOS 19.4R3.11, not that Juniper devices lack it

#### Scenario: Supported table without data
- **WHEN** `srx-01` has no LLDP neighbours and the probe of `lldpRemTable` answers `noSuchInstance`
- **THEN** the note says that the LLDP remote table is supported and was empty in that capture, not that LLDP is unsupported

### Requirement: Lab limitations documented
The lab README SHALL state what the lab cannot reproduce, at least that snmpsim never answers `noSuchObject`, that synthetic switches do not prove vendor behaviour, and which hypotheses (H1 to H3, H6) remain pending.

#### Scenario: Reading the limitations
- **WHEN** a reader opens `lab/README.md`
- **THEN** the limitations and pending hypotheses are listed with the reason each one is pending
