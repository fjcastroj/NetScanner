# Spec Delta

## ADDED Requirements

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
