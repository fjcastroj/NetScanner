# Spec Delta

## MODIFIED Requirements

### Requirement: Allowed IPv4 addresses
Files in the repository SHALL contain only these IPv4 addresses: 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (documentation), the lab range 10.99.0.0/24, 127.0.0.0/8, 0.0.0.0 and 255.255.255.255, and contiguous netmasks only in the netmask column of lab data files. Any other IPv4 address SHALL be reported, including public ones.

#### Scenario: Private address outside the lab range
- **WHEN** a file contains an address such as one in 192.168.0.0/16 or in 10.0.0.0/8 outside 10.99.0.0/24
- **THEN** the confidentiality check fails and reports the file and line

#### Scenario: Lab and documentation addresses
- **WHEN** a file contains 10.99.0.11 or 192.0.2.10
- **THEN** the check does not report them

#### Scenario: OIDs and version numbers are not addresses
- **WHEN** a file contains an OID such as `1.3.6.1.4.1.12356.101.4.1.1` or a version string such as `7.2.5`
- **THEN** the check does not report it as an IP address

#### Scenario: Netmask in the netmask column of lab data
- **WHEN** a `.snmprec` file under `lab/` has a line for `ipAdEntNetMask` (`1.3.6.1.2.1.4.20.1.3.`) whose value is a contiguous netmask, for example the dotted form of a /26 mask
- **THEN** the check does not report it

#### Scenario: Netmask-like value elsewhere
- **WHEN** the dotted form of a netmask appears in any other column, in any other file type or outside `lab/`
- **THEN** the check reports it as usual

#### Scenario: Non-contiguous value in the netmask column
- **WHEN** the netmask column of a lab file contains a value that is not a contiguous netmask
- **THEN** the check reports it
