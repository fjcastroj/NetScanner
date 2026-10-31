# data-confidentiality Specification

## Purpose

Prevents confidential information from the company network used for testing
(addresses, names, identifiers, captures, credentials) from ever reaching the
repository, which will become public, or its history.

## Requirements

### Requirement: Allowed IPv4 addresses
Files in the repository SHALL contain only these IPv4 addresses:
192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (documentation), the lab
range 10.99.0.0/24, 127.0.0.0/8, 0.0.0.0 and 255.255.255.255. Any other IPv4
address SHALL be reported, including public ones.

#### Scenario: Private address outside the lab range
- **WHEN** a file contains an address such as one in 192.168.0.0/16 or in 10.0.0.0/8 outside 10.99.0.0/24
- **THEN** the confidentiality check fails and reports the file and line

#### Scenario: Lab and documentation addresses
- **WHEN** a file contains 10.99.0.11 or 192.0.2.10
- **THEN** the check does not report them

#### Scenario: OIDs and version numbers are not addresses
- **WHEN** a file contains an OID such as `1.3.6.1.4.1.12356.101.4.1.1` or a version string such as `7.2.5`
- **THEN** the check does not report it as an IP address

### Requirement: Allowed IPv6 addresses
Files in the repository SHALL contain only these IPv6 addresses: 2001:db8::/32
(documentation), `::1`, `::` and the fixed list of link-scope multicast
groups ff02::1, ff02::2, ff02::5, ff02::6, ff02::9, ff02::d, ff02::16,
ff02::fb and ff02::1:2. Any other IPv6 address SHALL be reported, including
link-local and solicited-node addresses, which can embed real identifiers.

#### Scenario: Unique local or global address
- **WHEN** a file contains an address in fc00::/7 or a global unicast address outside 2001:db8::/32
- **THEN** the check fails and reports the file and line

#### Scenario: Link-local address
- **WHEN** a file contains an address in fe80::/10
- **THEN** the check fails and reports the file and line

#### Scenario: Multicast outside the fixed list
- **WHEN** a file contains `ff02::1` or `ff02::fb`
- **THEN** the check does not report them
- **AND** a solicited-node address (`ff02::1:ffXX:XXXX`) or any other multicast group outside the list is reported

#### Scenario: Times and MAC addresses are not IPv6
- **WHEN** a file contains a time such as `12:30:45` or a MAC address written with colons
- **THEN** the IPv6 rule does not report it

### Requirement: Allowed MAC addresses
Files in the repository SHALL contain only these MAC addresses: the RFC 7042
documentation range 00:00:5E:00:53:00 to 00:00:5E:00:53:FF, unicast
addresses with the locally administered bit set, 00:00:00:00:00:00,
FF:FF:FF:FF:FF:FF, and the well-known protocol multicast addresses
01:80:C2:00:00:00 to 01:80:C2:00:00:0F and 01:00:0C:CC:CC:CC. Any other MAC
address SHALL be reported, in any common notation.

#### Scenario: Globally administered unicast MAC
- **WHEN** a file contains a MAC such as 3C:xx:xx:xx:xx:xx with the locally administered bit clear and outside the documentation range
- **THEN** the check fails and reports the file and line

#### Scenario: Allowed MACs in any notation
- **WHEN** a file contains `02:00:00:00:00:01`, `00-00-5E-00-53-1A`, `0000.5e00.5301` or the LLDP multicast `01:80:C2:00:00:0E`
- **THEN** the check does not report them

### Requirement: Local list of confidential terms
The check SHALL also search, case-insensitively, for terms listed in a local
file ignored by Git (company name, domains, site names, naming patterns).
The repository SHALL contain only an example of that file with fictitious
terms.

#### Scenario: Confidential term found
- **WHEN** a staged file contains a term from the local list
- **THEN** the check fails and reports the file and line without printing the matched term

#### Scenario: Local list missing
- **WHEN** the check runs and the local list does not exist (for example in CI)
- **THEN** the address, MAC and secret rules still run and a notice says the term check was skipped

### Requirement: Narrow, justified exceptions
The check SHALL accept exceptions only from a committed allowlist where each
entry names one exact value, the file or files where it may appear and a
reason. Exceptions SHALL NOT disable a rule for a whole file, and the check
SHALL report exceptions that no longer match anything.

#### Scenario: Range notation in documentation
- **WHEN** the specification or the docs name forbidden blocks in CIDR notation, such as `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` or `fe80::/10`, and those exact values are allowlisted for those files
- **THEN** the check does not report them in those files and still reports any other address in the same files

#### Scenario: Negative tests
- **WHEN** the check's own tests need a forbidden value
- **THEN** the tests build the value at run time instead of writing it literally, so no exception is needed

#### Scenario: Stale exception
- **WHEN** an allowlist entry matches no occurrence in its files
- **THEN** the check reports the stale entry so it can be removed

### Requirement: Checks before commit and in CI
The confidentiality check and a secret scanner SHALL run as a Git pre-commit
hook and in the CI workflow, and a failure SHALL block the commit locally and
mark the CI run as failed.

#### Scenario: Commit with confidential data
- **WHEN** the developer tries to commit a file that fails the check
- **THEN** the commit is rejected with the reason and the offending file

#### Scenario: Secret pattern
- **WHEN** a staged file contains something that looks like a credential or private key
- **THEN** the secret scanner rejects the commit

#### Scenario: Repository passes its own check
- **WHEN** the check runs over every tracked file, including this specification, the docs and the tests
- **THEN** it passes using only the allowlist entries described above

### Requirement: Real data kept outside the repository
Raw captures, configuration exports, logs, database dumps and screenshots SHALL
be stored outside the repository folder when they come from the company
network. The repository SHALL ignore the usual file types for such data as a
second line of defence, and SHALL document the procedure.

#### Scenario: Raw capture placed in the repository by mistake
- **WHEN** a file such as `capture.pcap`, `switch.walk` or `backup.sql` is created inside the repository folder
- **THEN** Git ignores it and it cannot be staged without forcing it

#### Scenario: Procedure documented
- **WHEN** a contributor reads `docs/confidentiality.md`
- **THEN** it explains where real data is kept, that only anonymised data enters the repository, that raw data is never given to AI tools, and what to do if something leaks (remove it from the history and rotate any exposed credential)
