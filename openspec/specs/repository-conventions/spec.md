# repository-conventions Specification

## Purpose

Defines the licence, authorship statements, documentation and automated
checks that every contribution to NetScanner must satisfy, as required by
the UNIR Final Degree Project rules.

## Requirements

### Requirement: RNF-11 Open licence
The repository SHALL be licensed under the Apache License 2.0, with the full
licence text in `LICENSE` and a `NOTICE` file that names the author and states
that the project was developed as part of the Final Degree Project (TFE) of
the Bachelor's Degree in Computer Engineering at UNIR.

#### Scenario: Licence files present
- **WHEN** the repository root is inspected
- **THEN** `LICENSE` contains the Apache License 2.0 text and `NOTICE` contains the author and the UNIR TFE statement

### Requirement: Source file headers
Every source file written for the project SHALL start with a header that
contains the SPDX identifier `Apache-2.0`, the copyright holder and the UNIR
TFE statement; this covers Python, TypeScript, JavaScript, CSS, shell,
Dockerfile and YAML configuration files. An automated check SHALL fail when a
file lacks it.

#### Scenario: File without header
- **WHEN** a new source file without the header is added and the checks run
- **THEN** the header check fails and names the file

#### Scenario: Generated and third-party files
- **WHEN** the header check runs
- **THEN** lock files, generated files and vendored assets listed in the check's exclusion list are skipped

### Requirement: Project documentation
The repository SHALL include a `README.md` that states the TFE origin of the
project, what it does, its prerequisites and how to start it, and a
`CHANGELOG.md` updated by every change that alters behaviour.

#### Scenario: README states the academic origin
- **WHEN** a visitor opens the repository page
- **THEN** the README states that NetScanner was developed as part of the Final Degree Project of the Bachelor's Degree in Computer Engineering at UNIR

### Requirement: RNF-10 Automated checks
The repository SHALL provide automated checks that run locally and on every
push and pull request: backend linting and tests, frontend linting, tests and
build, the header and confidentiality checks, the stack test and
`openspec validate --strict`. Tests SHALL NOT need real network devices.

#### Scenario: Checks on push
- **WHEN** a commit is pushed to GitHub
- **THEN** the CI workflow runs all checks and reports failure if any of them fails

#### Scenario: Tests without a network
- **WHEN** the test suites run on a machine with no access to the company network
- **THEN** all tests run using only local or simulated resources

### Requirement: Consistent line endings
The repository SHALL enforce LF line endings for text files so that scripts
and configuration copied into Linux containers work when the repository is
checked out on Windows.

#### Scenario: Checkout on Windows
- **WHEN** the repository is cloned on Windows and the stack is built
- **THEN** shell scripts and configuration files inside the containers have LF line endings and run correctly
