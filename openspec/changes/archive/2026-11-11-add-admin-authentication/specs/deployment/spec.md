# Spec Delta

## ADDED Requirements

### Requirement: Administrator commands in the deployment
The deployment documentation SHALL give the commands to create the administrator and reset its password with Docker Compose, and SHALL state that exposing NetScanner beyond the local machine requires a reverse proxy with TLS in front of the `web` service.

#### Scenario: First start
- **WHEN** an operator follows the README on a new installation
- **THEN** they create the administrator with one documented command and can log in

### Requirement: Stack test covers authentication
The automated stack test SHALL create an administrator with a throwaway password, check that settings, credential, run and inventory routes answer 401 without a session through the web port, log in, run a lab discovery, and log out.

#### Scenario: Stack test with authentication
- **WHEN** the stack test runs
- **THEN** the protected routes answer 401 before login, the lab run completes after login, and the same routes answer 401 again after logout
