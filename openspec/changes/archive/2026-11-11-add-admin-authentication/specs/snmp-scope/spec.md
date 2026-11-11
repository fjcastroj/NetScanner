# Spec Delta

## REMOVED Requirements

### Requirement: Lab-only guard until authentication
**Reason**: Administrator authentication now protects every administrative route, which is the condition set by the project for removing the guard. The end-to-end tests of `admin-authentication` show that the settings, credential and run routes answer 401 without a session.
**Migration**: None. Allowed ranges outside the lab range are accepted when saved by an authenticated administrator. The remaining scope rules (deny by default, exclusions, special addresses, frozen scope, enforcement below every SNMP use) are unchanged.
