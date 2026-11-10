# Spec Delta

## MODIFIED Requirements

### Requirement: Small network for iteration 1
The lab SHALL form a small network: the real firewall `srx-01`, a synthetic switch with LLDP towards a second synthetic switch, forwarding entries for MAC addresses taken from the firewall's IP-MAC table, and a second synthetic switch without LLDP-MIB and with 32-bit counters only. The first synthetic switch SHALL also hold a small `ipNetToPhysicalTable`, produced by the generator, with entries for `srx-01` (its management address and its MAC address, derived from `srx-01`), for the second switch and for the address where no agent answers, so that IP-MAC following can reach lab addresses.

#### Scenario: Consistent addresses across devices
- **WHEN** the synthetic switches are generated
- **THEN** the MAC addresses of their forwarding entries and the addresses of their neighbours match those in `srx-01` and in each other, so that later changes can locate hosts and infer links

#### Scenario: Edge cases present
- **WHEN** the lab is queried
- **THEN** it includes a neighbour advertising a management address outside the lab range, an address in the lab range where no agent answers, a table that is supported but empty, and a device without `ifXTable`

#### Scenario: IP-MAC entries towards lab addresses
- **WHEN** `lab-sw-01`'s `ipNetToPhysicalTable` is read
- **THEN** it holds exactly the entries for 10.99.0.13 with `srx-01`'s MAC address, for 10.99.0.3 with `lab-sw-02`'s MAC address and for 10.99.0.9 with an invented MAC address, and the manifest lists the `srx-01` MAC address among the values derived from `srx-01`
