# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Registry of the SNMP tables and scalar groups used in iteration 1 (design D1).

Each spec has the OID of the table entry (or scalar group), its columns by
name and sub-identifier, the probe column used to classify a walk without
rows (design D4) and the MIB object name stored in ``snmp_queries``.
``by_columns`` specs are always walked column by column: scalar groups,
whose subtree also holds other tables, and ``entPhysicalTable``, whose
serial number column must never be requested (data minimisation).
"""

from __future__ import annotations

from dataclasses import dataclass

from netscanner.store.registry import check_mib_object

Oid = tuple[int, ...]


def parse_oid(text: str) -> Oid:
    return tuple(int(part) for part in text.strip(".").split("."))


def format_oid(oid: Oid) -> str:
    return ".".join(str(part) for part in oid)


@dataclass(frozen=True)
class TableSpec:
    mib_object: str
    oid: Oid
    columns: dict[str, int]
    probe: str
    by_columns: bool = False

    def __post_init__(self) -> None:
        check_mib_object(self.mib_object)
        if self.probe not in self.columns:
            raise ValueError(f"probe column {self.probe!r} is not a column of {self.mib_object}")

    def column_oid(self, name: str) -> Oid:
        return (*self.oid, self.columns[name])

    def column_name(self, sub_id: int) -> str | None:
        return self._names.get(sub_id)

    @property
    def _names(self) -> dict[int, str]:
        return {sub: name for name, sub in self.columns.items()}


def _spec(
    mib_object: str,
    oid: str,
    columns: dict[str, int],
    probe: str | None = None,
    *,
    by_columns: bool = False,
) -> TableSpec:
    return TableSpec(mib_object, parse_oid(oid), columns, probe or next(iter(columns)), by_columns)


TABLES: dict[str, TableSpec] = {
    spec.mib_object: spec
    for spec in (
        _spec(
            "SNMPv2-MIB::system",
            "1.3.6.1.2.1.1",
            {"sysDescr": 1, "sysObjectID": 2, "sysUpTime": 3, "sysName": 5, "sysServices": 7},
            by_columns=True,
        ),
        _spec(
            "IF-MIB::ifTable",
            "1.3.6.1.2.1.2.2.1",
            {
                "ifIndex": 1,
                "ifDescr": 2,
                "ifType": 3,
                "ifMtu": 4,
                "ifSpeed": 5,
                "ifPhysAddress": 6,
                "ifAdminStatus": 7,
                "ifOperStatus": 8,
                "ifLastChange": 9,
                "ifInOctets": 10,
                "ifInUcastPkts": 11,
                "ifInErrors": 14,
                "ifOutOctets": 16,
                "ifOutUcastPkts": 17,
                "ifOutErrors": 20,
            },
        ),
        _spec(
            "IF-MIB::ifXTable",
            "1.3.6.1.2.1.31.1.1.1",
            {"ifName": 1, "ifHCInOctets": 6, "ifHCOutOctets": 10, "ifHighSpeed": 15, "ifAlias": 18},
        ),
        _spec(
            "IP-MIB::ipAddrTable",
            "1.3.6.1.2.1.4.20.1",
            {"ipAdEntAddr": 1, "ipAdEntIfIndex": 2, "ipAdEntNetMask": 3},
        ),
        _spec(
            "IP-MIB::ipAddressTable",
            "1.3.6.1.2.1.4.34.1",
            {"ipAddressIfIndex": 3, "ipAddressType": 4, "ipAddressPrefix": 5, "ipAddressStatus": 7},
        ),
        _spec(
            "IP-MIB::ipNetToMediaTable",
            "1.3.6.1.2.1.4.22.1",
            {
                "ipNetToMediaIfIndex": 1,
                "ipNetToMediaPhysAddress": 2,
                "ipNetToMediaNetAddress": 3,
                "ipNetToMediaType": 4,
            },
        ),
        _spec(
            "IP-MIB::ipNetToPhysicalTable",
            "1.3.6.1.2.1.4.35.1",
            {"ipNetToPhysicalPhysAddress": 4, "ipNetToPhysicalType": 6, "ipNetToPhysicalState": 7},
        ),
        _spec(
            "ENTITY-MIB::entPhysicalTable",
            "1.3.6.1.2.1.47.1.1.1.1",
            {
                "entPhysicalDescr": 2,
                "entPhysicalClass": 5,
                "entPhysicalName": 7,
                "entPhysicalSoftwareRev": 10,
                "entPhysicalModelName": 13,
            },
            by_columns=True,
        ),
        _spec(
            "LLDP-MIB::lldpLocalSystemData",
            "1.0.8802.1.1.2.1.3",
            {
                "lldpLocChassisIdSubtype": 1,
                "lldpLocChassisId": 2,
                "lldpLocSysName": 3,
                "lldpLocSysDesc": 4,
            },
            by_columns=True,
        ),
        _spec(
            "LLDP-MIB::lldpLocPortTable",
            "1.0.8802.1.1.2.1.3.7.1",
            {"lldpLocPortIdSubtype": 2, "lldpLocPortId": 3, "lldpLocPortDesc": 4},
        ),
        _spec(
            "LLDP-MIB::lldpRemTable",
            "1.0.8802.1.1.2.1.4.1.1",
            {
                "lldpRemChassisIdSubtype": 4,
                "lldpRemChassisId": 5,
                "lldpRemPortIdSubtype": 6,
                "lldpRemPortId": 7,
                "lldpRemPortDesc": 8,
                "lldpRemSysName": 9,
                "lldpRemSysDesc": 10,
                "lldpRemSysCapSupported": 11,
                "lldpRemSysCapEnabled": 12,
            },
        ),
        _spec(
            "LLDP-MIB::lldpRemManAddrTable",
            "1.0.8802.1.1.2.1.4.2.1",
            {"lldpRemManAddrIfSubtype": 3, "lldpRemManAddrIfId": 4},
        ),
        _spec(
            "BRIDGE-MIB::dot1dBase",
            "1.3.6.1.2.1.17.1",
            {"dot1dBaseBridgeAddress": 1, "dot1dBaseNumPorts": 2, "dot1dBaseType": 3},
            by_columns=True,
        ),
        _spec(
            "BRIDGE-MIB::dot1dBasePortTable",
            "1.3.6.1.2.1.17.1.4.1",
            {"dot1dBasePort": 1, "dot1dBasePortIfIndex": 2},
        ),
        _spec(
            "BRIDGE-MIB::dot1dTpFdbTable",
            "1.3.6.1.2.1.17.4.3.1",
            {"dot1dTpFdbAddress": 1, "dot1dTpFdbPort": 2, "dot1dTpFdbStatus": 3},
        ),
        _spec(
            "Q-BRIDGE-MIB::dot1qTpFdbTable",
            "1.3.6.1.2.1.17.7.1.2.2.1",
            {"dot1qTpFdbPort": 2, "dot1qTpFdbStatus": 3},
        ),
        _spec(
            "Q-BRIDGE-MIB::dot1qVlanCurrentTable",
            "1.3.6.1.2.1.17.7.1.4.2.1",
            {
                "dot1qVlanFdbId": 3,
                "dot1qVlanCurrentEgressPorts": 4,
                "dot1qVlanCurrentUntaggedPorts": 5,
                "dot1qVlanStatus": 6,
            },
        ),
    )
}


def get_table(mib_object: str) -> TableSpec:
    try:
        return TABLES[mib_object]
    except KeyError:
        raise KeyError(f"no table spec for {mib_object!r}") from None
