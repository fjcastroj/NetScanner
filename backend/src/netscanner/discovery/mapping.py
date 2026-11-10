# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Mapping of SNMP results to store rows (design D9).

A complete walk passes every expected column, with ``None`` for a column
missing in a row (absent); a partial walk passes only the columns received
(the rest not retrieved). That is ``TableResult.reported``: discovery adds no
rule of its own. Values are decoded here; validation stays in the store.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterator
from typing import Any

from netscanner.snmp import GetResult, TableResult
from netscanner.snmp.tables import Oid, parse_oid

Address = ipaddress.IPv4Address | ipaddress.IPv6Address

SYSTEM_OIDS = {
    "sys_descr": parse_oid("1.3.6.1.2.1.1.1.0"),
    "sys_object_id": parse_oid("1.3.6.1.2.1.1.2.0"),
    "sys_uptime": parse_oid("1.3.6.1.2.1.1.3.0"),
    "sys_name": parse_oid("1.3.6.1.2.1.1.5.0"),
}
ENT_CLASS_CHASSIS = 3
LLDP_SUBTYPE_MAC = {"chassis": 4, "port": 3}
INET_IPV4, INET_IPV6 = 1, 2


def text(value: Any) -> Any:
    """DisplayString values as text; anything that is not bytes unchanged."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def mac(value: Any) -> Any:
    if isinstance(value, bytes):
        return ":".join(f"{b:02x}" for b in value)
    return value


def hexstr(value: Any) -> Any:
    return value.hex() if isinstance(value, bytes) else value


def _fields(
    result: TableResult, index: Oid, columns: dict[str, tuple[str, Callable[[Any], Any]]]
) -> dict[str, Any]:
    """Store fields of one row in the store's contract (``reported``)."""
    reported = result.reported(index)
    out: dict[str, Any] = {}
    for column, (field, decode) in columns.items():
        if column in reported:
            value = reported[column]
            out[field] = None if value is None else decode(value)
    return out


def _same(value: Any) -> Any:
    return value


def inet_address(kind: int, octets: tuple[int, ...]) -> Address | None:
    """An InetAddress (type, then octets) as an IP address; other types give None."""
    if kind == INET_IPV4 and len(octets) == 4:
        return ipaddress.IPv4Address(bytes(octets))
    if kind == INET_IPV6 and len(octets) == 16:
        return ipaddress.IPv6Address(bytes(octets))
    return None


def _length_prefixed(index: Oid, start: int) -> tuple[int, tuple[int, ...]] | None:
    """(type, octets) of an InetAddressType + length-prefixed InetAddress index part."""
    if len(index) < start + 2:
        return None
    kind, length = index[start], index[start + 1]
    octets = index[start + 2 : start + 2 + length]
    return (kind, octets) if len(octets) == length else None


# --- System group -----------------------------------------------------------


def system_row(result: GetResult) -> dict[str, Any]:
    """System group from a complete GET: a missing scalar is reported absent."""
    row: dict[str, Any] = {}
    for field, oid in SYSTEM_OIDS.items():
        value = result.values.get(oid)
        row[field] = text(value) if field in ("sys_descr", "sys_name") else value
    return row


# --- Addresses --------------------------------------------------------------


def ip_address_table_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    """``ipAddressTable``: index InetAddressType.length.address."""
    for index in result.rows:
        parsed = _length_prefixed(index, 0)
        address = inet_address(*parsed) if parsed else None
        if address is None:
            continue  # zoned or unknown address types are not device addresses here
        yield {
            "address": str(address),
            **_fields(result, index, {"ipAddressIfIndex": ("if_index", _same)}),
        }


def ip_addr_table_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    """``ipAddrTable``: index is the IPv4 address."""
    for index in result.rows:
        if len(index) != 4:
            continue
        address = str(ipaddress.IPv4Address(bytes(index)))
        yield {
            "address": address,
            **_fields(result, index, {"ipAdEntIfIndex": ("if_index", _same)}),
        }


# --- Interfaces -------------------------------------------------------------

IF_TABLE_COLUMNS = {
    "ifDescr": ("if_descr", text),
    "ifType": ("if_type", _same),
    "ifSpeed": ("if_speed", _same),
    "ifPhysAddress": ("phys_address", _same),
    "ifAdminStatus": ("admin_status", _same),
    "ifOperStatus": ("oper_status", _same),
    "ifLastChange": ("last_change", _same),
}
IF_XTABLE_COLUMNS = {
    "ifName": ("if_name", text),
    "ifAlias": ("if_alias", text),
    "ifHighSpeed": ("if_high_speed", _same),
}


def if_table_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    for index in result.rows:
        if len(index) == 1:
            yield {"if_index": index[0], **_fields(result, index, IF_TABLE_COLUMNS)}


def if_xtable_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    for index in result.rows:
        if len(index) == 1:
            yield {"if_index": index[0], **_fields(result, index, IF_XTABLE_COLUMNS)}


# --- ENTITY-MIB ---------------------------------------------------------------


def chassis_model(result: TableResult) -> dict[str, Any] | None:
    """Model and version of the chassis entry, or None when there is none."""
    for index, row in sorted(result.rows.items()):
        if row.get("entPhysicalClass") == ENT_CLASS_CHASSIS:
            return _fields(
                result,
                index,
                {
                    "entPhysicalModelName": ("model", text),
                    "entPhysicalSoftwareRev": ("software_version", text),
                },
            )
    return None


# --- LLDP -------------------------------------------------------------------


def lldp_chassis(result: TableResult) -> tuple[int, str] | None:
    row = result.rows.get((0,), {})
    subtype, value = row.get("lldpLocChassisIdSubtype"), row.get("lldpLocChassisId")
    if not isinstance(subtype, int) or not isinstance(value, bytes) or not value:
        return None
    return subtype, lldp_id(subtype, value, "chassis")


def lldp_id(subtype: Any, value: Any, kind: str) -> Any:
    """Chassis or port identifier as text: MAC subtypes in colon notation."""
    if subtype == LLDP_SUBTYPE_MAC[kind] and isinstance(value, bytes) and len(value) == 6:
        return mac(value)
    return text(value)


def local_port_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    for index, row in result.rows.items():
        if len(index) != 1:
            continue
        fields = _fields(
            result,
            index,
            {
                "lldpLocPortIdSubtype": ("port_id_subtype", _same),
                "lldpLocPortDesc": ("port_desc", text),
            },
        )
        if "lldpLocPortId" in row:
            fields["port_id"] = lldp_id(
                row.get("lldpLocPortIdSubtype"), row["lldpLocPortId"], "port"
            )
        yield {"local_port_num": index[0], **fields}


def remote_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    """``lldpRemTable``: index timeMark.localPortNum.remIndex (the time mark is dropped)."""
    for index, row in result.rows.items():
        if len(index) != 3:
            continue
        fields = _fields(
            result,
            index,
            {
                "lldpRemChassisIdSubtype": ("remote_chassis_id_subtype", _same),
                "lldpRemPortIdSubtype": ("remote_port_id_subtype", _same),
                "lldpRemSysName": ("remote_sys_name", text),
                "lldpRemPortDesc": ("remote_port_desc", text),
                "lldpRemSysCapEnabled": ("remote_capabilities", hexstr),
            },
        )
        for column, field, kind, subtype in (
            ("lldpRemChassisId", "remote_chassis_id", "chassis", "lldpRemChassisIdSubtype"),
            ("lldpRemPortId", "remote_port_id", "port", "lldpRemPortIdSubtype"),
        ):
            reported = result.reported(index)
            if column in reported:
                value = reported[column]
                fields[field] = None if value is None else lldp_id(row.get(subtype), value, kind)
        yield {"local_port_num": index[1], "remote_index": index[2], **fields}


def management_address_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    """``lldpRemManAddrTable``: index timeMark.port.remIndex.subtype.length.address."""
    for index in result.rows:
        parsed = _length_prefixed(index, 3)
        address = inet_address(*parsed) if parsed else None
        if address is not None:
            yield {"local_port_num": index[1], "remote_index": index[2], "address": str(address)}


# --- IP-MAC -----------------------------------------------------------------


def ip_net_to_physical_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    """``ipNetToPhysicalTable``: index ifIndex.InetAddressType.length.address."""
    for index, row in result.rows.items():
        parsed = _length_prefixed(index, 1)
        address = inet_address(*parsed) if parsed else None
        if address is None or "ipNetToPhysicalPhysAddress" not in row:
            continue
        yield {
            "if_index": index[0],
            "ip_address": str(address),
            "mac_address": row["ipNetToPhysicalPhysAddress"],
            "entry_type": row.get("ipNetToPhysicalType"),
        }


def ip_net_to_media_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    """``ipNetToMediaTable``: index ifIndex.IPv4 address."""
    for index, row in result.rows.items():
        if len(index) != 5 or "ipNetToMediaPhysAddress" not in row:
            continue
        yield {
            "if_index": index[0],
            "ip_address": str(ipaddress.IPv4Address(bytes(index[1:]))),
            "mac_address": row["ipNetToMediaPhysAddress"],
            "entry_type": row.get("ipNetToMediaType"),
        }
