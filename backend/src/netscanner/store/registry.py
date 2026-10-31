# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Registries of names that are stored as text and validated in code (design D8, D12).

MIB objects, methods, query outcomes, indicators, error categories and vendor
enterprise numbers live here, so adding one needs no migration. Unknown names
are rejected before anything is written.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from netscanner.store.errors import UnknownNameError

# --- MIB objects ------------------------------------------------------------

MIB_OBJECTS: frozenset[str] = frozenset(
    {
        "SNMPv2-MIB::system",
        "ENTITY-MIB::entPhysicalTable",
        "LLDP-MIB::lldpLocalSystemData",
        "LLDP-MIB::lldpLocPortTable",
        "LLDP-MIB::lldpRemTable",
        "LLDP-MIB::lldpRemManAddrTable",
        "CISCO-CDP-MIB::cdpCacheTable",
        "IF-MIB::ifTable",
        "IF-MIB::ifXTable",
        "IP-MIB::ipAddressTable",
        "IP-MIB::ipAddrTable",
        "IP-MIB::ipNetToPhysicalTable",
        "IP-MIB::ipNetToMediaTable",
    }
)

ADDRESS_TABLES = frozenset({"IP-MIB::ipAddressTable", "IP-MIB::ipAddrTable"})
IP_MAC_TABLES = frozenset({"IP-MIB::ipNetToPhysicalTable", "IP-MIB::ipNetToMediaTable"})
NEIGHBOR_TABLES = {"LLDP-MIB::lldpRemTable": "lldp", "CISCO-CDP-MIB::cdpCacheTable": "cdp"}


def check_mib_object(name: str) -> str:
    if name not in MIB_OBJECTS:
        raise UnknownNameError(f"unknown MIB object: {name!r}")
    return name


# --- Methods ----------------------------------------------------------------


class Origin(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"


@dataclass(frozen=True)
class Method:
    """A registered derivation (observed) or inference (inferred) method."""

    name: str
    origin: Origin
    version: int
    description: str
    assumptions: str


_METHODS = (
    Method(
        "ifhighspeed-when-ifspeed-saturated",
        Origin.OBSERVED,
        1,
        "Speed in bit/s from ifHighSpeed (Mbit/s) when ifSpeed is at its maximum.",
        "None beyond IF-MIB: ifSpeed reports 4294967295 when the speed does not fit.",
    ),
    Method(
        "ipaddress-ifindex",
        Origin.OBSERVED,
        1,
        "Address linked to the interface whose ifIndex the address table names.",
        "None beyond IP-MIB: ipAddressIfIndex and ipAdEntIfIndex are ifIndex values.",
    ),
    Method(
        "ip-mac-ifindex",
        Origin.OBSERVED,
        1,
        "IP-MAC entry linked to the interface whose ifIndex the entry names.",
        "None beyond IP-MIB: ipNetToPhysicalIfIndex and ipNetToMediaIfIndex are ifIndex values.",
    ),
    Method(
        "cdp-cache-ifindex",
        Origin.OBSERVED,
        1,
        "CDP neighbour entry linked to the interface whose ifIndex is its cdpCacheIfIndex.",
        "None beyond CISCO-CDP-MIB: cdpCacheIfIndex is the ifIndex of the local interface.",
    ),
    Method(
        "lldp-portid-ifname",
        Origin.OBSERVED,
        1,
        "LLDP local port mapped to the interface whose ifName equals the port id.",
        "None beyond 802.1AB: port id subtype interfaceName(5) carries ifName.",
    ),
    Method(
        "lldp-portnum-equals-ifindex",
        Origin.INFERRED,
        1,
        "LLDP local port mapped to the interface whose ifIndex equals lldpLocPortNum.",
        "Assumes lldpLocPortNum equals ifIndex, which 802.1AB does not guarantee (H1).",
    ),
    Method(
        "lldp-port-description-match",
        Origin.INFERRED,
        1,
        "LLDP local port mapped to the only interface whose ifDescr equals lldpLocPortDesc.",
        "Assumes descriptions are unique and copied verbatim; a heuristic.",
    ),
    Method(
        "enterprise-registry",
        Origin.INFERRED,
        1,
        "Vendor name looked up from the enterprise number of sysObjectID.",
        "Assumes the enterprise that owns the agent's OID made the hardware; false for "
        "OEM devices and generic agents, which the registry marks.",
    ),
    Method(
        "sysdescr-model-pattern",
        Origin.INFERRED,
        1,
        "Model and software version taken from 'model <x>' and 'version <y>' fragments "
        "of sysDescr.",
        "Assumes sysDescr labels them with these words; free text with no standard format.",
    ),
    Method(
        "chassis-id",
        Origin.INFERRED,
        1,
        "Observations attached to the device that reported the same LLDP chassis id.",
        "Assumes chassis ids are unique and stable, which no standard guarantees (H3).",
    ),
    Method(
        "address",
        Origin.INFERRED,
        1,
        "Observations attached to the device already known at the queried address.",
        "Assumes the address still belongs to the same device; addresses are not identities.",
    ),
)

METHODS: dict[str, Method] = {m.name: m for m in _METHODS}
IDENTITY_METHODS = frozenset({"chassis-id", "address"})


def get_method(name: str) -> Method:
    try:
        return METHODS[name]
    except KeyError:
        raise UnknownNameError(f"unknown method: {name!r}") from None


# --- Query outcomes ---------------------------------------------------------


class Outcome(StrEnum):
    OK = "ok"
    EMPTY = "empty"
    NOT_AVAILABLE = "not_available"
    NO_RESPONSE = "no_response"
    PARTIAL = "partial"
    ERROR = "error"


COMPLETE_OUTCOMES = frozenset({Outcome.OK, Outcome.EMPTY})
INDICATOR_OUTCOMES = frozenset({Outcome.EMPTY, Outcome.NOT_AVAILABLE})


class Indicator(StrEnum):
    """What the device returned that an empty or not available outcome is based on."""

    NO_SUCH_OBJECT = "noSuchObject"
    NO_SUCH_INSTANCE = "noSuchInstance"
    END_OF_MIB_VIEW = "endOfMibView"
    END_OF_SUBTREE = "end_of_subtree"


class Operation(StrEnum):
    GET = "get"
    GETNEXT = "getnext"
    GETBULK = "getbulk"
    WALK = "walk"


class SnmpVersion(StrEnum):
    V1 = "1"
    V2C = "2c"
    V3 = "3"


ERROR_CATEGORIES: frozenset[str] = frozenset(
    {
        "snmp-error-status",
        "decode-error",
        "transport-error",
        "validation-error",
        "database-error",
        "internal-error",
    }
)


def check_error_category(name: str) -> str:
    if name not in ERROR_CATEGORIES:
        # Not echoed: a wrong category may be raw exception text.
        raise UnknownNameError("unknown error category")
    return name


# --- Vendors ----------------------------------------------------------------

VENDORS: dict[int, str] = {
    9: "Cisco",
    11: "HPE",
    2636: "Juniper",
    12356: "Fortinet",
    14823: "Aruba",
    14988: "MikroTik",
    41112: "Ubiquiti",
}
# Enterprise numbers of generic SNMP agents: they do not identify the hardware vendor.
GENERIC_AGENTS: dict[int, str] = {8072: "Net-SNMP"}


class VendorStatus(StrEnum):
    KNOWN = "known"
    GENERIC_AGENT = "generic_agent"
    NOT_IN_REGISTRY = "not_in_registry"


def lookup_vendor(enterprise_number: int) -> tuple[VendorStatus, str | None]:
    if enterprise_number in GENERIC_AGENTS:
        return VendorStatus.GENERIC_AGENT, None
    if enterprise_number in VENDORS:
        return VendorStatus.KNOWN, VENDORS[enterprise_number]
    return VendorStatus.NOT_IN_REGISTRY, None


ENTERPRISES_PREFIX = "1.3.6.1.4.1."


def enterprise_number(sys_object_id: str) -> int | None:
    """Enterprise number in a ``sysObjectID`` (decoding, hence observed)."""
    if not sys_object_id.startswith(ENTERPRISES_PREFIX):
        return None
    head = sys_object_id[len(ENTERPRISES_PREFIX) :].split(".", 1)[0]
    return int(head) if head.isdigit() else None
