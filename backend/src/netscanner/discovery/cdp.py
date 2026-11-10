# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""CDP cache parsing (CISCO-CDP-MIB), kept in its own module (RNF-08, design D1).

``cdpCacheTable`` is indexed by ``cdpCacheIfIndex.cdpCacheDeviceIndex``. Only
addresses of type IP (1) with four octets become candidates.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from typing import Any

from netscanner.discovery.mapping import hexstr, text
from netscanner.snmp import TableResult

CDP_ADDRESS_IP = 1


def neighbor_rows(result: TableResult) -> Iterator[dict[str, Any]]:
    """Neighbour entries for the store: local ``ifIndex`` as local port number."""
    for index in result.rows:
        if len(index) != 2:
            continue
        reported = result.reported(index)
        row: dict[str, Any] = {"local_port_num": index[0], "remote_index": index[1]}
        # The device identifier serves as both chassis identifier and system
        # name; the platform has no field in the store and is not kept.
        for column, field, decode in (
            ("cdpCacheDeviceId", "remote_chassis_id", text),
            ("cdpCacheDeviceId", "remote_sys_name", text),
            ("cdpCacheDevicePort", "remote_port_id", text),
            ("cdpCacheCapabilities", "remote_capabilities", hexstr),
        ):
            if column in reported:
                value = reported[column]
                row[field] = None if value is None else decode(value)
        yield row


def addresses(result: TableResult) -> Iterator[str]:
    """Advertised IPv4 addresses, in table order."""
    for _, row in sorted(result.rows.items()):
        if row.get("cdpCacheAddressType") != CDP_ADDRESS_IP:
            continue
        value = row.get("cdpCacheAddress")
        if isinstance(value, bytes) and len(value) == 4:
            yield str(ipaddress.IPv4Address(value))
