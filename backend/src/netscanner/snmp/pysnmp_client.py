# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""PySNMP transport (design D2, D7, D8): the only module that imports PySNMP.

It imports only the GET and GETBULK command functions; there is no code path
that can send a SET. The library's credential objects (``CommunityData``,
``UsmUserData``) and engine are built just before an operation and dropped
after it. PySNMP debug logging is never enabled.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from pyasn1.type import univ
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto import errind, rfc1902, rfc1905

from netscanner.snmp.credentials import SnmpV2cCredential, SnmpV3Credential
from netscanner.snmp.results import SnmpException, SnmpValue, Target
from netscanner.snmp.tables import Oid, format_oid
from netscanner.snmp.walker import BoundedClient, Response, ResponseKind, SnmpLimits, Transport
from netscanner.store.registry import SNMP_ERROR_STATUSES

AUTH = {
    "SHA": usmHMACSHAAuthProtocol,
    "SHA-224": usmHMAC128SHA224AuthProtocol,
    "SHA-256": usmHMAC192SHA256AuthProtocol,
    "SHA-384": usmHMAC256SHA384AuthProtocol,
    "SHA-512": usmHMAC384SHA512AuthProtocol,
}
PRIV = {
    "AES-128": usmAesCfb128Protocol,
    "AES-192": usmAesCfb192Protocol,
    "AES-256": usmAesCfb256Protocol,
}

# USM reports surface as error indications; their counters name the category.
_REPORTS = {
    errind.UnknownUserName: "unknownUserName",
    errind.WrongDigest: "wrongDigest",
    errind.UnsupportedSecurityLevel: "unsupportedSecLevel",
    errind.NotInTimeWindow: "notInTimeWindow",
    errind.UnknownEngineID: "unknownEngineID",
    errind.DecryptionError: "decryptionError",
}


def _auth_data(credential: SnmpV2cCredential | SnmpV3Credential) -> CommunityData | UsmUserData:
    if isinstance(credential, SnmpV2cCredential):
        # SNMPv2c is required by the spec (many devices only offer it); v1 is refused.
        return CommunityData(credential.community.get_secret_value(), mpModel=1)  # noqa: S508
    priv = credential.priv_key.get_secret_value() if credential.priv_key else None
    return UsmUserData(
        credential.user,
        credential.auth_key.get_secret_value(),
        priv,
        authProtocol=AUTH[credential.auth_protocol],
        privProtocol=PRIV[credential.priv_protocol] if credential.priv_protocol else None,
    )


def convert(value: object) -> SnmpValue | SnmpException:
    """Library value to a plain Python value (shared with the comparison)."""
    if isinstance(value, rfc1905.NoSuchObject):
        return SnmpException.NO_SUCH_OBJECT
    if isinstance(value, rfc1905.NoSuchInstance):
        return SnmpException.NO_SUCH_INSTANCE
    if isinstance(value, rfc1905.EndOfMibView):
        return SnmpException.END_OF_MIB_VIEW
    if isinstance(value, rfc1902.IpAddress):  # before OctetString, its base type
        return str(ipaddress.IPv4Address(bytes(value.asOctets())))
    if isinstance(value, univ.ObjectIdentifier):
        return format_oid(tuple(value))
    if isinstance(value, univ.OctetString):  # also Opaque and Bits
        return bytes(value.asOctets())
    return int(value)


class _PySnmpTransport(Transport):
    def __init__(
        self,
        engine: SnmpEngine,
        auth: CommunityData | UsmUserData,
        udp: UdpTransportTarget,
        context: str,
    ) -> None:
        self._engine, self._auth, self._udp = engine, auth, udp
        self._context = ContextData(contextName=context)

    def _response(
        self, indication: object, status: object, varbinds: Sequence[ObjectType]
    ) -> Response:
        if indication is not None:
            if isinstance(indication, errind.RequestTimedOut):
                return Response(ResponseKind.TIMEOUT)
            report = next((n for cls, n in _REPORTS.items() if isinstance(indication, cls)), None)
            if report is not None:
                return Response(ResponseKind.V3_REPORT, detail=report)
            if isinstance(indication, errind.SerializationError | errind.DeserializationError):
                return Response(ResponseKind.DECODE_ERROR)
            return Response(ResponseKind.TRANSPORT_ERROR)
        if status and int(status) != 0:
            name = status.prettyPrint() if hasattr(status, "prettyPrint") else str(status)
            return Response(
                ResponseKind.ERROR_STATUS, detail=name if name in SNMP_ERROR_STATUSES else "genErr"
            )
        return Response(ResponseKind.OK, [(tuple(vb[0]), convert(vb[1])) for vb in varbinds])

    async def get(self, oids: Sequence[Oid]) -> Response:
        objects = [ObjectType(ObjectIdentity(format_oid(o))) for o in oids]
        indication, status, _, varbinds = await get_cmd(
            self._engine, self._auth, self._udp, self._context, *objects, lookupMib=False
        )
        return self._response(indication, status, varbinds)

    async def bulk(self, oid: Oid, max_repetitions: int) -> Response:
        start = ObjectType(ObjectIdentity(format_oid(oid)))
        indication, status, _, varbinds = await bulk_cmd(
            self._engine,
            self._auth,
            self._udp,
            self._context,
            0,
            max_repetitions,
            start,
            lookupMib=False,
        )
        return self._response(indication, status, varbinds)


@asynccontextmanager
async def pysnmp_transport(target: Target, limits: SnmpLimits) -> AsyncIterator[Transport]:
    engine = SnmpEngine()
    try:
        udp = await UdpTransportTarget.create(
            (target.address, target.port), timeout=limits.timeout, retries=limits.retries
        )
        yield _PySnmpTransport(engine, _auth_data(target.credential), udp, target.context)
    finally:
        engine.close_dispatcher()


class PySnmpClient(BoundedClient):
    """The application's SNMP client."""

    def __init__(self, limits: SnmpLimits | None = None) -> None:
        super().__init__(pysnmp_transport, limits)
