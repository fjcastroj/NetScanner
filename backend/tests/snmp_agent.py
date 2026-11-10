# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Scripted SNMPv2c agent for tests (design D11 of add-snmp-client-and-lab).

Test helper, not production code. An asyncio UDP server built on PySNMP's
message encoders that answers GET, GETNEXT and GETBULK from a dict with the
standard semantics snmpsim lacks: ``noSuchObject`` for an OID outside every
known object type, ``noSuchInstance`` for an unknown instance of a known one,
``endOfMibView`` past the last OID. Each test sets its behaviour: a delay,
stop answering after N responses, an error status after N responses,
non-increasing OIDs after N responses, or a garbage datagram.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from pyasn1.codec.ber import decoder, encoder
from pysnmp.proto import api, rfc1902, rfc1905

Oid = tuple[int, ...]
V2C = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]

ERROR_STATUS = {"tooBig": 1, "noSuchName": 2, "genErr": 5, "noAccess": 6, "authorizationError": 16}


def oid(text: str) -> Oid:
    return tuple(int(p) for p in text.strip(".").split("."))


@dataclass
class Behaviour:
    delay: float = 0.0
    stop_after: int | None = None  # responses sent before going silent
    ignore_first: int = 0  # requests ignored before answering (to cause one retry)
    error_status: str | None = None
    error_after: int = 0  # good responses before the error status
    non_increasing_after: int | None = None
    garbage: bool = False
    # Answers to GET only, for ambiguous column probes.
    get_override: dict[Oid, object] = field(default_factory=dict)


@dataclass
class ScriptedAgent:
    data: dict[Oid, object]
    community: str = "scripted"
    # Object types (columns or scalars) the agent implements; by default the
    # parent of every instance OID.
    object_types: set[Oid] | None = None
    behaviour: Behaviour = field(default_factory=Behaviour)
    host: str = "127.0.0.1"
    port: int = 0
    requests: int = 0
    responses: int = 0
    in_flight: int = 0
    max_in_flight: int = 0
    _transport: asyncio.DatagramTransport | None = None

    def __post_init__(self) -> None:
        if self.object_types is None:
            self.object_types = {o[:-1] for o in self.data}
        self._order = sorted(self.data)

    # --- lifecycle --------------------------------------------------------

    async def start(self) -> ScriptedAgent:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self), local_addr=(self.host, self.port)
        )
        self.port = self._transport.get_extra_info("sockname")[1]
        return self

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    async def __aenter__(self) -> ScriptedAgent:
        return await self.start()

    async def __aexit__(self, *exc: object) -> None:
        self.close()

    # --- semantics --------------------------------------------------------

    def _get(self, o: Oid) -> object:
        if o in self.behaviour.get_override:
            return self.behaviour.get_override[o]
        if o in self.data:
            return self.data[o]
        if any(o[: len(t)] == t for t in self.object_types or ()):
            return rfc1905.noSuchInstance
        return rfc1905.noSuchObject

    def _next(self, o: Oid) -> tuple[Oid, object]:
        for candidate in self._order:
            if candidate > o:
                return candidate, self.data[candidate]
        return o, rfc1905.endOfMibView

    def answer(self, request: bytes) -> bytes | None:
        """The response datagram, or None to stay silent."""
        b = self.behaviour
        if self.requests <= b.ignore_first:
            return None
        if b.stop_after is not None and self.responses >= b.stop_after:
            return None
        if b.garbage:
            return b"\x30\x03\x02\x01"  # truncated BER: not an SNMP message
        try:
            message, _ = decoder.decode(request, asn1Spec=V2C.Message())
        except Exception:
            return None
        if str(V2C.apiMessage.get_community(message)) != self.community:
            return None  # SNMPv2c: a wrong community gets silence
        pdu = V2C.apiMessage.get_pdu(message)
        response = V2C.apiMessage.get_response(message)
        rpdu = V2C.apiMessage.get_pdu(response)
        requested = [tuple(vb[0]) for vb in V2C.apiPDU.get_varbinds(pdu)]
        varbinds: list[tuple[Oid, object]] = []
        if b.error_status is not None and self.responses >= b.error_after:
            V2C.apiPDU.set_error_status(rpdu, ERROR_STATUS[b.error_status])
            V2C.apiPDU.set_error_index(rpdu, 1)
            varbinds = [(o, rfc1902.Null()) for o in requested]
        elif b.non_increasing_after is not None and self.responses >= b.non_increasing_after:
            varbinds = [(o, rfc1902.Integer32(0)) for o in requested]  # same OID back
        elif pdu.isSameTypeWith(V2C.GetRequestPDU()):
            varbinds = [(o, self._get(o)) for o in requested]
        elif pdu.isSameTypeWith(V2C.GetNextRequestPDU()):
            varbinds = [self._next(o) for o in requested]
        elif pdu.isSameTypeWith(V2C.GetBulkRequestPDU()):
            repetitions = int(V2C.apiBulkPDU.get_max_repetitions(pdu))
            for start in requested:
                current = start
                for _ in range(max(repetitions, 1)):
                    current, value = self._next(current)
                    varbinds.append((current, value))
                    if value is rfc1905.endOfMibView:
                        break
        else:
            return None  # anything else, SET included, is ignored
        V2C.apiPDU.set_varbinds(rpdu, varbinds)
        return encoder.encode(response)


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, agent: ScriptedAgent) -> None:
        self.agent = agent
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.get_running_loop().create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        agent = self.agent
        agent.requests += 1
        agent.in_flight += 1
        agent.max_in_flight = max(agent.max_in_flight, agent.in_flight)
        try:
            if agent.behaviour.delay:
                await asyncio.sleep(agent.behaviour.delay)
            reply = agent.answer(data)
            if reply is not None and self.transport is not None:
                agent.responses += 1
                self.transport.sendto(reply, addr)
        finally:
            agent.in_flight -= 1


def table(base: str, columns: dict[int, list[object]]) -> dict[Oid, object]:
    """Instances of a table with integer indexes 1..n: {column: [values...]}."""
    root = oid(base)
    return {
        (*root, col, i): v for col, values in columns.items() for i, v in enumerate(values, start=1)
    }
