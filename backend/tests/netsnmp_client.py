# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Net-SNMP command-line transport, for the library comparison only (design D2, D14).

Not used by the application. It runs ``snmpget`` and ``snmpbulkget`` once per
request with numeric OIDs and hexadecimal strings (``-On -Ox -Ot``) and
plugs into the same :class:`BoundedClient` as the PySNMP transport, so the
contract suite runs against it unchanged. Credentials go on the command
line, which a real implementation could not accept (they are visible in the
process list); that is one of the reasons recorded in
``docs/decisions/snmp-library.md``.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from netscanner.snmp.credentials import SnmpV2cCredential
from netscanner.snmp.results import SnmpException, SnmpValue, Target
from netscanner.snmp.tables import Oid, format_oid, parse_oid
from netscanner.snmp.walker import BoundedClient, Response, ResponseKind, SnmpLimits, Transport

AUTH = {
    "SHA": "SHA",
    "SHA-224": "SHA-224",
    "SHA-256": "SHA-256",
    "SHA-384": "SHA-384",
    "SHA-512": "SHA-512",
}
PRIV = {"AES-128": "AES", "AES-192": "AES-192", "AES-256": "AES-256"}

EXCEPTIONS = {
    "No Such Object available on this agent at this OID": SnmpException.NO_SUCH_OBJECT,
    "No Such Instance currently exists at this OID": SnmpException.NO_SUCH_INSTANCE,
    "No more variables left in this MIB View (It is past the end of the MIB tree)": (
        SnmpException.END_OF_MIB_VIEW
    ),
}
# Net-SNMP spells some error statuses differently from RFC 3416.
STATUS_NAMES = {
    "genError": "genErr",
    "tooBig": "tooBig",
    "noSuchName": "noSuchName",
    "noAccess": "noAccess",
}
REPORTS = {
    "Unknown user name": "unknownUserName",
    "Authentication failure (incorrect password, community or key)": "wrongDigest",
    "Unsupported security level": "unsupportedSecLevel",
    "Decryption error": "decryptionError",
}
LINE = re.compile(r"^(\.[0-9.]+) = (.*)$")


def available() -> bool:
    return shutil.which("snmpget") is not None and shutil.which("snmpbulkget") is not None


def parse_value(text: str) -> SnmpValue | SnmpException:
    if text in EXCEPTIONS:
        return EXCEPTIONS[text]
    if text == '""':
        return b""
    kind, _, value = text.partition(": ")
    if not _:
        return int(text)  # -Ot prints TimeTicks as a bare number
    if kind == "Hex-STRING" or kind in ("BITS", "Opaque"):
        return bytes.fromhex(value.split("  ")[0] if kind == "BITS" else value)
    if kind == "OID":
        return value.lstrip(".")
    if kind == "IpAddress":
        return value
    return int(value.split()[0])  # INTEGER, Counter32/64, Gauge32, UInteger32


def parse_output(text: str) -> list[tuple[Oid, SnmpValue | SnmpException]]:
    """Varbind lines, joining the continuation lines of long hex strings."""
    entries: list[list[str]] = []
    for line in text.splitlines():
        m = LINE.match(line)
        if m:
            entries.append([m.group(1), m.group(2).rstrip()])
        elif entries and line.strip():
            entries[-1][1] += " " + line.strip()
    return [(parse_oid(oid), parse_value(value)) for oid, value in entries]


class NetSnmpTransport(Transport):
    def __init__(self, target: Target, limits: SnmpLimits) -> None:
        self.target, self.limits = target, limits

    def _common(self) -> list[str]:
        c = self.target.credential
        args = ["-On", "-Ox", "-Ot", "-t", str(self.limits.timeout), "-r", str(self.limits.retries)]
        if isinstance(c, SnmpV2cCredential):
            args += ["-v2c", "-c", c.community.get_secret_value()]
        else:
            args += [
                "-v3",
                "-u",
                c.user,
                "-l",
                c.level,
                "-a",
                AUTH[c.auth_protocol],
                "-A",
                c.auth_key.get_secret_value(),
            ]
            if c.priv_protocol and c.priv_key:
                args += ["-x", PRIV[c.priv_protocol], "-X", c.priv_key.get_secret_value()]
            if self.target.context:
                args += ["-n", self.target.context]
        return [*args, f"udp:{self.target.address}:{self.target.port}"]

    async def _run(self, tool: str, extra: list[str], oids: Sequence[Oid]) -> Response:
        process = await asyncio.create_subprocess_exec(
            tool, *extra, *self._common(), *(format_oid(o) for o in oids),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )  # fmt: skip
        out, err = await process.communicate()
        text, errors = out.decode(errors="replace"), err.decode(errors="replace")
        if "Timeout: No Response" in errors or "Timeout: No Response" in text:
            return Response(ResponseKind.TIMEOUT)
        for message, counter in REPORTS.items():
            if message in errors:
                return Response(ResponseKind.V3_REPORT, detail=counter)
        # "Reason: (genError) ..." or "Reason: authorizationError (...)".
        reason = re.search(r"Reason: \(?(\w+)\)?", text + errors)
        if reason:
            return Response(
                ResponseKind.ERROR_STATUS, detail=STATUS_NAMES.get(reason.group(1), reason.group(1))
            )
        if process.returncode != 0:
            return Response(ResponseKind.TRANSPORT_ERROR)
        try:
            return Response(ResponseKind.OK, parse_output(text))
        except ValueError:
            return Response(ResponseKind.DECODE_ERROR)

    async def get(self, oids: Sequence[Oid]) -> Response:
        return await self._run("snmpget", [], oids)

    async def bulk(self, oid: Oid, max_repetitions: int) -> Response:
        return await self._run("snmpbulkget", ["-Cn0", f"-Cr{max_repetitions}"], [oid])


@asynccontextmanager
async def netsnmp_transport(target: Target, limits: SnmpLimits) -> AsyncIterator[Transport]:
    yield NetSnmpTransport(target, limits)


class NetSnmpClient(BoundedClient):
    def __init__(self, limits: SnmpLimits | None = None) -> None:
        super().__init__(netsnmp_transport, limits)
