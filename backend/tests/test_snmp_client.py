# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""SNMP client: settings, credentials, read-only surface and canaries (RNF-01, RNF-02, D5)."""

from __future__ import annotations

import ast
import logging
import secrets
import subprocess
import sys
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from netscanner.core.config import EXIT_CONFIG_ERROR
from netscanner.core.logging_setup import MASK, configure_logging
from netscanner.snmp import (
    BoundedClient,
    CredentialError,
    SnmpLimits,
    SnmpV2cCredential,
    SnmpV3Credential,
    Target,
    get_table,
    parse_credential,
)
from netscanner.snmp.walker import Response, ResponseKind

from .conftest import Canaries, SnmpLab, make_settings, run_module
from .snmp_agent import Behaviour, ScriptedAgent, table

SNMP_PACKAGE = Path(__file__).resolve().parents[1] / "src" / "netscanner" / "snmp"
IF_TABLE = get_table("IF-MIB::ifTable")


# --- Settings (design D5) ---------------------------------------------------


def test_snmp_settings_defaults(canaries: Canaries) -> None:
    limits = SnmpLimits.from_settings(make_settings(canaries))
    assert limits == SnmpLimits(
        timeout=3.0, retries=1, max_repetitions=25, max_rows=200_000, max_devices=8
    )


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("NETSCANNER_SNMP_MAX_REPETITIONS", "51"),
        ("NETSCANNER_SNMP_MAX_REPETITIONS", "0"),
        ("NETSCANNER_SNMP_TIMEOUT", "0"),
        ("NETSCANNER_SNMP_TIMEOUT", "-1"),
        ("NETSCANNER_SNMP_RETRIES", "9"),
        ("NETSCANNER_SNMP_MAX_ROWS", "0"),
        ("NETSCANNER_SNMP_MAX_DEVICES", "0"),
    ],
)
def test_out_of_range_settings_refused(canaries: Canaries, variable: str, value: str) -> None:
    env = {
        "NETSCANNER_SECRET_KEY": canaries.secret_key,
        "NETSCANNER_DB_PASSWORD": canaries.db_password,
        variable: value,
    }
    result = run_module("netscanner.collector", env)
    assert result.returncode == EXIT_CONFIG_ERROR
    assert variable in result.stderr
    canaries.assert_absent(result.stdout, result.stderr)


@pytest.mark.parametrize(
    "overrides", [{"max_repetitions": 51}, {"timeout": 0}, {"max_devices": 0}, {"retries": -1}]
)
def test_limits_refuse_out_of_range_values(overrides: dict) -> None:
    with pytest.raises(ValueError, match="NETSCANNER_SNMP_"):
        SnmpLimits(**overrides)


# --- Credentials (design D7) ------------------------------------------------


def v3(**overrides: object) -> dict:
    values: dict[str, object] = {
        "version": "3",
        "user": "lab-user",
        "level": "authPriv",
        "auth_protocol": "SHA-256",
        "auth_key": "auth-" + secrets.token_hex(8),
        "priv_protocol": "AES-128",
        "priv_key": "priv-" + secrets.token_hex(8),
    }
    values.update(overrides)
    return values


def test_supported_credentials_accepted() -> None:
    assert isinstance(parse_credential({"version": "2c", "community": "lab"}), SnmpV2cCredential)
    for auth in ("SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"):
        for priv in ("AES-128", "AES-192", "AES-256"):
            assert isinstance(
                parse_credential(v3(auth_protocol=auth, priv_protocol=priv)), SnmpV3Credential
            )
    no_priv = parse_credential(v3(level="authNoPriv", priv_protocol=None, priv_key=None))
    assert no_priv.priv_key is None


@pytest.mark.parametrize(
    "value",
    [
        {"version": "1", "community": "CANARY"},
        v3(auth_protocol="MD5", auth_key="CANARY-auth-key"),
        v3(priv_protocol="DES", priv_key="CANARY-priv-key"),
        v3(priv_protocol="3DES", priv_key="CANARY-priv-key"),
        v3(level="authPriv", priv_protocol=None, priv_key="CANARY-priv-key"),
        v3(level="noAuthNoPriv", auth_key="CANARY-auth-key"),
        {"version": "2c", "community": "CANARY", "extra": "CANARY"},
    ],
)
def test_unsupported_credentials_refused_without_echoing_secrets(value: dict) -> None:
    canary = "canary-" + secrets.token_hex(8)
    value = {
        k: (v.replace("CANARY", canary) if isinstance(v, str) else v) for k, v in value.items()
    }
    with pytest.raises(CredentialError) as info:
        parse_credential(value)
    assert canary not in str(info.value) and canary not in repr(info.value)


def test_credentials_and_targets_never_show_secrets() -> None:
    canary = "canary-" + secrets.token_hex(8)
    v2 = SnmpV2cCredential(community=canary)
    v3_cred = parse_credential(v3(auth_key=canary + "-a", priv_key=canary + "-p"))
    for obj in (v2, v3_cred, Target("10.99.0.11", v2), Target("10.99.0.11", v3_cred)):
        assert canary not in str(obj) and canary not in repr(obj)


# --- Read-only surface (design D8) ------------------------------------------

READ_ONLY_IMPORTS = {
    "CommunityData",
    "ContextData",
    "ObjectIdentity",
    "ObjectType",
    "SnmpEngine",
    "UdpTransportTarget",
    "UsmUserData",
    "bulk_cmd",
    "get_cmd",
    "errind",
    "rfc1902",
    "rfc1905",
    "univ",
}
SET_NAMES = {"set_cmd", "setCmd", "SetRequestPDU", "SetRequest", "sendSetRequest", "SET"}


def test_snmp_package_is_read_only() -> None:
    for path in SNMP_PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.split(".")[0] in ("pysnmp", "pyasn1")
            ):
                assert path.name == "pysnmp_client.py", f"{path.name} imports the SNMP library"
                for alias in node.names:
                    if alias.name.startswith(("usm", "USM_")):
                        continue  # authentication and privacy protocol identifiers
                    assert alias.name in READ_ONLY_IMPORTS, f"{path.name} imports {alias.name}"
            if isinstance(node, ast.Import):
                assert not any(a.name.split(".")[0] == "pysnmp" for a in node.names)
            name = (
                node.id
                if isinstance(node, ast.Name)
                else node.attr
                if isinstance(node, ast.Attribute)
                else None
            )
            assert name not in SET_NAMES, f"{path.name} references {name}"
    from netscanner.snmp import BoundedClient as Client

    assert not [m for m in dir(Client) if m.lower().startswith("set")]


def test_client_interface_does_not_load_the_library() -> None:
    code = "import sys, netscanner.snmp; print('pysnmp' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


async def test_code_using_the_interface_runs_with_a_fake() -> None:
    class FakeTransport:
        async def get(self, oids: Sequence[tuple[int, ...]]) -> Response:
            return Response(ResponseKind.OK, [(o, 1) for o in oids])

        async def bulk(self, oid: tuple[int, ...], max_repetitions: int) -> Response:
            return Response(ResponseKind.OK, [((*IF_TABLE.oid, 1, 1), 1), ((2,), 0)])

    @asynccontextmanager
    async def fake(target: Target, limits: SnmpLimits) -> AsyncIterator[FakeTransport]:
        yield FakeTransport()

    result = await BoundedClient(fake).walk_table(
        Target("10.99.0.11", SnmpV2cCredential(community="x")), IF_TABLE
    )
    assert (result.outcome, result.rows) == ("ok", {(1,): {"ifIndex": 1}})


# --- Canaries (RNF-01) ------------------------------------------------------

FAST = SnmpLimits(timeout=0.3, retries=0, max_repetitions=10)


def _text(result: object) -> str:
    return repr(result) + str(getattr(result, "error_category", ""))


@pytest.mark.parametrize(
    "behaviour",
    [
        Behaviour(stop_after=0),
        Behaviour(error_status="genErr"),
        Behaviour(garbage=True),
        Behaviour(stop_after=1),
    ],
    ids=["timeout", "error-status", "malformed", "mid-walk-timeout"],
)
async def test_community_canary_absent_in_every_failure(
    behaviour: Behaviour, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    from netscanner.snmp.pysnmp_client import PySnmpClient

    canary = "canary-community-" + secrets.token_hex(8)
    data = table("1.3.6.1.2.1.2.2.1", {2: [b"port"] * 30})
    caplog.set_level(logging.DEBUG)
    async with ScriptedAgent(data, community=canary, behaviour=behaviour) as agent:
        target = Target(agent.host, SnmpV2cCredential(community=canary), port=agent.port)
        result = await PySnmpClient(FAST).walk_table(target, IF_TABLE)
        get_result = await PySnmpClient(FAST).get(target, [IF_TABLE.column_oid("ifDescr")])
    assert result.outcome != "ok"
    texts = [_text(result), _text(get_result), str(target), caplog.text, *capsys.readouterr()]
    assert all(canary not in t for t in texts)


@pytest.mark.lab
@pytest.mark.parametrize("wrong", ["auth_key", "user"])
async def test_v3_keys_absent_on_reports(
    snmp_lab: SnmpLab,
    wrong: str,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from netscanner.snmp.pysnmp_client import PySnmpClient

    canary = "canary-key-" + secrets.token_hex(8)
    values = {
        "user": snmp_lab.v3_user,
        "level": "authPriv",
        "auth_protocol": "SHA-256",
        "auth_key": snmp_lab.v3_auth_key,
        "priv_protocol": "AES-128",
        "priv_key": canary,
    }
    values[wrong] = canary if wrong == "auth_key" else "nobody"
    caplog.set_level(logging.DEBUG)
    target = Target(snmp_lab.host, SnmpV3Credential(**values), port=snmp_lab.port, context="srx-01")
    result = await PySnmpClient(SnmpLimits(timeout=1, retries=0)).walk_table(
        target, get_table("SNMPv2-MIB::system")
    )
    expected = "v3_report:wrongDigest" if wrong == "auth_key" else "v3_report:unknownUserName"
    assert (result.outcome, result.error_category) == ("error", expected)
    texts = [_text(result), str(target), caplog.text, *capsys.readouterr()]
    assert all(canary not in t for t in texts)


async def test_secrets_masked_in_logs_while_in_use(capsys: pytest.CaptureFixture[str]) -> None:
    canary = "canary-community-" + secrets.token_hex(8)
    configure_logging("DEBUG", [])
    log = logging.getLogger("netscanner.test")

    class LoggingTransport:
        async def get(self, oids: Sequence[tuple[int, ...]]) -> Response:
            return Response(ResponseKind.TIMEOUT)

        async def bulk(self, oid: tuple[int, ...], max_repetitions: int) -> Response:
            log.warning("library said: bad community %s", canary)  # a leaky library message
            try:
                raise RuntimeError(f"connect failed for {canary}")
            except RuntimeError:
                log.exception("library failure")
            return Response(ResponseKind.TIMEOUT)

    @asynccontextmanager
    async def leaky(target: Target, limits: SnmpLimits) -> AsyncIterator[LoggingTransport]:
        yield LoggingTransport()

    target = Target("10.99.0.11", SnmpV2cCredential(community=canary))
    await BoundedClient(leaky).walk_table(target, IF_TABLE)
    err = capsys.readouterr().err
    assert "library said: bad community " + MASK in err and canary not in err
    log.warning("after the query: %s", canary)  # no longer in use, no longer masked
    assert canary in capsys.readouterr().err
