# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Architecture tests of design D1 (add-discovery-and-basic-inventory).

Static analysis (AST) of every module of the production package
``netscanner``, in the style of the read-only test. Each rule reports the
offending module. Each rule is also run against a small offending sample, to
show it detects what it claims. Static analysis cannot see dynamic imports,
so ``importlib`` and ``__import__`` are forbidden in production code.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "netscanner"

ADAPTER = "netscanner.snmp.pysnmp_client"
TEST_ONLY_ARGUMENTS = {"endpoint_for", "v3_context"}
CLIENT_CONSTRUCTORS = {"PySnmpClient", "BoundedClient"}
# Test-only keyword arguments of other production entry points (D3, D7).
TEST_ONLY_KEYWORDS = {"run_collector": {"client"}}


def modules() -> list[tuple[str, str]]:
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        parts = path.relative_to(PACKAGE.parent).with_suffix("").parts
        name = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
        found.append((name, path.read_text(encoding="utf-8")))
    return found


def _within(module: str, package: str) -> bool:
    return module == package or module.startswith(package + ".")


def _imports(tree: ast.AST) -> list[str]:
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
            names += [f"{node.module}.{a.name}" for a in node.names]
    return names


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


# --- Rules: each returns a list of messages naming the module ----------------


def snmp_library_imports(module: str, tree: ast.AST) -> list[str]:
    """PySNMP only in the adapter; the adapter only from inside netscanner.snmp."""
    found = []
    for name in _imports(tree):
        if name.split(".")[0] == "pysnmp" and module != ADAPTER:
            found.append(f"{module} imports the SNMP library ({name})")
        if _within(name, ADAPTER) and not _within(module, "netscanner.snmp"):
            found.append(f"{module} imports the SNMP adapter {ADAPTER}")
    return found


def authorized_target_construction(module: str, tree: ast.AST) -> list[str]:
    """AuthorizedTarget is called only inside netscanner.scope."""
    if _within(module, "netscanner.scope"):
        return []
    return [
        f"{module} constructs an AuthorizedTarget outside the scope policy"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == "AuthorizedTarget"
    ]


def passed_test_only_arguments(module: str, tree: ast.AST) -> list[str]:
    """endpoint_for, v3_context (D3) and run_collector(client=) are never passed in production."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg in TEST_ONLY_ARGUMENTS:
                found.append(f"{module} passes the test-only argument {keyword.arg}")
        for keyword in node.keywords:
            if keyword.arg in TEST_ONLY_KEYWORDS.get(_call_name(node) or "", ()):
                found.append(
                    f"{module} passes the test-only argument {keyword.arg} to {_call_name(node)}"
                )
        if _call_name(node) == "run_collector" and len(node.args) > 2:
            found.append(f"{module} passes test-only arguments to run_collector positionally")
        # Positionally: the client constructors take at most (resolver, limits).
        if (
            _call_name(node) in CLIENT_CONSTRUCTORS
            and not _within(module, "netscanner.snmp")
            and len(node.args) > 2
        ):
            found.append(f"{module} passes test-only arguments to {_call_name(node)} positionally")
    return found


def credential_decryption(module: str, tree: ast.AST) -> list[str]:
    """CredentialResolver.resolve and the decryption helper only in snmp and credential_store."""
    if _within(module, "netscanner.snmp") or _within(module, "netscanner.credential_store"):
        return []
    found = []
    for name in _imports(tree):
        if _within(name, "netscanner.credential_store.crypto"):
            found.append(f"{module} imports the decryption module ({name})")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name | ast.Attribute):
            ident = node.id if isinstance(node, ast.Name) else node.attr
            if ident == "decrypt_secret":
                found.append(f"{module} references the decryption helper")
        if isinstance(node, ast.Attribute) and node.attr == "resolve":
            owner = node.value
            owner_name = (
                owner.id
                if isinstance(owner, ast.Name)
                else owner.attr
                if isinstance(owner, ast.Attribute)
                else _call_name(owner)
                if isinstance(owner, ast.Call)
                else ""
            )
            if owner_name and "resolver" in owner_name.lower():
                found.append(f"{module} calls CredentialResolver.resolve")
    return found


def dynamic_imports(module: str, tree: ast.AST) -> list[str]:
    """No importlib or __import__: static analysis must see every import."""
    found = []
    for name in _imports(tree):
        if name.split(".")[0] == "importlib":
            found.append(f"{module} imports importlib")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "__import__":
            found.append(f"{module} uses __import__")
    return found


def api_obtains_no_client(module: str, tree: ast.AST) -> list[str]:
    """The API only creates pending runs: it never obtains an SNMP client (D7)."""
    if not _within(module, "netscanner.api"):
        return []
    found = [
        f"{module} imports the SNMP client factory ({name})"
        for name in _imports(tree)
        if _within(name, "netscanner.snmp.factory") or name.endswith(".create_client")
    ]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in {
            *CLIENT_CONSTRUCTORS,
            "create_client",
        }:
            found.append(f"{module} obtains an SNMP client")
    return found


RULES = [
    snmp_library_imports,
    authorized_target_construction,
    passed_test_only_arguments,
    credential_decryption,
    dynamic_imports,
    api_obtains_no_client,
]


def check(module: str, source: str) -> list[str]:
    tree = ast.parse(source)
    return [message for rule in RULES for message in rule(module, tree)]


# --- The production package passes every rule -------------------------------


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.__name__)
def test_production_package(rule) -> None:
    found = [m for name, source in modules() for m in rule(name, ast.parse(source))]
    assert found == [], "\n".join(found)


def test_every_production_module_is_inspected() -> None:
    names = {name for name, _ in modules()}
    assert {ADAPTER, "netscanner.scope.policy", "netscanner.credential_store.resolver"} <= names
    assert any(name.startswith("netscanner.migrations") for name in names)


# --- Each rule detects what it claims and names the module -------------------


@pytest.mark.parametrize(
    ("module", "source", "expected"),
    [
        (
            "netscanner.discovery.engine",
            "import pysnmp",
            "netscanner.discovery.engine imports the SNMP library",
        ),
        (
            "netscanner.snmp.walker",
            "from pysnmp.proto import api",
            "netscanner.snmp.walker imports the SNMP library",
        ),
        (
            "netscanner.collector.service",
            "from netscanner.snmp.pysnmp_client import PySnmpClient",
            "imports the SNMP adapter",
        ),
        (
            "netscanner.discovery.engine",
            "AuthorizedTarget(a, 161, 1, p)",
            "constructs an AuthorizedTarget",
        ),
        (
            "netscanner.discovery.engine",
            "scope.AuthorizedTarget(a, 161, 1, p)",
            "constructs an AuthorizedTarget",
        ),
        (
            "netscanner.collector.service",
            "client = PySnmpClient(r, l, endpoint_for=m)",
            "passes the test-only argument endpoint_for",
        ),
        (
            "netscanner.api.app",
            "c = BoundedClient(f, r, v3_context='x')",
            "passes the test-only argument v3_context",
        ),
        ("netscanner.collector.service", "PySnmpClient(r, l, mapping)", "positionally"),
        (
            "netscanner.collector.__main__",
            "await run_collector(settings, stop, client=lab)",
            "passes the test-only argument client to run_collector",
        ),
        (
            "netscanner.collector.__main__",
            "await service.run_collector(settings, stop, client=lab)",
            "passes the test-only argument client to run_collector",
        ),
        ("netscanner.collector.__main__", "await run_collector(s, stop, e, lab)", "positionally"),
        (
            "netscanner.discovery.engine",
            "await resolver.resolve(1)",
            "calls CredentialResolver.resolve",
        ),
        (
            "netscanner.discovery.engine",
            "await self._resolver.resolve(1)",
            "calls CredentialResolver.resolve",
        ),
        (
            "netscanner.discovery.engine",
            "CredentialResolver(e, k).resolve(1)",
            "calls CredentialResolver.resolve",
        ),
        (
            "netscanner.api.routes",
            "from netscanner.credential_store.crypto import decrypt_secret",
            "decryption",
        ),
        ("netscanner.api.routes", "x = decrypt_secret", "references the decryption helper"),
        ("netscanner.discovery.engine", "import importlib", "imports importlib"),
        ("netscanner.discovery.engine", "m = __import__('pysnmp')", "uses __import__"),
        (
            "netscanner.api.routes",
            "from netscanner.snmp import create_client",
            "imports the SNMP client factory",
        ),
        (
            "netscanner.api.routes",
            "client = create_client(settings, resolver)",
            "obtains an SNMP client",
        ),
    ],
)
def test_rule_detects_and_names_the_module(module: str, source: str, expected: str) -> None:
    found = check(module, source)
    assert any(expected in m and m.startswith(module) for m in found), found


@pytest.mark.parametrize(
    ("module", "source"),
    [
        ("netscanner.snmp.pysnmp_client", "from pysnmp.proto import api"),
        ("netscanner.snmp.factory", "from netscanner.snmp.pysnmp_client import PySnmpClient"),
        ("netscanner.scope.policy", "AuthorizedTarget(a, 161, 1, self, _token=_TOKEN)"),
        (
            "netscanner.snmp.walker",
            "credential = await self._resolver.resolve(target.credential_id)",
        ),
        ("netscanner.credential_store.resolver", "decrypt_secret(row.secret, key)"),
        ("netscanner.migrate", "p = Path(__file__).resolve()"),
        ("netscanner.collector.service", "client = PySnmpClient(resolver, limits)"),
        ("netscanner.collector.service", "from netscanner.snmp import create_client"),
        ("netscanner.collector.service", "client = create_client(settings, resolver)"),
        ("netscanner.collector.__main__", "await run_collector(settings, stop)"),
        ("netscanner.collector.__main__", "await run_collector(settings, stop, engine=engine)"),
    ],
)
def test_allowed_uses_pass(module: str, source: str) -> None:
    assert check(module, source) == []
