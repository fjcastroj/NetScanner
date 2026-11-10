# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Scope policy, lab-only guard and settings limits (snmp-scope spec, design D2, D6).

Property-style: each rule is checked over every address of small ranges and
over sampled addresses of larger ones, in IPv4 and IPv6, instead of a few
examples.
"""

from __future__ import annotations

import ipaddress

import pytest

from netscanner.core.config import Settings
from netscanner.scope import (
    AuthorizedTarget,
    DiscoveryCeilings,
    LimitsAboveCeiling,
    Rejection,
    ScopeError,
    ScopePolicy,
    SettingsError,
    check_run_limits,
    run_parameters_for,
    validate_settings,
)
from netscanner.store.runs import RunLimits, RunParameters

from .conftest import Canaries, make_settings, run_module

LAB = "10.99.0.0/24"


def reason(policy: ScopePolicy, address: str) -> str | None:
    result = policy.authorize(address)
    return result.reason if isinstance(result, Rejection) else None


# --- Deny by default, exclusion wins ----------------------------------------


def test_empty_scope_refused() -> None:
    with pytest.raises(ScopeError) as info:
        ScopePolicy.build([])
    assert info.value.category == "empty_scope"


def test_deny_by_default_outside_every_allowed_range() -> None:
    policy = ScopePolicy.build(["10.99.0.0/26"])
    for i in range(1, 255):
        address = f"10.99.0.{i}"
        inside = 0 < i < 63  # network .0 and broadcast .63 are special
        assert (reason(policy, address) is None) is inside, address
    for address in ("192.0.2.10", "203.0.113.10", "198.51.100.1", "2001:db8::1"):
        assert reason(policy, address) == "out_of_scope"


def test_exclusion_wins_inside_allowed() -> None:
    policy = ScopePolicy.build([LAB], ["10.99.0.3/32", "10.99.0.64/28"])
    for i in range(1, 255):
        address = f"10.99.0.{i}"
        expected = "excluded" if i == 3 or 64 <= i < 80 else None
        assert reason(policy, address) == expected, address


def test_ipv6_scope() -> None:
    policy = ScopePolicy.build(["::1/128"], ["::1/128"])
    assert reason(policy, "::1") == "excluded"
    assert reason(ScopePolicy.build(["::1/128"]), "::1") is None
    assert reason(ScopePolicy.build(["::1/128"]), "2001:db8::5") == "out_of_scope"


# --- Special addresses ------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "224.0.0.1",
        "239.255.255.250",
        "ff02::1",
        "ff05::2",
        "255.255.255.255",
        "0.0.0.0",
        "::",
        "169.254.10.20",
        "fe80::1",
    ],
)
def test_special_addresses_refused_even_when_allowed(address: str) -> None:
    # Allowed ranges never contain them under the lab guard; build the policy
    # directly to show the rule does not depend on the guard.
    network = ipaddress.ip_network(address).supernet(new_prefix=0)
    policy = ScopePolicy((network,), ())
    assert reason(policy, address) == "special_address"


def test_loopback_only_when_a_loopback_range_is_allowed() -> None:
    lab_only = ScopePolicy.build([LAB])
    assert reason(lab_only, "127.0.0.1") == "special_address"
    assert reason(lab_only, "::1") == "special_address"
    with_loopback = ScopePolicy.build([LAB, "127.0.0.0/8", "::1/128"])
    for address in ("127.0.0.1", "127.1.2.3", "::1"):
        assert reason(with_loopback, address) is None
    # A wide range that merely contains loopback does not allow it.
    assert (
        reason(ScopePolicy((ipaddress.ip_network("0.0.0.0/0"),), ()), "127.0.0.1")
        == "special_address"
    )


@pytest.mark.parametrize("prefix", [24, 25, 26, 27, 28, 29, 30])
def test_network_and_broadcast_of_ranges_up_to_slash_30_refused(prefix: int) -> None:
    network = ipaddress.ip_network(f"10.99.0.0/{prefix}")
    policy = ScopePolicy.build([str(network)])
    assert reason(policy, str(network.network_address)) == "special_address"
    assert reason(policy, str(network.broadcast_address)) == "special_address"
    for host in network.hosts():
        assert reason(policy, str(host)) is None


@pytest.mark.parametrize("network", ["10.99.0.4/31", "10.99.0.6/32"])
def test_point_to_point_ranges_fully_usable(network: str) -> None:
    policy = ScopePolicy.build([network])
    for address in ipaddress.ip_network(network):
        assert reason(policy, str(address)) is None


def test_special_checked_before_excluded_and_scope() -> None:
    policy = ScopePolicy.build(["10.99.0.0/30"], ["10.99.0.0/32"])
    assert reason(policy, "10.99.0.0") == "special_address"  # network address, also excluded


# --- Authorised targets -----------------------------------------------------


def test_authorized_target_only_from_the_policy() -> None:
    policy = ScopePolicy.build([LAB], credential_id=7)
    target = policy.authorize("10.99.0.13")
    assert isinstance(target, AuthorizedTarget)
    assert (str(target.address), target.port, target.credential_id, target.policy) == (
        "10.99.0.13",
        161,
        7,
        policy,
    )
    with pytest.raises(TypeError, match=r"only by ScopePolicy\.authorize"):
        AuthorizedTarget(ipaddress.ip_address("10.99.0.13"), 161, 7, policy)
    with pytest.raises(AttributeError):
        target.address = ipaddress.ip_address("203.0.113.10")  # type: ignore[misc]
    assert isinstance(policy.authorize("203.0.113.10"), Rejection)


def test_policy_is_frozen_per_run() -> None:
    params = RunParameters(allowed_ranges=[LAB], exclusions=["10.99.0.3/32"], credential_id=1)
    policy = ScopePolicy.from_parameters(params)
    target = policy.authorize("10.99.0.2")
    # New settings saved meanwhile build another policy; the target keeps its own.
    ScopePolicy.from_parameters(RunParameters(allowed_ranges=["10.99.0.0/28"], credential_id=2))
    assert target.policy is policy and target.credential_id == 1
    assert not policy.contains("10.99.0.3") and policy.contains("10.99.0.200")


# --- Lab-only guard (D6) ----------------------------------------------------


@pytest.mark.parametrize(
    "network", ["198.51.100.0/24", "10.0.0.0/8", "10.99.0.0/23", "203.0.113.0/24", "2001:db8::/32"]
)
def test_non_lab_range_refused_by_the_policy(network: str) -> None:
    with pytest.raises(ScopeError) as info:
        ScopePolicy.build([network])
    assert info.value.category == "scope_not_allowed"


def test_guard_bypassed_in_the_database_still_refused_at_run_start() -> None:
    stored = RunParameters(allowed_ranges=["198.51.100.0/24"], seeds=["198.51.100.1"])
    with pytest.raises(ScopeError) as info:
        ScopePolicy.from_parameters(stored)
    assert info.value.category == "scope_not_allowed"


# --- Settings: validation, ceilings, freezing -------------------------------

CEILINGS = DiscoveryCeilings()


def problems(data: dict) -> dict[str, str]:
    with pytest.raises(SettingsError) as info:
        validate_settings(data, CEILINGS)
    return dict(info.value.problems)


def test_valid_settings() -> None:
    settings = validate_settings(
        {
            "seeds": ["10.99.0.13", "10.99.0.2"],
            "allowed_ranges": [LAB],
            "exclusions": ["10.99.0.3/32"],
            "max_depth": 1,
        },
        CEILINGS,
    )
    assert [str(s) for s in settings.seeds] == ["10.99.0.13", "10.99.0.2"]


def test_real_network_range_refused_when_saved() -> None:
    found = problems({"allowed_ranges": [LAB, "198.51.100.0/24"]})
    assert "real networks require administrator authentication" in found["allowed_ranges.1"]


@pytest.mark.parametrize(
    ("seed", "why"),
    [
        ("203.0.113.10", "out of scope"),
        ("10.99.0.3", "excluded"),
        ("10.99.0.255", "special address"),
    ],
)
def test_seed_outside_the_scope_names_the_seed(seed: str, why: str) -> None:
    found = problems({"seeds": [seed], "allowed_ranges": [LAB], "exclusions": ["10.99.0.3/32"]})
    # The field names the seed by position; the reason never repeats the value (D10).
    assert found["seeds.0"] == f"seed is {why}"
    assert seed not in found["seeds.0"]


def test_host_name_as_seed_refused() -> None:
    assert "seeds.0" in problems({"seeds": ["lab-sw-01"], "allowed_ranges": [LAB]})


@pytest.mark.parametrize(
    ("field", "value", "ceiling"),
    [
        ("max_depth", 6, 5),
        ("max_candidates", 4097, 4096),
        ("max_devices", 257, 256),
        ("max_datagrams", 50001, 50000),
    ],
)
def test_limit_above_the_ceiling_refused_with_the_ceiling(
    field: str, value: int, ceiling: int
) -> None:
    found = problems({"allowed_ranges": [LAB], field: value})
    assert found[field] == f"above the server's ceiling of {ceiling}"


def test_malformed_range_refused_without_echoing_it() -> None:
    found = problems({"allowed_ranges": ["10.99.0.0/33"]})
    assert "allowed_ranges.0" in found and "/33" not in found["allowed_ranges.0"]


def test_limits_frozen_into_run_parameters() -> None:
    settings = validate_settings(
        {
            "seeds": ["10.99.0.13"],
            "allowed_ranges": [LAB],
            "follow_ip_mac": True,
            "max_candidates": 50,
            "max_devices": 5,
            "max_datagrams": 900,
        },
        CEILINGS,
    )
    params = run_parameters_for(settings, CEILINGS, credential_id=3)
    assert params.limits == RunLimits(max_candidates=50, max_devices=5, max_datagrams=900)
    assert (params.max_depth, params.follow_ip_mac, params.credential_id) == (1, True, 3)


def test_limits_checked_again_at_run_start() -> None:
    edited = RunParameters(
        max_depth=9, limits=RunLimits(max_candidates=1, max_devices=999, max_datagrams=1)
    )
    with pytest.raises(LimitsAboveCeiling) as info:
        check_run_limits(edited, CEILINGS)
    assert info.value.names == ["max_depth", "max_devices"]
    check_run_limits(RunParameters(max_depth=5), CEILINGS)  # earlier runs without limits pass


def test_ceilings_from_settings(canaries: Canaries) -> None:
    settings: Settings = make_settings(canaries)
    assert DiscoveryCeilings.from_settings(settings) == DiscoveryCeilings(5, 4096, 256, 50000)


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("NETSCANNER_DISCOVERY_MAX_DEPTH", "33"),
        ("NETSCANNER_DISCOVERY_MAX_CANDIDATES", "0"),
        ("NETSCANNER_DISCOVERY_MAX_DATAGRAMS", "-5"),
    ],
)
def test_out_of_range_ceilings_refused_at_startup(
    canaries: Canaries, variable: str, value: str
) -> None:
    env = {
        "NETSCANNER_SECRET_KEY": canaries.secret_key,
        "NETSCANNER_DB_PASSWORD": canaries.db_password,
        variable: value,
    }
    result = run_module("netscanner.collector", env)
    assert result.returncode == 2 and variable in result.stderr


# --- IPv4-mapped IPv6 addresses (decision 5 on sections 1-4) -----------------


@pytest.mark.parametrize(
    ("mapped", "expected"),
    [
        ("::ffff:10.99.0.13", None),
        ("::ffff:10.99.0.3", "excluded"),
        ("::ffff:203.0.113.10", "out_of_scope"),
        ("::ffff:10.99.0.255", "special_address"),
    ],
)
def test_ipv4_mapped_addresses_judged_as_ipv4(mapped: str, expected: str | None) -> None:
    policy = ScopePolicy.build([LAB], ["10.99.0.3/32"])
    assert reason(policy, mapped) == expected
    assert policy.contains(mapped) is (expected is None)


def test_target_keeps_the_canonical_ipv4_address() -> None:
    policy = ScopePolicy.build([LAB])
    target = policy.authorize("::ffff:10.99.0.13")
    assert isinstance(target, AuthorizedTarget)
    assert target.address == ipaddress.IPv4Address("10.99.0.13")
    assert target.device_key == ("10.99.0.13", 161)
    assert policy.contains(target.address)
