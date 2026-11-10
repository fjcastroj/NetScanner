# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Discovery settings: validation when saved and freezing into a run (design D6).

Saved value → validated against the server's ceilings and the scope rules →
copied into ``RunParameters`` when the run is created → checked again when
the run starts, because the database can be edited outside the API.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, IPvAnyNetwork, ValidationError

from netscanner.core.config import Settings
from netscanner.scope.policy import ScopeError, ScopePolicy, outside_lab
from netscanner.store.runs import RunLimits, RunParameters


@dataclass(frozen=True)
class DiscoveryCeilings:
    """Server-side ceilings from the environment (values: Hypothesis, design D6)."""

    max_depth: int = 5
    max_candidates: int = 4096
    max_devices: int = 256
    max_datagrams: int = 50000

    @classmethod
    def from_settings(cls, settings: Settings) -> DiscoveryCeilings:
        return cls(
            max_depth=settings.discovery_max_depth,
            max_candidates=settings.discovery_max_candidates,
            max_devices=settings.discovery_max_devices,
            max_datagrams=settings.discovery_max_datagrams,
        )


class SettingsError(ValueError):
    """Invalid settings: one ``(field, reason)`` per problem, never a secret value."""

    def __init__(self, problems: list[tuple[str, str]]) -> None:
        super().__init__("; ".join(f"{field}: {reason}" for field, reason in problems))
        self.problems = problems


class DiscoverySettings(BaseModel):
    """The stored discovery settings (one row, ``discovery_settings``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seeds: list[IPvAnyAddress] = Field(default_factory=list, max_length=1024)
    allowed_ranges: list[IPvAnyNetwork] = Field(default_factory=list, max_length=1024)
    exclusions: list[IPvAnyNetwork] = Field(default_factory=list, max_length=1024)
    max_depth: int = Field(default=1, ge=0, le=32)
    follow_ip_mac: bool = False
    max_candidates: int = Field(default=4096, ge=1)
    max_devices: int = Field(default=256, ge=1)
    max_datagrams: int = Field(default=50000, ge=1)


LIMIT_FIELDS = ("max_depth", "max_candidates", "max_devices", "max_datagrams")


def validate_settings(data: dict, ceilings: DiscoveryCeilings) -> DiscoverySettings:
    """Validate settings to be saved; raise :class:`SettingsError` with every problem."""
    try:
        settings = DiscoverySettings.model_validate(data)
    except ValidationError as exc:
        problems = [
            (".".join(str(p) for p in e["loc"]) or "settings", e["msg"])
            for e in exc.errors(include_input=False, include_url=False, include_context=False)
        ]
        raise SettingsError(problems) from None
    problems: list[tuple[str, str]] = []
    for field in LIMIT_FIELDS:
        ceiling = getattr(ceilings, field)
        if getattr(settings, field) > ceiling:
            problems.append((field, f"above the server's ceiling of {ceiling}"))
    for i, network in enumerate(settings.allowed_ranges):
        if outside_lab([network]):
            problems.append(
                (
                    f"allowed_ranges.{i}",
                    "only the lab range 10.99.0.0/24 and loopback may be allowed: real networks "
                    "require administrator authentication to be in place first",
                )
            )
    if not problems and settings.allowed_ranges:
        policy = ScopePolicy.build(settings.allowed_ranges, settings.exclusions)
        for i, seed in enumerate(settings.seeds):
            rejection = policy.check(seed)
            if rejection is not None:
                # The field names the seed by position; the reason never repeats
                # the submitted value (design D10).
                problems.append((f"seeds.{i}", f"seed is {rejection.reason.replace('_', ' ')}"))
    elif settings.seeds and not settings.allowed_ranges:
        problems.append(("seeds", "seeds need an allowed range that contains them"))
    if problems:
        raise SettingsError(problems)
    return settings


def run_parameters_for(
    settings: DiscoverySettings, ceilings: DiscoveryCeilings, credential_id: int | None
) -> RunParameters:
    """Freeze the settings into the parameters of a new run."""
    params = RunParameters(
        seeds=settings.seeds,
        allowed_ranges=settings.allowed_ranges,
        exclusions=settings.exclusions,
        max_depth=settings.max_depth,
        credential_id=credential_id,
        follow_ip_mac=settings.follow_ip_mac,
        limits=RunLimits(
            max_candidates=settings.max_candidates,
            max_devices=settings.max_devices,
            max_datagrams=settings.max_datagrams,
        ),
    )
    check_run_limits(params, ceilings)
    return params


class LimitsAboveCeiling(ValueError):
    """A run whose stored limits exceed the server's current ceilings."""

    def __init__(self, names: list[str]) -> None:
        super().__init__(f"limits above the server's ceilings: {', '.join(names)}")
        self.names = names


def check_run_limits(params: RunParameters, ceilings: DiscoveryCeilings) -> None:
    """Check a run's frozen limits again at run start (design D6)."""
    over = []
    if params.max_depth is not None and params.max_depth > ceilings.max_depth:
        over.append("max_depth")
    if params.limits is not None:
        over += [f for f in LIMIT_FIELDS[1:] if getattr(params.limits, f) > getattr(ceilings, f)]
    if over:
        raise LimitsAboveCeiling(over)


__all__ = [
    "DiscoveryCeilings",
    "DiscoverySettings",
    "LimitsAboveCeiling",
    "ScopeError",
    "SettingsError",
    "check_run_limits",
    "run_parameters_for",
    "validate_settings",
]
