# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Scope policy and authorised targets (design D2, D6; snmp-scope spec, RNF-03).

Pure code, no I/O. A :class:`ScopePolicy` is built once per run from the
run's frozen parameters. ``authorize`` returns either an
:class:`AuthorizedTarget`, the only object the SNMP client accepts, or a
:class:`Rejection` with its reason, checked in the order special address,
excluded, out of scope. ``AuthorizedTarget`` needs a token private to this
module, so a direct construction raises. Python cannot make a class truly
unforgeable: the guarantee is by design and verified by architecture tests.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from netscanner.store.runs import RunParameters

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
RejectionReason = Literal["special_address", "excluded", "out_of_scope"]

LIMITED_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


class ScopeError(ValueError):
    """A scope that no run may use; ``category`` is the run's failure category."""

    def __init__(self, category: Literal["empty_scope", "scope_not_allowed"], message: str) -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class Rejection:
    reason: RejectionReason


_TOKEN = object()


class AuthorizedTarget:
    """An address the run's scope policy authorised, with the run's credential.

    Created only by :meth:`ScopePolicy.authorize`. It keeps a reference to the
    run's frozen policy, never to the current settings, so the SNMP adapter
    can check it again before every datagram.
    """

    __slots__ = ("address", "credential_id", "policy", "port")

    def __init__(
        self,
        address: Address,
        port: int,
        credential_id: int | None,
        policy: ScopePolicy,
        *,
        _token: object = None,
    ) -> None:
        if _token is not _TOKEN:
            raise TypeError("an AuthorizedTarget is created only by ScopePolicy.authorize")
        object.__setattr__(self, "address", address)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "credential_id", credential_id)
        object.__setattr__(self, "policy", policy)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("an AuthorizedTarget is immutable")

    @property
    def device_key(self) -> tuple[str, int]:
        return (str(self.address), self.port)

    def __repr__(self) -> str:
        return f"AuthorizedTarget({self.address}:{self.port}, credential {self.credential_id})"


def canonical(address: str | Address) -> Address:
    """The address to check and to send to: IPv4-mapped IPv6 becomes IPv4.

    Done at the entry to the policy, before every check, so an IPv4-mapped
    IPv6 address is judged, and sent, as the IPv4 address it carries.
    """
    parsed = (
        address
        if isinstance(address, ipaddress.IPv4Address | ipaddress.IPv6Address)
        else ipaddress.ip_address(address)
    )
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


@dataclass(frozen=True)
class ScopePolicy:
    """Allowed and excluded networks of one run; deny by default, exclusion wins."""

    allowed: tuple[Network, ...]
    excluded: tuple[Network, ...] = ()
    credential_id: int | None = None

    @classmethod
    def build(
        cls,
        allowed: Iterable[str | Network],
        excluded: Iterable[str | Network] = (),
        credential_id: int | None = None,
    ) -> ScopePolicy:
        """A policy for a run; refuses an empty scope and ranges it cannot build.

        The lab-only guard was removed by add-admin-authentication (design D9):
        every administrative route now needs a session.
        """
        try:
            allowed_nets = tuple(ipaddress.ip_network(n) for n in allowed)
            excluded_nets = tuple(ipaddress.ip_network(n) for n in excluded)
        except (TypeError, ValueError):
            raise ScopeError(
                "scope_not_allowed", "an allowed or excluded range is not a valid network"
            ) from None
        if not allowed_nets:
            raise ScopeError("empty_scope", "no allowed range: nothing may be queried")
        return cls(allowed_nets, excluded_nets, credential_id)

    @classmethod
    def from_parameters(cls, parameters: RunParameters) -> ScopePolicy:
        return cls.build(parameters.allowed_ranges, parameters.exclusions, parameters.credential_id)

    def _special(self, address: Address) -> bool:
        if address.is_multicast or address.is_unspecified or address.is_link_local:
            return True
        if address == LIMITED_BROADCAST:
            return True
        if address.is_loopback:
            # Loopback only when a loopback range itself is explicitly allowed.
            return not any(address in n and n.network_address.is_loopback for n in self.allowed)
        for network in self.allowed:
            if (
                network.version == 4
                and address in network
                and network.prefixlen <= 30
                and address in (network.network_address, network.broadcast_address)
            ):
                return True
        return False

    def check(self, address: str | Address) -> Rejection | None:
        """The reason an address may not be queried, or ``None`` if it may."""
        addr = canonical(address)
        if self._special(addr):
            return Rejection("special_address")
        if any(addr in n for n in self.excluded):
            return Rejection("excluded")
        if not any(addr in n for n in self.allowed):
            return Rejection("out_of_scope")
        return None

    def contains(self, address: str | Address) -> bool:
        return self.check(address) is None

    def authorize(self, address: str | Address, port: int = 161) -> AuthorizedTarget | Rejection:
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        addr = canonical(address)
        rejection = self.check(addr)
        if rejection is not None:
            return rejection
        return AuthorizedTarget(addr, port, self.credential_id, self, _token=_TOKEN)
