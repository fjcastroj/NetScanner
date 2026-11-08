# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""SNMP credentials held in memory only (design D7, RNF-01).

SNMPv2c with a community and SNMPv3 with authNoPriv or authPriv using
SHA-family authentication and AES privacy. SNMPv1, MD5 and DES are refused.
Secrets are ``SecretStr``: their text form is masked and validation errors
never echo them.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, model_validator

AuthProtocol = Literal["SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]
PrivProtocol = Literal["AES-128", "AES-192", "AES-256"]
SecurityLevel = Literal["authNoPriv", "authPriv"]


class CredentialError(ValueError):
    """An unsupported or malformed credential; the message names fields only."""


class _Credential(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    def secrets(self) -> list[str]:
        """Secret values, for the log-masking filter while a query runs."""
        values = []
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr):
                values.append(value.get_secret_value())
        return [v for v in values if v]


class SnmpV2cCredential(_Credential):
    version: Literal["2c"] = "2c"
    community: SecretStr = Field(min_length=1)


class SnmpV3Credential(_Credential):
    version: Literal["3"] = "3"
    user: str = Field(min_length=1, max_length=32)
    level: SecurityLevel
    auth_protocol: AuthProtocol
    # RFC 3414: passphrases of at least 8 characters.
    auth_key: SecretStr = Field(min_length=8)
    priv_protocol: PrivProtocol | None = None
    priv_key: SecretStr | None = Field(default=None, min_length=8)

    @model_validator(mode="after")
    def _privacy_matches_level(self) -> SnmpV3Credential:
        has_priv = self.priv_protocol is not None or self.priv_key is not None
        if self.level == "authPriv" and (self.priv_protocol is None or self.priv_key is None):
            raise ValueError("authPriv needs a privacy protocol and key")
        if self.level == "authNoPriv" and has_priv:
            raise ValueError("authNoPriv takes no privacy protocol or key")
        return self


Credential = Annotated[SnmpV2cCredential | SnmpV3Credential, Field(discriminator="version")]


class _Wrapper(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)
    credential: Credential


def parse_credential(
    value: dict | SnmpV2cCredential | SnmpV3Credential,
) -> SnmpV2cCredential | SnmpV3Credential:
    """Validate a credential; errors name the fields, never their values.

    SNMPv1 (version "1"), MD5 and DES are not among the accepted literals and
    are refused like any other unsupported value.
    """
    if isinstance(value, SnmpV2cCredential | SnmpV3Credential):
        return value
    try:
        return _Wrapper.model_validate({"credential": value}).credential
    except ValidationError as exc:
        parts = sorted(
            {
                f"{'.'.join(str(p) for p in e['loc'][1:]) or 'credential'}: {e['type']}"
                for e in exc.errors(include_input=False, include_url=False, include_context=False)
            }
        )
        raise CredentialError(f"invalid SNMP credential: {'; '.join(parts)}") from None
