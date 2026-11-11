# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Service configuration from ``NETSCANNER_*`` environment variables (design D6)."""

from __future__ import annotations

import ipaddress
import sys
from datetime import timedelta
from pathlib import Path
from typing import Literal, NoReturn, TextIO
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "NETSCANNER_"
PLACEHOLDER = "change-me"
SECRET_KEY_MIN_LENGTH = 32
EXIT_CONFIG_ERROR = 2


class Settings(BaseSettings):
    """Settings shared by the API, the collector and the migration step.

    Each secret is its own ``SecretStr`` field without a default. The database
    URL is built in code (``netscanner.core.db``), never read from a setting.
    """

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        hide_input_in_errors=True,
        extra="ignore",
    )

    secret_key: SecretStr
    db_password: SecretStr

    db_host: str = Field(default="db", min_length=1)
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = Field(default="netscanner", min_length=1)
    db_user: str = Field(default="netscanner", min_length=1)
    db_connect_timeout: float = Field(default=5.0, gt=0, le=60)

    api_host: str = "0.0.0.0"  # noqa: S104 - inside the container network only
    api_port: int = Field(default=8000, ge=1, le=65535)

    collector_check_interval: float = Field(default=10.0, gt=0, le=3600)
    # Seconds between claims of a pending discovery run (design D7).
    collector_poll_interval: float = Field(default=2.0, gt=0, le=3600)
    # Touched on every collector loop; the container health check reads its age.
    collector_heartbeat_file: Path | None = None

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Data not confirmed within this period is reported as stale, never deleted (RF-30).
    stale_after: timedelta = Field(default=timedelta(days=7), gt=timedelta(0))

    # SNMP load limits (design D5 of add-snmp-client-and-lab). The mechanism is
    # decided; the values are lab defaults to review after the first real run.
    snmp_timeout: float = Field(default=3.0, gt=0, le=60)
    snmp_retries: int = Field(default=1, ge=0, le=5)
    snmp_max_repetitions: int = Field(default=25, ge=1, le=50)
    snmp_max_rows: int = Field(default=200_000, ge=1, le=10_000_000)
    snmp_max_devices: int = Field(default=8, ge=1, le=256)

    # Ceilings of the discovery limits (design D6 of add-discovery-and-basic-inventory).
    # Values: Hypothesis, from the lab; reviewed after the first real run.
    discovery_max_depth: int = Field(default=5, ge=0, le=32)
    discovery_max_candidates: int = Field(default=4096, ge=1, le=1_000_000)
    discovery_max_devices: int = Field(default=256, ge=1, le=100_000)
    discovery_max_datagrams: int = Field(default=50000, ge=1, le=100_000_000)

    # Sessions of the administrator (design D3 of add-admin-authentication).
    # Initial values, to be reviewed.
    session_idle: timedelta = Field(default=timedelta(hours=8), gt=timedelta(0))
    session_max_age: timedelta = Field(default=timedelta(hours=24), gt=timedelta(0))
    session_cookie_secure: bool = True
    # Host address and port Compose publishes the web service on; the API reads
    # it for the Secure check (D3) and the default allowed origins (D6).
    web_bind: str = "127.0.0.1:8080"
    # The browser-facing origin behind a TLS proxy, e.g. https://netscanner.example (D6).
    public_origin: str | None = None

    @field_validator("web_bind")
    @classmethod
    def _web_bind_format(cls, value: str) -> str:
        parse_web_bind(value)
        return value

    @field_validator("public_origin")
    @classmethod
    def _public_origin_format(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        return normalise_origin(value)

    @model_validator(mode="after")
    def _session_periods(self) -> Settings:
        if self.session_idle > self.session_max_age:
            raise ValueError(
                f"{env_name('session_idle')} must not be longer than {env_name('session_max_age')}"
            )
        return self

    @field_validator("secret_key", "db_password")
    @classmethod
    def _reject_empty_and_placeholder(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if not raw:
            raise ValueError("must not be empty")
        if raw.lower() == PLACEHOLDER:
            raise ValueError(f"still has the placeholder '{PLACEHOLDER}'; it must be changed")
        return value

    @field_validator("secret_key")
    @classmethod
    def _secret_key_length(cls, value: SecretStr) -> SecretStr:
        # It derives the credential encryption key (design D5 of
        # add-discovery-and-basic-inventory). Length is a minimum, not proof of
        # entropy: the key must be generated, not chosen.
        if len(value.get_secret_value()) < SECRET_KEY_MIN_LENGTH:
            raise ValueError(f"must be at least {SECRET_KEY_MIN_LENGTH} characters long")
        return value

    def secret_values(self) -> list[str]:
        """Current secret values, for the log masking filter."""
        return [
            getattr(self, name).get_secret_value()
            for name, field in type(self).model_fields.items()
            if field.annotation is SecretStr
        ]


def env_name(field_name: str) -> str:
    return ENV_PREFIX + field_name.upper()


def parse_web_bind(value: str) -> tuple[str | None, int]:
    """``host:port``, ``[IPv6]:port`` or a bare ``port`` (published on every interface).

    Returns the host address (``None`` for a bare port) and the port. The host
    must be an IP address, as in the ``ports:`` of the Compose file.
    """
    text = value.strip()
    host: str | None
    if text.startswith("["):
        end = text.find("]")
        if end < 0 or text[end + 1 : end + 2] != ":":
            raise ValueError("must be host:port, [IPv6]:port or a port")
        host, port_text = text[1:end], text[end + 2 :]
    elif ":" in text:
        host, _, port_text = text.rpartition(":")
        if ":" in host:
            raise ValueError("an IPv6 address must be written in brackets: [address]:port")
    else:
        host, port_text = None, text
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ValueError("must end with a port between 1 and 65535")
    if host is not None:
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            raise ValueError("the host must be an IP address") from None
    return host, int(port_text)


def is_loopback_bind(value: str) -> bool:
    """Whether the web bind address publishes on a loopback address only."""
    host, _ = parse_web_bind(value)
    return host is not None and ipaddress.ip_address(host).is_loopback


DEFAULT_PORTS = {"http": 80, "https": 443}


def normalise_origin(value: str) -> str:
    """A bare origin ``scheme://host[:port]``: scheme http or https, nothing else.

    Scheme and host are lower-cased and a default port is dropped, as browsers
    send them in ``Origin``. A path (even ``/``), user information, query or
    fragment is refused.
    """
    parts = urlsplit(value.strip())
    if parts.scheme not in DEFAULT_PORTS:
        raise ValueError("must start with http:// or https://")
    if parts.path or parts.query or parts.fragment or "?" in value or "#" in value:
        raise ValueError("must be an origin only: no path, query or fragment")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("must not contain user information")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("has an invalid port") from None
    host = parts.hostname
    if not host:
        raise ValueError("must name a host")
    if ":" in host:
        host = f"[{host}]"
    origin = f"{parts.scheme}://{host}"
    if port is not None and port != DEFAULT_PORTS[parts.scheme]:
        origin += f":{port}"
    return origin


def api_settings_errors(settings: Settings) -> list[str]:
    """Checks that only the API needs (design D3): the Secure cookie and the bind address."""
    if not settings.session_cookie_secure and not is_loopback_bind(settings.web_bind):
        return [
            f"configuration error: {env_name('session_cookie_secure')} is false but "
            f"{env_name('web_bind')} is not a loopback address; the Secure cookie may be "
            "turned off only when the web service is published on 127.0.0.1 or [::1]"
        ]
    return []


def exit_if_invalid_for_api(settings: Settings, stream: TextIO | None = None) -> None:
    errors = api_settings_errors(settings)
    if errors:
        _exit_with(errors, stream or sys.stderr)


def format_validation_error(exc: ValidationError) -> list[str]:
    """Describe each error by variable name, error type and reason only.

    Inputs are never included: ``hide_input_in_errors`` covers the default
    text form and here only the location, type and message are used.
    """
    lines = []
    for err in exc.errors(include_url=False, include_input=False, include_context=False):
        loc = err.get("loc")
        # A check across several settings has no location; its message names them.
        name = env_name(str(loc[0])) if loc else "settings"
        reason = "is required but not set" if err["type"] == "missing" else err["msg"]
        lines.append(f"configuration error: {name}: {reason} [{err['type']}]")
    return lines


def load_settings_or_exit(stream: TextIO | None = None) -> Settings:
    """Load the settings or exit with a non-zero code and a safe message."""
    try:
        return Settings()
    except ValidationError as exc:
        _exit_with(format_validation_error(exc), stream or sys.stderr)


def _exit_with(lines: list[str], stream: TextIO) -> NoReturn:
    for line in lines:
        print(line, file=stream)
    print("configuration error: see .env.example for the expected variables", file=stream)
    raise SystemExit(EXIT_CONFIG_ERROR)
