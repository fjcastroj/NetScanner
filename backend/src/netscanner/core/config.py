# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Service configuration from ``NETSCANNER_*`` environment variables (design D6)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Literal, NoReturn, TextIO

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "NETSCANNER_"
PLACEHOLDER = "change-me"
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
    # Touched on every collector loop; the container health check reads its age.
    collector_heartbeat_file: Path | None = None

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("secret_key", "db_password")
    @classmethod
    def _reject_empty_and_placeholder(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if not raw:
            raise ValueError("must not be empty")
        if raw.lower() == PLACEHOLDER:
            raise ValueError(f"still has the placeholder '{PLACEHOLDER}'; it must be changed")
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


def format_validation_error(exc: ValidationError) -> list[str]:
    """Describe each error by variable name, error type and reason only.

    Inputs are never included: ``hide_input_in_errors`` covers the default
    text form and here only the location, type and message are used.
    """
    lines = []
    for err in exc.errors(include_url=False, include_input=False, include_context=False):
        loc = err.get("loc") or ("?",)
        name = env_name(str(loc[0]))
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
