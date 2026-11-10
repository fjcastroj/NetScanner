# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Logging setup with a last-line-of-defence filter that masks secrets."""

from __future__ import annotations

import logging
import sys
import threading
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import contextmanager

MASK = "***"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

# Secrets in use right now (for example an SNMP community during a query),
# masked by every SecretMaskingFilter in addition to its own list.
_in_use: Counter[str] = Counter()
_in_use_lock = threading.Lock()


def register_secrets(values: Iterable[str]) -> list[str]:
    """Start masking ``values`` in every log record; returns what to unregister."""
    registered = [v for v in values if v]
    with _in_use_lock:
        _in_use.update(registered)
    return registered


def unregister_secrets(registered: Iterable[str]) -> None:
    with _in_use_lock:
        for value in registered:
            _in_use[value] -= 1
            if _in_use[value] <= 0:
                del _in_use[value]


@contextmanager
def secrets_in_use(values: Iterable[str]) -> Iterator[None]:
    """Mask ``values`` in every log record while the block runs."""
    registered = register_secrets(values)
    try:
        yield
    finally:
        unregister_secrets(registered)


class SecretMaskingFilter(logging.Filter):
    """Replace the current secret values with ``***`` in every record.

    The message is rendered with its arguments, and exception and stack text
    are rendered too, so a secret cannot slip through any of them.
    """

    def __init__(self, secrets: Iterable[str]) -> None:
        super().__init__()
        # Longest first so a secret containing another one is fully masked.
        self._secrets = sorted({s for s in secrets if s}, key=len, reverse=True)
        self._formatter = logging.Formatter()

    def mask(self, text: str) -> str:
        with _in_use_lock:
            current = set(_in_use)
        for secret in sorted(current.union(self._secrets), key=len, reverse=True):
            text = text.replace(secret, MASK)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.mask(record.getMessage())
        record.args = None
        if record.exc_info:
            record.exc_text = self.mask(self._formatter.formatException(record.exc_info))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = self.mask(record.exc_text)
        if record.stack_info:
            record.stack_info = self.mask(record.stack_info)
        return True


def configure_logging(level: str, secrets: Iterable[str]) -> logging.Handler:
    """Send every log record to stderr through the masking filter."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.addFilter(SecretMaskingFilter(secrets))
    root = logging.getLogger()
    for old in list(root.handlers):
        root.removeHandler(old)
    root.addHandler(handler)
    root.setLevel(level)
    return handler
