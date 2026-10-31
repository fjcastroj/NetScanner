# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""The log masking filter replaces secrets in every part of a record."""

from __future__ import annotations

import logging

import pytest

from netscanner.core.logging_setup import MASK, configure_logging

from .conftest import Canaries


def test_secrets_masked_in_message_args_and_exceptions(
    capsys: pytest.CaptureFixture[str], canaries: Canaries
) -> None:
    configure_logging("DEBUG", canaries.all())
    log = logging.getLogger("netscanner.test.child")  # propagates to the root handler
    log.info("key is %s", canaries.secret_key)
    log.warning(f"password {canaries.db_password} inline")
    try:
        raise RuntimeError(f"failed with {canaries.db_password}")
    except RuntimeError:
        log.exception("something broke")
    log.info("stack", stack_info=True)

    err = capsys.readouterr().err
    assert err.count(MASK) >= 3
    assert "RuntimeError: failed with ***" in err
    canaries.assert_absent(err)


def test_empty_secrets_are_ignored(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", ["", "s3cr3t-value"])
    logging.getLogger("x").info("plain text with s3cr3t-value")
    err = capsys.readouterr().err
    assert "plain text with ***" in err
