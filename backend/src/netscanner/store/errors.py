# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Errors of the persistence layer. Messages never contain input values."""

from __future__ import annotations


class StoreError(ValueError):
    """Input the persistence layer refuses; nothing is written."""


class UnknownNameError(StoreError):
    """A name that is not in its registry."""


class RunStateError(StoreError):
    """A lifecycle transition that the run's current status does not allow."""
