# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Container health check: the collector loop touched its heartbeat recently.

Usage: ``python -m netscanner.collector.healthcheck PATH MAX_AGE_SECONDS``.
It reads no settings, so it needs no secrets.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path


def main(argv: list[str]) -> int:
    path, max_age = Path(argv[0]), float(argv[1])
    try:
        age = time.time() - path.stat().st_mtime
    except FileNotFoundError:
        return 1
    return 0 if age <= max_age else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
