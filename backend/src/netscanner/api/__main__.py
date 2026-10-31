# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Entry point: ``python -m netscanner.api``."""

from __future__ import annotations

import uvicorn

from netscanner.api.app import create_app
from netscanner.core.startup import bootstrap


def main() -> None:
    settings = bootstrap("api")
    uvicorn.run(
        create_app(settings),
        host=settings.api_host,
        port=settings.api_port,
        log_config=None,  # keep the root handler with the secret masking filter
        server_header=False,
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
