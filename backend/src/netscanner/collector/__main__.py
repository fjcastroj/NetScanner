# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Entry point: ``python -m netscanner.collector``."""

from __future__ import annotations

import asyncio
import signal

from netscanner.collector.service import run_collector
from netscanner.core.config import Settings
from netscanner.core.startup import bootstrap


async def _run(settings: Settings) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows event loop
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))
    await run_collector(settings, stop)


def main() -> None:
    settings = bootstrap("collector")
    asyncio.run(_run(settings))


if __name__ == "__main__":
    main()
