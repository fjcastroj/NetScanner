# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Measurements for the SNMP library decision (design D2).

Compares the PySNMP client with ``snmpbulkwalk`` (Net-SNMP, the reference) on
the lab: equality of the values of every table of the registry that srx-01
serves, and the walk time of ``ifTable`` and ``ifXTable`` (median of five
runs, max-repetitions 25). Needs the Net-SNMP tools and network access to the
lab, for example from a container on ``netscanner-lab``:

    python -m tests.measure_snmp_library --host 10.99.0.13 --community netscanner-lab

Prints a Markdown report used in docs/decisions/snmp-library.md.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import subprocess
import time

from netscanner.snmp import TABLES, SnmpLimits, SnmpV2cCredential, TableSpec, Target
from netscanner.snmp.pysnmp_client import PySnmpClient
from netscanner.snmp.tables import format_oid

from .netsnmp_client import parse_output

RUNS = 5
REPETITIONS = 25


def reference_walk(host: str, community: str, oid: str) -> tuple[list, float]:
    start = time.monotonic()
    args = ["snmpbulkwalk", "-v2c", "-c", community, "-On", "-Ox", "-Ot", f"-Cr{REPETITIONS}"]
    args += ["-t", "5", "-r", "1", host, oid]
    out = subprocess.run(args, capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - start
    varbinds = [vb for vb in parse_output(out.stdout) if not isinstance(vb[1], str) or vb[1] != ""]
    return varbinds, elapsed


def reference_rows(spec: TableSpec, host: str, community: str) -> dict:
    """Registry columns of the table as Net-SNMP returns them."""
    subtrees = [spec.column_oid(c) for c in spec.columns] if spec.by_columns else [spec.oid]
    rows: dict = {}
    for subtree in subtrees:
        varbinds, _ = reference_walk(host, community, format_oid(subtree))
        for oid, value in varbinds:
            if oid[: len(spec.oid)] != spec.oid or len(oid) <= len(spec.oid):
                continue
            column = spec.column_name(oid[len(spec.oid)])
            if column is not None and not hasattr(value, "value"):
                rows.setdefault(oid[len(spec.oid) + 1 :], {})[column] = value
    return rows


async def main(host: str, community: str) -> None:
    client = PySnmpClient(SnmpLimits(timeout=5, retries=1, max_repetitions=REPETITIONS))
    target = Target(host, SnmpV2cCredential(community=community))

    print("| Table | PySNMP outcome | Rows | Values equal to snmpbulkwalk |")
    print("|-------|----------------|------|------------------------------|")
    all_equal = True
    for spec in TABLES.values():
        result = await client.walk_table(target, spec)
        expected = reference_rows(spec, host, community)
        equal = result.rows == expected
        all_equal &= equal
        verdict = "yes" if equal else "NO"
        print(f"| `{spec.mib_object}` | {result.outcome} | {result.row_count} | {verdict} |")
    print(f"\nAll values equal: {'yes' if all_equal else 'NO'}\n")

    print("| Walk | PySNMP median (s) | snmpbulkwalk median (s) | Ratio |")
    print("|------|-------------------|-------------------------|-------|")
    for name in ("IF-MIB::ifTable", "IF-MIB::ifXTable"):
        spec = TABLES[name]
        ours, theirs = [], []
        for _ in range(RUNS):
            start = time.monotonic()
            result = await client.walk_table(target, spec)
            ours.append(time.monotonic() - start)
            assert result.outcome == "ok"
            theirs.append(reference_walk(host, community, format_oid(spec.oid))[1])
        a, b = statistics.median(ours), statistics.median(theirs)
        print(f"| `{name}` | {a:.2f} | {b:.2f} | {a / b:.2f} |")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True)
    parser.add_argument("--community", required=True)
    args = parser.parse_args()
    asyncio.run(main(args.host, args.community))
