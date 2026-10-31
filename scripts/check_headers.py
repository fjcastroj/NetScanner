# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Header check: every project source file starts with the licence header.

The header (design D10) must appear in the first lines of the file, after an
optional shebang, and contain the SPDX identifier, the copyright holder and
the UNIR TFE statement.

Usage:
    check_headers.py [--all] [FILE ...]
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path

CHECKED_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".css",
    ".sh",
    ".yml",
    ".yaml",
}
CHECKED_NAMES = {"Dockerfile"}

# Lock files, generated output, vendored assets and tool-managed files.
EXCLUDED = [
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/.venv/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/uv.lock",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
    "frontend/src/vite-env.d.ts",
    "openspec/**",
    ".claude/**",
]

HEAD_LINES = 12
REQUIRED = [
    re.compile(r"SPDX-License-Identifier: Apache-2\.0"),
    re.compile(r"Copyright \d{4}(?:-\d{4})? Francisco Javier Castro Jiménez"),
    re.compile(r"Final Degree Project \(TFE\)"),
    re.compile(r"Universidad Internacional de La Rioja \(UNIR\)"),
]


def is_checked(rel: str) -> bool:
    if any(
        fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch("/" + rel, pattern) for pattern in EXCLUDED
    ):
        return False
    path = Path(rel)
    return (
        path.suffix in CHECKED_SUFFIXES
        or path.name in CHECKED_NAMES
        or (path.name.startswith("Dockerfile."))
    )


def has_header(text: str) -> bool:
    head = "\n".join(text.splitlines()[:HEAD_LINES])
    return all(rx.search(head) for rx in REQUIRED)


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return sorted({p for p in out.decode("utf-8").split("\0") if p})


def check(root: Path, files: list[str], out=sys.stdout) -> int:
    missing = []
    for rel in files:
        if not is_checked(rel):
            continue
        path = root / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if not has_header(text):
            missing.append(rel)
    for rel in missing:
        print(f"{rel}: missing licence header (see design D10)", file=out)
    return 1 if missing else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="*")
    parser.add_argument("--all", action="store_true", help="check every tracked file")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.all:
        files = tracked_files(root)
    else:
        files = [Path(f).resolve().relative_to(root).as_posix() for f in args.files]
    return check(root, files)


if __name__ == "__main__":
    sys.exit(main())
