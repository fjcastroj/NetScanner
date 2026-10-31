# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Tests for scripts/check_headers.py."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_headers as ch

HEADER = (
    "SPDX-License-Identifier: Apache-2.0\n"
    "Copyright 2026 Francisco Javier Castro Jiménez\n"
    "Developed as part of the Final Degree Project (TFE), Bachelor's Degree in\n"
    "Computer Engineering, Universidad Internacional de La Rioja (UNIR).\n"
)


def commented(prefix: str) -> str:
    return "".join(f"{prefix} {line}\n" for line in HEADER.splitlines())


def run(root: Path, files: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    return ch.check(root, files, out=out), out.getvalue()


def write(root: Path, rel: str, text: str) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return rel


def test_missing_header_reported(tmp_path: Path) -> None:
    rel = write(tmp_path, "backend/src/app.py", "print('hi')\n")
    code, out = run(tmp_path, [rel])
    assert code == 1
    assert "backend/src/app.py: missing licence header" in out


@pytest.mark.parametrize(
    ("rel", "body"),
    [
        ("a.py", commented("#") + "x = 1\n"),
        ("run.sh", "#!/bin/sh\n" + commented("#") + "echo\n"),
        ("src/App.tsx", "/*\n" + commented(" *") + " */\nexport {};\n"),
        ("style.css", "/*\n" + HEADER + "*/\n"),
        ("Dockerfile", commented("#") + "FROM scratch\n"),
        ("compose.yml", commented("#") + "services: {}\n"),
    ],
)
def test_header_accepted(tmp_path: Path, rel: str, body: str) -> None:
    write(tmp_path, rel, body)
    assert run(tmp_path, [rel]) == (0, "")


def test_partial_header_reported(tmp_path: Path) -> None:
    rel = write(tmp_path, "a.ts", "// SPDX-License-Identifier: Apache-2.0\nexport {};\n")
    assert run(tmp_path, [rel])[0] == 1


def test_header_too_far_down_reported(tmp_path: Path) -> None:
    rel = write(tmp_path, "a.py", "\n" * 20 + commented("#"))
    assert run(tmp_path, [rel])[0] == 1


@pytest.mark.parametrize(
    "rel",
    [
        "frontend/node_modules/pkg/index.js",
        "frontend/dist/assets/index.js",
        "backend/uv.lock",
        "frontend/package-lock.json",
        "frontend/src/vite-env.d.ts",
        "openspec/config.yaml",
        "vendor/lib.min.js",
        "README.md",
        "LICENSE",
    ],
)
def test_excluded_and_unchecked_files_skipped(tmp_path: Path, rel: str) -> None:
    write(tmp_path, rel, "no header\n")
    assert run(tmp_path, [rel]) == (0, "")
