# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Tests for scripts/check_confidentiality.py.

Forbidden values are built at run time (joined from parts) so that this file
passes the check itself without allowlist entries.
"""

from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_confidentiality as cc


def v4(*parts: int | str) -> str:
    return ".".join(str(p) for p in parts)


def v6(*groups: str) -> str:
    return ":".join(groups)


def mac(*octets: str, sep: str = ":") -> str:
    return sep.join(octets)


def kinds(line: str) -> list[str]:
    return [kind for kind, _ in cc.scan_line(line)]


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root

    def write(self, rel: str, text: str) -> str:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return rel

    def run(self, files: list[str], *, check_stale: bool = False) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cc.run(
            self.root,
            files,
            check_stale=check_stale,
            terms_path=self.root / cc.TERMS_FILE,
            allowlist_path=self.root / cc.ALLOWLIST_FILE,
            out=out,
            err=err,
        )
        return code, out.getvalue(), err.getvalue()


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path)


# --- IPv4 -------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr",
    [v4(192, 168, 1, 10), v4(10, 1, 2, 3), v4(172, 16, 5, 4), v4(8, 8, 8, 8), v4(10, 98, 0, 1)],
)
def test_private_and_public_ipv4_reported(repo: Repo, addr: str) -> None:
    rel = repo.write("notes.md", f"line one\nhost at {addr} here\n")
    code, out, _ = repo.run([rel])
    assert code == 1
    assert f"notes.md:2: IPv4 address: {addr}" in out


def test_ipv4_at_end_of_sentence_reported() -> None:
    assert kinds(f"The router is {v4(192, 168, 0, 1)}.") == ["IPv4 address"]


@pytest.mark.parametrize(
    "addr",
    [
        "10.99.0.11",
        "192.0.2.10",
        "198.51.100.7",
        "203.0.113.200",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "10.99.0.0/24",
    ],
)
def test_lab_and_documentation_ipv4_allowed(addr: str) -> None:
    assert kinds(f"address {addr}") == []


@pytest.mark.parametrize("text", ["1.3.6.1.4.1.12356.101.4.1.1", "version 7.2.5", "v1.2.3.4.5"])
def test_oids_and_versions_not_addresses(text: str) -> None:
    assert kinds(text) == []


# --- IPv6 -------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr",
    [
        v6("fd12", "3456", "", "1"),  # unique local
        v6("2a00", "1450", "", "200e"),  # global unicast
        v6("fe80", "", "1"),  # link-local
        v6("fe80", "", "a00", "27ff", "fe4e", "66a1"),
        v6("1", "2", "3", "4", "5", "6", "7", "8"),  # full form, no ::
        v6("ff02", "", "1", "ff00", "1234"),  # solicited-node
        v6("ff02", "", "3"),  # multicast group outside the list
        v6("ff05", "", "2"),  # other scope
    ],
)
def test_forbidden_ipv6_reported(repo: Repo, addr: str) -> None:
    rel = repo.write("a.txt", f"peer {addr} up\n")
    code, out, _ = repo.run([rel])
    assert code == 1
    assert f"a.txt:1: IPv6 address: {addr}" in out


@pytest.mark.parametrize(
    "addr",
    [
        "2001:db8::1",
        "2001:db8:0:1::5/64",
        "::1",
        "::",
        "ff02::1",
        "ff02::2",
        "ff02::5",
        "ff02::6",
        "ff02::9",
        "ff02::d",
        "ff02::16",
        "ff02::fb",
        "ff02::1:2",
    ],
)
def test_allowed_ipv6(addr: str) -> None:
    assert kinds(f"address {addr} ok") == []


@pytest.mark.parametrize(
    "text",
    [
        "at 12:30:45 today",
        "at 09:15",
        "mac 02:00:00:00:00:01",
        "x = a[::2]",
        "std::vector",
        "key: value: other",
    ],
)
def test_times_macs_and_code_not_ipv6(text: str) -> None:
    assert "IPv6 address" not in kinds(text)


def test_ipv6_with_trailing_colon_in_prose() -> None:
    assert kinds(f"neighbour {v6('fe80', '', '1')}: down") == ["IPv6 address"]


# --- MAC --------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        mac("3c", "11", "22", "33", "44", "55"),
        mac("3C", "11", "22", "33", "44", "55", sep="-"),
        ".".join(["3c11", "2233", "4455"]),
        mac("01", "00", "5e", "00", "00", "fb"),  # multicast not in the protocol list
    ],
)
def test_globally_administered_mac_reported(repo: Repo, value: str) -> None:
    rel = repo.write("m.txt", f"port learned {value}\n")
    code, out, _ = repo.run([rel])
    assert code == 1
    assert f"m.txt:1: MAC address: {value}" in out


@pytest.mark.parametrize(
    "value",
    [
        "02:00:00:00:00:01",
        "00-00-5E-00-53-1A",
        "0000.5e00.5301",
        "01:80:C2:00:00:0E",
        "00:00:00:00:00:00",
        "FF:FF:FF:FF:FF:FF",
        "01:00:0C:CC:CC:CC",
        "01:80:c2:00:00:00",
    ],
)
def test_allowed_macs_in_any_notation(value: str) -> None:
    assert kinds(f"mac {value}") == []


# --- Terms ------------------------------------------------------------------


def test_term_reported_without_printing_it(repo: Repo) -> None:
    term = "Fictitious" + "Corp"
    repo.write(cc.TERMS_FILE, f"# comment\n{term.lower()}\n")
    rel = repo.write("readme.md", f"ok\nSee intranet.{term.upper()}.example\n")
    code, out, err = repo.run([rel])
    assert code == 1
    assert "readme.md:2: confidential term" in out
    assert term.lower() not in (out + err).lower()


def test_missing_term_list_skips_only_terms(repo: Repo) -> None:
    rel = repo.write("a.txt", f"{v4(192, 168, 3, 3)}\n")
    code, out, err = repo.run([rel])
    assert code == 1
    assert "IPv4 address" in out
    assert "term check skipped" in err


# --- Allowlist --------------------------------------------------------------


def write_allowlist(repo: Repo, value: str, path: str) -> None:
    repo.write(
        cc.ALLOWLIST_FILE,
        f'entries:\n  - value: "{value}"\n    paths: ["{path}"]\n    reason: CIDR in docs\n',
    )


def test_allowlisted_cidr_in_its_file_only(repo: Repo) -> None:
    cidr = v4(192, 168, 0, 0) + "/16"
    other = v4(192, 168, 7, 7)
    write_allowlist(repo, cidr, "docs/**/rules.md")
    allowed = repo.write("docs/sub/rules.md", f"Forbidden: {cidr}\nHost {other}\n")
    elsewhere = repo.write("src/notes.md", f"Forbidden: {cidr}\n")
    code, out, _ = repo.run([allowed, elsewhere, cc.ALLOWLIST_FILE], check_stale=True)
    assert code == 1
    assert "docs/sub/rules.md:1" not in out
    assert f"docs/sub/rules.md:2: IPv4 address: {other}" in out
    assert f"src/notes.md:1: IPv4 address: {cidr}" in out
    assert cc.ALLOWLIST_FILE + ":" not in out  # the allowlist may hold its own values
    assert "stale" not in out


def test_allowlisted_value_does_not_cover_bare_address(repo: Repo) -> None:
    cidr = v4(10, 0, 0, 0) + "/8"
    write_allowlist(repo, cidr, "docs/a.md")
    rel = repo.write("docs/a.md", f"{v4(10, 0, 0, 0)}\n")
    code, _, _ = repo.run([rel])
    assert code == 1


def test_stale_allowlist_entry_reported(repo: Repo) -> None:
    write_allowlist(repo, v6("fc00", "") + "/7", "docs/a.md")
    rel = repo.write("docs/a.md", "nothing here\n")
    code, out, _ = repo.run([rel], check_stale=True)
    assert code == 1
    assert "stale entry" in out


@pytest.mark.parametrize(
    "body",
    [
        'entries:\n  - value: "10.*"\n    paths: ["a"]\n    reason: x\n',
        'entries:\n  - value: "x"\n    paths: []\n    reason: x\n',
        'entries:\n  - value: "x"\n    paths: ["a"]\n',
    ],
)
def test_invalid_allowlist_rejected(repo: Repo, body: str) -> None:
    repo.write(cc.ALLOWLIST_FILE, body)
    code, _, err = repo.run([])
    assert code == 2
    assert "invalid allowlist" in err


def test_binary_files_skipped(repo: Repo) -> None:
    path = repo.root / "img.png"
    path.write_bytes(b"\x89PNG\0" + v4(192, 168, 1, 1).encode())
    assert repo.run(["img.png"])[0] == 0


def test_cli_all_scans_git_files(repo: Repo) -> None:
    subprocess.run(["git", "init", "-q"], cwd=repo.root, check=True)
    repo.write(".gitignore", "ignored.txt\n")
    repo.write("ignored.txt", v4(192, 168, 1, 1))
    repo.write("clean.txt", "192.0.2.1\n")
    assert cc.main(["--all", "--root", str(repo.root)]) == 0
    repo.write("dirty.txt", v4(172, 20, 1, 1))
    assert cc.main(["--all", "--root", str(repo.root)]) == 1
