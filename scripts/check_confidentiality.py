# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Francisco Javier Castro Jiménez
# Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
# Computer Engineering, Universidad Internacional de La Rioja (UNIR).
"""Confidentiality check: rejects real network identifiers in repository files.

Implements the rules of the ``data-confidentiality`` spec (design D11):
IPv4, IPv6 and MAC addresses outside the allowed ranges, terms from a local
Git-ignored list, and narrow exceptions from a committed allowlist.

Usage:
    check_confidentiality.py [--all] [FILE ...]

Exit codes: 0 clean, 1 findings or stale allowlist entries, 2 configuration
error.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

TERMS_FILE = ".confidential-terms"
ALLOWLIST_FILE = ".confidentiality-allowlist.yaml"

ALLOWED_IPV4 = [
    ipaddress.ip_network(n)
    for n in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "10.99.0.0/24",
        "127.0.0.0/8",
        "0.0.0.0/32",
        "255.255.255.255/32",
    )
]
ALLOWED_IPV6_NETWORKS = [ipaddress.ip_network("2001:db8::/32")]
# Loopback, unspecified and a fixed list of well-known link-scope multicast
# groups. Solicited-node groups are excluded because they embed host bits.
ALLOWED_IPV6_ADDRESSES = {
    ipaddress.ip_address(a)
    for a in (
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
    )
}

# Dotted quads not preceded by a digit or dot and not followed by a digit or
# by a dot plus digit, so OIDs and version strings are not candidates.
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?!\d|\.\d)")
# Colon-separated hexadecimal groups, optionally ending in an embedded IPv4.
IPV6_RE = re.compile(
    r"(?<![\w:.])((?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}))"
    r"(/\d{1,3})?(?![\w:])"
)
MAC_RES = [
    re.compile(r"(?<![\w:])((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?![\w:])"),
    re.compile(r"(?<![\w-])((?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2})(?![\w-])"),
    re.compile(r"(?<![\w.])([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![\w.])"),
]
TIME_RE = re.compile(r"\d{1,2}:\d{2}(?::\d{2})?")

ALLOWED_MACS = {bytes(6), bytes.fromhex("ffffffffffff"), bytes.fromhex("01000ccccccc")}


@dataclass
class Finding:
    path: str
    line: int
    kind: str
    value: str | None  # None when the value must not be printed

    def __str__(self) -> str:
        detail = f": {self.value}" if self.value is not None else ""
        return f"{self.path}:{self.line}: {self.kind}{detail}"


@dataclass
class AllowEntry:
    value: str
    paths: list[str]
    reason: str
    patterns: list[re.Pattern[str]] = field(default_factory=list)
    used: bool = False

    def applies_to(self, path: str) -> bool:
        return any(p.fullmatch(path) for p in self.patterns)


class ConfigError(Exception):
    pass


def glob_to_regex(glob: str) -> re.Pattern[str]:
    """Translate a path glob (``**``, ``*``, ``?``) to a regex on POSIX paths."""
    out = []
    i = 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out))


def load_allowlist(path: Path) -> list[AllowEntry]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = []
    for i, raw in enumerate(data.get("entries") or [], start=1):
        if not isinstance(raw, dict):
            raise ConfigError(f"allowlist entry {i} is not a mapping")
        value, paths, reason = raw.get("value"), raw.get("paths"), raw.get("reason")
        if not isinstance(value, str) or not value or any(c in value for c in "*?["):
            raise ConfigError(f"allowlist entry {i}: 'value' must be one exact value")
        if isinstance(paths, str):
            paths = [paths]
        if not paths or not all(isinstance(p, str) and p for p in paths):
            raise ConfigError(f"allowlist entry {i}: 'paths' must list one or more files")
        if not isinstance(reason, str) or not reason.strip():
            raise ConfigError(f"allowlist entry {i}: 'reason' is required")
        entry = AllowEntry(value=value, paths=paths, reason=reason)
        entry.patterns = [glob_to_regex(p) for p in paths]
        entries.append(entry)
    return entries


def load_terms(path: Path) -> list[str] | None:
    if not path.exists():
        return None
    terms = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line.casefold())
    return terms


def ipv4_allowed(addr: ipaddress.IPv4Address) -> bool:
    return any(addr in net for net in ALLOWED_IPV4)


def ipv6_allowed(addr: ipaddress.IPv6Address) -> bool:
    return addr in ALLOWED_IPV6_ADDRESSES or any(addr in net for net in ALLOWED_IPV6_NETWORKS)


def mac_allowed(mac: bytes) -> bool:
    if mac in ALLOWED_MACS:
        return True
    if mac[:5] == bytes.fromhex("00005e0053"):
        return True
    if mac[:5] == bytes.fromhex("0180c20000") and mac[5] <= 0x0F:
        return True
    first = mac[0]
    return bool(first & 0x02) and not first & 0x01  # locally administered unicast


def parse_mac(token: str) -> bytes | None:
    digits = re.sub(r"[:.\-]", "", token)
    if len(digits) != 12:
        return None
    return bytes.fromhex(digits)


def is_mac(token: str) -> bool:
    return any(rx.fullmatch(token) for rx in MAC_RES[:2])


def scan_line(text: str) -> list[tuple[str, str]]:
    """Return ``(kind, token)`` for every forbidden identifier in one line."""
    found: list[tuple[str, str]] = []

    for m in IPV4_RE.finditer(text):
        try:
            addr = ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        if not ipv4_allowed(addr):
            found.append(("IPv4 address", m.group(0)))

    for m in IPV6_RE.finditer(text):
        token = m.group(1)
        if token.startswith(":") and not token.startswith("::"):
            token = token[1:]
        if token.endswith(":") and not token.endswith("::"):
            token = token[:-1]
        if "::" not in token and token.count(":") < 7:
            continue
        if is_mac(token) or TIME_RE.fullmatch(token) or re.fullmatch(r"::\d*", token):
            continue  # MACs, times and slice syntax such as ``[::2]``
        try:
            addr = ipaddress.IPv6Address(token)
        except ValueError:
            continue
        if addr.ipv4_mapped is not None:
            continue  # the embedded IPv4 is checked by the IPv4 rule
        if not ipv6_allowed(addr):
            found.append(("IPv6 address", token + (m.group(2) or "")))

    for rx in MAC_RES:
        for m in rx.finditer(text):
            mac = parse_mac(m.group(1))
            if mac is not None and not mac_allowed(mac):
                found.append(("MAC address", m.group(1)))

    return found


# Netmasks are allowed only in the ipAdEntNetMask column of lab data (design
# D12 of add-snmp-client-and-lab); there is no global "looks like a mask" rule.
LAB_DATA_RE = glob_to_regex("lab/**/*.snmprec")
NETMASK_OID_PREFIX = "1.3.6.1.2.1.4.20.1.3."


def is_contiguous_netmask(value: str) -> bool:
    try:
        n = int(ipaddress.IPv4Address(value))
    except ValueError:
        return False
    inverted = n ^ 0xFFFFFFFF
    return inverted & (inverted + 1) == 0  # ones followed only by zeros


def lab_netmask(rel: str, line: str) -> str | None:
    """The netmask value of an ``ipAdEntNetMask`` line in lab data, if any."""
    if not LAB_DATA_RE.fullmatch(rel):
        return None
    parts = line.split("|", 2)
    if len(parts) != 3 or not parts[0].startswith(NETMASK_OID_PREFIX):
        return None
    value = parts[2].strip()
    return value if is_contiguous_netmask(value) else None


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def scan_file(
    root: Path,
    rel: str,
    allowlist: list[AllowEntry],
    terms: list[str] | None,
) -> list[Finding]:
    try:
        data = (root / rel).read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        return []
    if is_binary(data):
        return []
    text = data.decode("utf-8", errors="replace")
    applicable = [e for e in allowlist if e.applies_to(rel)]
    # The allowlist itself necessarily contains the values it allows.
    own_values = {e.value for e in allowlist} if rel == ALLOWLIST_FILE else set()

    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        netmask = lab_netmask(rel, line)
        for kind, token in scan_line(line):
            if token in own_values:
                continue
            if kind == "IPv4 address" and token == netmask:
                continue
            entry = next((e for e in applicable if e.value == token), None)
            if entry is not None:
                entry.used = True
                continue
            findings.append(Finding(rel, lineno, kind, token))
        if terms:
            folded = line.casefold()
            if any(t in folded for t in terms):
                findings.append(Finding(rel, lineno, "confidential term from local list", None))
    return findings


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return sorted({p for p in out.decode("utf-8").split("\0") if p})


def run(
    root: Path,
    files: list[str],
    *,
    check_stale: bool,
    terms_path: Path,
    allowlist_path: Path,
    out=sys.stdout,
    err=sys.stderr,
) -> int:
    try:
        allowlist = load_allowlist(allowlist_path)
    except (ConfigError, yaml.YAMLError) as exc:
        print(f"confidentiality: invalid allowlist: {exc}", file=err)
        return 2
    terms = load_terms(terms_path)
    if terms is None:
        print(
            f"confidentiality: notice: {TERMS_FILE} not found, term check skipped",
            file=err,
        )

    findings: list[Finding] = []
    for rel in files:
        findings.extend(scan_file(root, rel, allowlist, terms))

    for f in findings:
        print(f, file=out)
    stale = [e for e in allowlist if not e.used] if check_stale else []
    for e in stale:
        print(
            f"{allowlist_path.name}: stale entry {e.value!r} for {', '.join(e.paths)}",
            file=out,
        )
    if findings or stale:
        print(
            f"confidentiality: {len(findings)} finding(s), {len(stale)} stale entr(y/ies). "
            "See docs/confidentiality.md.",
            file=err,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="*", help="files to check (relative to --root)")
    parser.add_argument("--all", action="store_true", help="check every tracked file")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--terms", type=Path, help=f"term list (default: ROOT/{TERMS_FILE})")
    parser.add_argument("--allowlist", type=Path, help=f"default: ROOT/{ALLOWLIST_FILE}")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if args.all:
        files = tracked_files(root)
    else:
        files = [Path(f).resolve().relative_to(root).as_posix() for f in args.files]
    return run(
        root,
        files,
        check_stale=args.all,
        terms_path=args.terms or root / TERMS_FILE,
        allowlist_path=args.allowlist or root / ALLOWLIST_FILE,
    )


if __name__ == "__main__":
    sys.exit(main())
