# Confidentiality of test-network data

NetScanner is tested on a real company network, and this repository will be
public. Nothing that identifies that network may ever be committed: real IP
or MAC addresses, hostnames, serial numbers, `sysLocation` / `sysContact`
values, site names, the company name or domain, topology, configurations,
captures, logs, database dumps, screenshots or credentials. That includes
code comments, test fixtures, docs, commit messages and examples. The exact
rules are in the `data-confidentiality` spec.

## Where real data lives

Raw data from the company network is stored **outside the repository
folder**, for example in `C:\desarrollos\NetScanner-private\`. Keeping it
outside means neither Git nor tools working on the repository folder (editors
with indexing, AI assistants) can see it.

As a second line of defence `.gitignore` excludes the usual file types for
such data (`*.pcap`, `*.pcapng`, `*.walk`, `*.snmpwalk`, `*.sql`, `*.dump`,
`*.log`, `private/`, `local/`) and `.env`. Do not rely on it: a file with an
unusual name is not ignored.

## Only anonymised data enters the repository

Before any data from the test network becomes a fixture, a lab agent or an
example, anonymise it outside the repository:

- IPv4 addresses → the lab range 10.99.0.0/24 or the documentation ranges
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
- IPv6 addresses → 2001:db8::/32.
- MAC addresses → the RFC 7042 range 00:00:5E:00:53:00–FF or locally
  administered addresses such as 02:00:00:00:00:01.
- Hostnames, sites, domains, contacts, locations and serial numbers →
  fictitious values (e.g. `lab-sw-01`, `example.invalid`).
- SNMP communities and keys → removed or replaced with obvious placeholders.

Keep the mapping between real and fictitious values outside the repository
as well. Synthetic data is labelled as synthetic.

## Raw data is never given to AI tools

Do not paste, upload or open raw captures, walks, configurations or logs in
an AI assistant, including the one used to develop this project. Give it
only the anonymised version.

### Claude Code deny rules for `local/` and their limits

`.claude/settings.json` denies Claude Code access to `local/`, the ignored
folder that holds the capture kit and anonymised captures under review. The
rules follow the Claude Code permissions documentation
(<https://code.claude.com/docs/en/permissions>, checked 2026-11-08).
`/local/**` is anchored at the repository root, and `./local/**` at the
current directory.

| Tool | Covered by | How far |
|------|------------|---------|
| Read | `Read(/local)`, `Read(/local/**)`, `Read(./local/**)` | Blocked |
| Grep, Glob | The same `Read` rules | Best effort, per the documentation. `Grep(path)` and `Glob(path)` rules are accepted but never matched, so no specific rule is possible. A search of a parent folder may still return files under `local/` |
| Edit, Write, NotebookEdit | `Edit(/local)`, `Edit(/local/**)`, `Edit(./local/**)`; `Read` deny also blocks Edit and Write | Blocked. `Write(path)` rules are never matched; `Edit` covers Write and NotebookEdit |
| Bash, PowerShell | `Read` and `Edit` rules for the file commands Claude Code recognises (`cat`, `head`, `tail`, `sed`, `tee`) and for redirect targets; `Bash(...)` and `PowerShell(...)` rules for commands with an argument starting with `local` or `./local`, or a path containing `NetScanner/local` | Partial: these rules match the command text only |

**What stays uncovered.** A tool rule cannot stop an arbitrary shell command
from reaching `local/`. A Bash or PowerShell rule matches the text of the
command, not the files a process opens. These still reach the folder:
- commands that read without naming it, such as `grep -r pattern .` from the
  repository root;
- any program that opens files itself, such as a Python or Node script, a
  `docker run -v` mount, an archiver or `git`;
- other spellings of the same path, such as variables, globs, an absolute
  path without `NetScanner`, or `sh -c` with a quoted command.

Only the operating-system sandbox of Claude Code enforces this for every
process, and it is not available on native Windows, where this project is
developed. The deny rules are therefore a safety net, not a boundary. The
rule that matters stays the one above: raw data lives outside the repository
folder and is never given to AI tools. `local/` holds only the capture kit
and anonymised data waiting for review.

## Automated checks

`scripts/check_confidentiality.py` and gitleaks run as a pre-commit hook
(`pre-commit install`) and in CI. The confidentiality check rejects:

- IPv4 addresses outside the allowed ranges, including private blocks such
  as 10.0.0.0/8 (outside 10.99.0.0/24), 172.16.0.0/12 and 192.168.0.0/16,
  and any public address;
- IPv6 addresses outside 2001:db8::/32, `::1`, `::` and a fixed list of
  well-known link-scope multicast groups — including unique local
  (fc00::/7) and link-local (fe80::/10) addresses, which can embed a MAC;
- globally administered MAC addresses in colon, hyphen or Cisco dotted
  notation;
- terms from your local `.confidential-terms` file (ignored by Git; start
  from `.confidential-terms.example`). Matches are reported by file and line
  only.

Run it over the whole repository with:

```sh
python scripts/check_confidentiality.py --all
```

Never bypass the hooks with `--no-verify`. If a value is a genuine false
positive, add a narrow entry to `.confidentiality-allowlist.yaml`: one exact
value, the files where it may appear and a reason. Whole-file exclusions are
not accepted, and entries that no longer match anything are reported.

## If something leaks

1. **Stop.** Do not push. If it is already pushed, make the repository
   private if it is not already, and do not open pull requests from the
   affected branch.
2. **Rotate any exposed credential first** (SNMP community, key, password,
   token). Assume it is compromised even if the history is rewritten.
3. **Remove it from the history**, not only from the latest commit, with
   `git filter-repo` (for example `--replace-text` with a file of
   expressions, or `--invert-paths --path <file>`), then force-push every
   affected branch and tag.
4. Ask collaborators to re-clone, and request removal of cached views from
   the hosting platform if the repository was public.
5. Add the leaked term to your local `.confidential-terms` or tighten the
   check so the same mistake is caught next time.
