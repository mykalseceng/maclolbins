# MacLOLBins

Finds the Apple living-off-the-land binaries (LOLBins) on a Mac or macOS VM and shows what each
one can do there: how it is abused (MITRE ATT&CK), its code signature, every entitlement with
Apple's documentation, SIP protection and TCC grants. Each scan writes a single-page HTML
report, and an MCP server and Claude Code skill expose the same data to agents.

## Usage

```sh
uv sync
uv run maclolbins scan --vm macOS                    # scan a Parallels VM, write reports/<vm>-<time>/
uv run maclolbins render reports/<scan>/scan.json    # rebuild a report from a saved scan
uv run maclolbins mcp --reports reports              # serve scans over MCP (stdio)
```

`scan` pipes a read-only probe into `prlctl exec <vm> --current-user /bin/bash -s`, so it needs
Parallels Desktop, a running VM and a logged-in user. A scan of about 1,650 binaries takes two to
three minutes. Each scan directory holds `scan.json` and the report (`index.html` plus
`assets/data.js`); `reports/` is gitignored because scans contain host details.

## Report

`index.html` is a column browser over the scanned filesystem; open it in a browser, no network
needed. `index.html#/usr/bin/curl` selects a binary. It shows the catalogued binaries that are
Apple platform-signed or SIP-protected (116 on macOS 26.6.2), and for each one:

- what it is (man-page summary) and why it matters: abuse, ATT&CK techniques and tactics linked
  to attack.mitre.org, and worked commands with the privilege they need
- permissions, owner, setuid/setgid, SIP `restricted` flag, SHA-256
- signing chain, platform binary, hardened runtime, and entitlements that weaken it
- every entitlement with its exact value, linked to Apple's page when Apple documents it
- TCC access by entitlement (no prompt) and by grants in the system and user TCC databases
- launchd Mach services that run it (XPC-server candidates; never connected to)

Smart folders cut across the tree: setuid or setgid, unsigned, private entitlements, TCC access,
weakened runtime and scripts. Search covers names, paths, techniques, tactics, signing
identifiers and entitlement keys.

## MCP server

`maclolbins mcp` speaks MCP protocol revision 2026-07-28 (stateless, via the `mcp` 2.x SDK).
`.mcp.json` registers it for Claude Code in this repo.

| Tool | |
|---|---|
| `discover_targets` | This Mac, Parallels, Tart, VMware Fusion and UTM VMs, and ssh hosts, each with a scan command |
| `scan_target` | Pipes the probe into any argv that runs bash on the target; writes the scan and report |
| `get_probe_script`, `import_probe_output` | For targets that cannot take the probe on stdin (Fusion, UTM) |
| `render_report` | Rebuilds a saved scan's report, byte-identical to `maclolbins render` |
| `list_scans`, `list_lolbins`, `get_lolbin` | Query a scan; answers match the report field for field |
| `explain_entitlement` | Apple's documentation for an entitlement key, or its namespace meaning |

The agent decides how to reach the target: `["/bin/bash", "-s"]` for this Mac,
`["prlctl", "exec", "<vm>", "--current-user", "/bin/bash", "-s"]`, `["tart", "exec", "-i",
"<vm>", "/bin/bash", "-s"]`, or `["ssh", "-o", "BatchMode=yes", "user@host", "/bin/bash",
"-s"]`.

## Skill

`.claude/skills/maclolbins` teaches Claude Code to use the server: pick the target, produce the
report only through the tools so it matches `maclolbins render` exactly, and answer questions
with ATT&CK technique and tactic links, Apple entitlement links, and notes where the catalogue's
techniques changed in ATT&CK v20.

## Safety

The probe is read-only: it writes nothing outside its own temp directory, needs no sudo, and
reads the TCC databases with `sqlite3 -readonly` (an unreadable database is recorded, not an
error). XPC entries come from launchd plists and static strings; no service is looked up or
connected to. `scan_target` runs the argv it is given, so review it before approving the call.

## Development

```sh
uv run pytest -q
uv run ruff check && uv run ruff format --check && uv run ty check
shellcheck src/maclolbins/probe.sh && shfmt -d src/maclolbins/probe.sh
uv run python scripts/update_apple_entitlements.py   # refresh Apple's entitlement docs
prek install
```

Add a LOLBin with a `[[binary]]` block in `src/maclolbins/catalog.toml`; the loader rejects
unknown techniques, duplicate names or paths, and unused technique definitions.
