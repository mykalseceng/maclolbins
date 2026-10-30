# MacLOLBins

Finds the Apple living-off-the-land binaries (LOLBins) on a Mac or macOS VM and shows what each
one can do there: how it is abused, with MITRE ATT&CK techniques and worked commands, its
permissions and SIP protection, its code signature and hardened runtime, every entitlement with
Apple's documentation, TCC access by entitlement and by grant, and the launchd services that run
it. Each scan writes a single-page HTML report.

## Usage

```sh
uv run maclolbins scan --vm macOS                 # scan a Parallels VM into reports/
uv run maclolbins render reports/SCAN/scan.json   # rebuild a report from a saved scan
uv run maclolbins mcp --reports reports           # serve scans to agents over MCP
```

`scan` pipes a read-only probe into `prlctl exec <vm> --current-user /bin/bash -s`, so it needs a
running VM with a logged-in user; a scan takes two to three minutes. Open `index.html` in the
scan directory; `index.html#/usr/bin/curl` selects a binary.

`mcp` serves the same data to agents over MCP 2026-07-28 and is registered for Claude Code in
`.mcp.json`. Its `scan_target` tool takes any argv that runs bash on the target, so an agent can
scan this Mac, a Parallels or Tart VM, or any Mac over SSH; VMware Fusion and UTM guests go
through `get_probe_script` and `import_probe_output`. The skill in `.claude/skills/maclolbins`
teaches Claude Code to produce reports through these tools and to answer questions with ATT&CK
and Apple documentation links.

## Safety

The probe is read-only: it needs no sudo, writes nothing outside its own temp directory, and
opens the TCC databases with `sqlite3 -readonly`, recording an unreadable one rather than
failing. XPC services are found from launchd plists and never contacted. Scans contain host
details, so `reports/` is gitignored. `scan_target` runs the argv the agent gives it; review it
before approving the call.

## Development

```sh
uv sync
uv run pytest -q
uv run ruff check && uv run ruff format --check && uv run ty check
shellcheck src/maclolbins/probe.sh && shfmt -d src/maclolbins/probe.sh
prek install
```
