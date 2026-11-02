# MacLOLBins

Finds the Apple living-off-the-land binaries (LOLBins) on a Mac or macOS VM and shows what each one
can do there. The scan reads the target's default PATH from `/etc/paths` and `/etc/paths.d`,
inventories every executable on it, and reports every Apple binary there, ranked by evidence.
Capabilities come from symbol names and library paths found in each binary (for example
`_curl_easy_perform` or `libcurl` for making HTTP requests); privilege signals are setuid/setgid,
private or TCC entitlements, a weakened runtime and launchd XPC services. The tool derives all of
it from the binaries themselves rather than a list of names, and a binary with no evidence is
still listed, with a score of 0.

For each binary the report shows its capabilities and the evidence behind them, MITRE ATT&CK
techniques, permissions and SIP protection, its code signature and hardened runtime, every
entitlement with Apple's documentation, TCC access by entitlement and by grant, and the launchd
services that run it. Hand-written notes in `src/maclolbins/catalog.toml` add abuse text and worked
commands for some paths; they never decide what is reported or how it ranks. Each scan writes a single-page HTML
report.

## Usage

```sh
uv run maclolbins scan --vm macOS                 # scan a Parallels VM into reports/
uv run maclolbins render reports/SCAN/scan.json   # rebuild a report from a saved scan
uv run maclolbins mcp --reports reports           # serve scans to agents over MCP
```

`scan` pipes a read-only probe into `prlctl exec <vm> --current-user /bin/bash -s`, so it needs a
running VM with a logged-in user; a scan takes about two minutes. Open `index.html` in the
scan directory; `index.html#/usr/bin/curl` selects a binary.

`mcp` serves the same data to agents over MCP and is registered for Claude Code in `.mcp.json`. Its
`scan_target` tool takes any argv that runs bash on the target, so an agent can scan this Mac, a
Parallels or Tart VM, or any Mac over SSH; VMware Fusion and UTM guests go through
`get_probe_script` and `import_probe_output`. The skill in `.claude/skills/maclolbins` teaches
Claude Code to produce reports through these tools and to answer questions with ATT&CK and Apple
documentation links.

## Development

```sh
uv sync
uv run pytest -q
uv run ruff check && uv run ruff format --check && uv run ty check
shellcheck src/maclolbins/probe.sh && shfmt -d src/maclolbins/probe.sh
prek install
```
