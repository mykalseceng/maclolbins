# lolbins

Enumerates macOS living-off-the-land binaries (LOLBins) on a Mac or macOS VM and builds a static
site documenting each one. The same data is served to agents over MCP (see
[MCP server](#mcp-server)).

## Usage

```sh
uv sync
uv run lolbins scan --vm macOS          # probe the VM, write reports/<vm>-<timestamp>/
uv run lolbins render reports/<dir>/scan.json   # re-render the site from saved data
```

`scan` runs `prlctl exec <vm> --current-user /bin/bash -s` and pipes in the probe, so it needs
Parallels Desktop, a running VM, and a logged-in user. It runs read-only and needs no password or
sudo. A full scan of about 1,650 binaries takes roughly 80 seconds, most of it spent in
`whatis` looking up man-page summaries.

Each scan directory contains:

- `scan.json`: the full result (host facts, TCC grants, launchd Mach-service registrations,
  catalog matches, and the inventory with signing, entitlements, permissions, file flags and
  SHA-256 for every binary). This is the stable interface for later tooling; its shape is the
  `ScanResult` TypedDict in `src/lolbins/scan.py`.
- `index.html` plus `assets/data.js`: the report, rendered from `scan.json`. Open
  `index.html` in a browser or host the directory anywhere static; keep the two together.

`reports/` is gitignored because scans contain host details.

## MCP server

`lolbins mcp` serves scans over the Model Context Protocol on stdio. It speaks protocol revision
2026-07-28 (stateless: no `initialize` handshake or session; `tools/list` carries a one-hour
public cache hint) through the `mcp` 2.x Python SDK's `MCPServer`. To add it to Claude Code:

```sh
claude mcp add lolbins -- \
  uv --directory /path/to/lolbins run lolbins mcp --reports /path/to/lolbins/reports
```

| Tool | What it does |
|------|--------------|
| `discover_targets` | Lists this Mac, Parallels, Tart, VMware Fusion and UTM VMs, and `~/.ssh/config` hosts, each with a suggested scan command |
| `scan_target` | Pipes the probe into any argv that runs bash reading stdin on the target; saves `scan.json` and the HTML report |
| `get_probe_script` | Returns the probe script, for targets that cannot take it on stdin |
| `import_probe_output` | Builds a scan and report from probe output captured on the target |
| `list_scans` | Lists saved scans with their target, macOS version and report path |
| `list_lolbins` | Lists a scan's report binaries, filtered by text, tactic, flag or entitlement prefix |
| `get_lolbin` | Everything the report says about one binary: description, abuse, ATT&CK techniques with links, worked commands, file facts, SIP, signing, entitlements with values and Apple documentation links, TCC grants, XPC evidence |
| `explain_entitlement` | Apple's documentation and link for an entitlement key, or its namespace meaning |

The server does not decide how to reach the binaries; the agent does. `scan_target` takes any argv
that starts bash reading a script from stdin on the target:

| Target | Command |
|--------|---------|
| This Mac | `["/bin/bash", "-s"]` |
| Parallels | `["prlctl", "exec", "<vm>", "--current-user", "/bin/bash", "-s"]` |
| Tart | `["tart", "exec", "-i", "<vm>", "/bin/bash", "-s"]` (needs the Tart Guest Agent) |
| Any Mac with Remote Login, including VMware Fusion and UTM guests | `["ssh", "-o", "BatchMode=yes", "user@host", "/bin/bash", "-s"]` |

VMware Fusion's `vmrun` and UTM's `utmctl` cannot attach stdin to a program in a macOS guest; reach
those guests over SSH, or run `get_probe_script`'s script in the guest by any means and pass its
saved stdout to `import_probe_output`.

`scan_target` and `import_probe_output` return a `scan_id`, the name of the scan's report
directory; the query tools take it as an argument, so scans from `lolbins scan` are served too.
Every answer about a binary is built from the same data the HTML report renders
(`site_data()`), and `tests/parity.py` checks the two agree field by field.

## How it works

| File | Role |
|------|------|
| `src/lolbins/catalog.toml` | The LOLBin catalog: binaries, paths, ATT&CK techniques, privilege, abuse |
| `src/lolbins/catalog.py` | Loads and validates the catalog |
| `src/lolbins/probe.sh` | Guest-side collector; emits tab-separated records |
| `src/lolbins/probe.py` | Runs the probe through a command (prlctl) and parses its records |
| `src/lolbins/scan.py` | Matches the inventory to the catalog; file-flag heuristics |
| `src/lolbins/entitlements.py` | Explains entitlement keys against Apple's documentation |
| `src/lolbins/tcc.py` | Names TCC services the way System Settings does |
| `src/lolbins/apple_entitlements.json` | Apple's documented entitlements (built by `scripts/update_apple_entitlements.py`) |
| `src/lolbins/browser.html` | The report page: a column browser that reads `assets/data.js` |
| `src/lolbins/site.py` | Writes the report page and its data file |
| `src/lolbins/reports.py` | Writes each scan into its report directory; finds scans by ID |
| `src/lolbins/targets.py` | Finds reachable Macs and VMs and the command that reaches each |
| `src/lolbins/views.py` | Shapes report data into the MCP server's answers |
| `src/lolbins/server.py` | The MCP server and its tools |
| `src/lolbins/cli.py` | `scan`, `render` and `mcp` commands |

The probe inventories top-level executables in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` and
`/usr/libexec`, plus every catalog path. This broad inventory is retained in `scan.json` so the
catalogue can be audited for omissions. The rendered report shows only usable, catalogued paths
that are Apple platform-signed or protected by SIP; inactive developer-tool shims and
third-party paths are excluded. For each probed path it records `stat` (including BSD file
flags, where SIP's `restricted` flag shows), SHA-256, `codesign` details, entitlements, and its
one-line man-page summary from `whatis` (when the VM has a man page for it).

It also reads both TCC databases (`/Library/Application Support/com.apple.TCC/TCC.db` and the
user's own) with `sqlite3 -readonly`. Reading them needs Full Disk Access; a database the probe
cannot open is recorded as unreadable rather than failing the scan. Each binary is matched to the
grants that name it by path or signing identifier.

The probe also intersects the inventoried executable paths with launchd jobs that declare
`MachServices`. For each match it records the job label, system or per-user launchd domain, plist
path, exact service properties, and recognized static XPC listener markers in the executable.
This is candidate discovery only: it does not look up a Mach service, open an XPC connection,
enumerate exported methods, or test connection-admission and authorization checks.

From that data the scan flags binaries that are not SIP-protected, hold TCC entitlements, hold an
allowed TCC grant, or hold an entitlement that weakens code-signing protections (such as
`get-task-allow` or `disable-library-validation`).

The report is a single page, `index.html`, that reads its data from `assets/data.js`. It is a
column browser over the scanned filesystem, in the style of Finder's column view:

- **Columns** walk the real directory tree. Folder rows roll up what they contain; file rows
  carry glyphs for catalogued LOLBin, setuid/setgid, TCC access, weakened runtime, entitlements,
  script, developer shim and unreadable. Folders over 40 items get a filter box, a *Show* menu
  and sticky A-Z headings. Column widths and the two dividers are draggable.
- **Smart folders** in the sidebar cut across the tree: catalogued LOLBins, setuid or setgid,
  unsigned, private entitlements, TCC access and scripts.
- **Inspector** shows the selected file: what it is, why it matters (abuse notes, ATT&CK
  techniques and worked commands for catalogued entries), any XPC-server candidate evidence and
  documented functionality, a permission matrix with the setuid and setgid bits called out, SIP
  protection, privacy and code integrity (TCC grants and entitlements, hardened runtime, and any
  entitlement that weakens code signing), the signing chain drawn leaf to root, and every
  entitlement with its exact value grouped by namespace.
  Keys listed in [Apple's entitlement documentation](https://developer.apple.com/documentation/bundleresources/entitlements)
  link to their Apple page; keys not listed are undocumented by definition.
- **Search** matches name, path, catalogue entry, tactic, technique, man-page summary, signing
  identifier and entitlement key.

A catalog path that is an xcode-select stub, doing nothing until Command Line Tools are
installed, is marked *Inactive shim*; an absent path is *Missing*. Selections are addressable:
`index.html#/usr/bin/curl`. The page needs no network and keeps its state in the URL.

## Extending

- **Add a LOLBin:** add a `[[binary]]` block to `catalog.toml`, with one or more
  `[[binary.example]]` blocks (title, command, explanation). If it uses a new technique, define
  the technique in `[techniques]`. The loader rejects unknown techniques, duplicate names or
  paths, and unused technique definitions.
- **Refresh Apple's entitlement docs:** `uv run python scripts/update_apple_entitlements.py`.
- **Scan another target:** use the MCP server's `scan_target`, or call `run_probe` with any
  argv that runs bash reading the script from stdin, e.g. `["ssh", "host", "/bin/bash", "-s"]`.

## Development

```sh
uv run pytest
uv run ruff format && uv run ruff check && uv run ty check
shellcheck src/lolbins/probe.sh && shfmt -d src/lolbins/probe.sh
```

The probe tests run `probe.sh` against the local Mac and are skipped on other platforms.
