---
name: maclolbins
description: Scan a Mac or macOS VM for living-off-the-land binaries (LOLBins) with the MacLOLBins MCP server, reproduce the MacLOLBins HTML report exactly, and answer questions about the binaries it finds — capabilities and the symbols that show them, abuse, MITRE ATT&CK techniques and tactics with links, entitlements with Apple documentation links, code signing, SIP and TCC. Use this skill whenever the user mentions macOS LOLBins or LOOBins, a LOLBin report or scan, abusable or dual-use macOS system binaries, entitlements or TCC/SIP posture of Apple binaries, ATT&CK mapping for macOS tools, or scanning a Parallels, VMware Fusion, UTM, Tart or local Mac target, even if they don't name the MacLOLBins tools.
---

# MacLOLBins

The MacLOLBins MCP server (tools appear as `mcp__maclolbins__<tool>`) probes a Mac read-only. It
inventories every executable on the target's default PATH, keeps the Apple binaries, ranks them
by evidence (capabilities from symbol names and library paths found in each binary, and
privilege signals), and renders an HTML report.
This skill covers the two things people want from it, often in the same conversation:

- **The report.** A browsable `index.html` showing every reported binary on the target. It
  is produced by MacLOLBins itself, so reproducing it means running the right tools, not writing
  HTML.
- **Answers.** Targeted questions such as "which of these can skip TCC prompts?" or "how is
  osascript abused?", answered from the same data with ATT&CK and Apple links.

Work out which the user wants. "Generate/produce/rebuild the report" wants the report;
"which/what/how/explain" wants answers; "scan my VM and tell me what's risky" wants both. If the
tools are missing, see [When the tools are not connected](#when-the-tools-are-not-connected).

## Choosing the target

The server does not decide where the binaries live; you do.

1. If the user is asking about a scan that already exists, call `list_scans` first. Scans take
   about two minutes, so reuse a scan when the question is about its data; state its
   `scan_id`, `collected_at` and macOS version so the user knows how fresh it is. Scan again
   when they ask for a new report, a fresh scan, or a target with no scan.
2. Otherwise call `discover_targets`. It lists this Mac, Parallels, Tart, VMware Fusion and UTM
   VMs, and ssh config hosts, each with a suggested `command` and a `note`.
3. Pick the target the user named. If several match or none was named and more than one is
   plausible, ask; scanning the wrong machine wastes minutes and mislabels the report.
4. Read the target's `note` before scanning; it carries the preconditions:
   - **Parallels**: needs Parallels Tools and a user logged in to the guest desktop.
   - **Tart**: needs the Tart Guest Agent (`tart exec`).
   - **VMware Fusion, UTM**: `command` is null because `vmrun`/`utmctl` cannot pipe stdin to a
     macOS guest. Either scan over SSH (`["ssh", "-o", "BatchMode=yes", "user@<guest ip>",
     "/bin/bash", "-s"]`, Remote Login on; `vmrun -T fusion getGuestIPAddress <vmx> -wait`
     prints the address), or call `get_probe_script`, have the script run in the guest
     (`/bin/bash probe.sh > probe.out`), copy `probe.out` back and call `import_probe_output`.
   - **ssh hosts**: key-based login only; BatchMode stops a password prompt from swallowing
     the probe script.
   - **This Mac**: on a Mac with Xcode installed the probe's `whatis` step can take well over
     ten minutes; warn the user and prefer a VM if they have one.

## Producing the report

The report is `<reports>/<scan_id>/index.html` plus `assets/data.js`, rendered by MacLOLBins from
`scan.json`. It is the same report whether it came from `maclolbins scan`, `scan_target`,
`import_probe_output` or `render_report`, and it is reproducible byte for byte. Hand-written
HTML, summaries or edits to those files are not the report, so do not create or modify them;
if the user wants something different, that is an answer or a new artifact, named as such.

- **New scan:** call `scan_target(command, target)`. Use a short `target` name such as the VM
  name; it becomes the `scan_id` prefix. Tell the user it takes a few minutes before starting.
- **Out-of-band probe output:** `import_probe_output(output_path, target)`.
- **Existing scan:** `render_report(scan_id)` rebuilds `index.html` and `data.js` with the
  current catalogue, so edited notes, library rules and technique mappings reach an old scan.
  A rule that names a new symbol needs a new scan, because the probe only records the symbols
  the catalogue asked for at scan time. Use it when the report is missing, or the user asks to
  regenerate it.

Each returns a summary. Give the user:

- the report as a clickable `file://<path>#/` link, and `open <path>` to open it; the page needs
  no network,
- the target, macOS version and build, and when it was collected,
- `lolbins_in_report` out of `inventoried` executables, and the PATH that was scanned
  (`path_dirs`),
- whether both TCC databases were readable (`tcc_sources`); an unreadable one means TCC grants
  are missing from the report, usually for lack of Full Disk Access.

The report deep-links to a binary with `index.html#/usr/bin/curl`, so `file://<path>#<binary
path>` points the user straight at its inspector. Counts of the report and of the scan differ by
design: the report keeps only Apple binaries and leaves out inactive developer shims
(`references/report-and-flags.md`). A binary with score 0 is in the report with no capability
or privilege evidence; say so rather than calling it dangerous.

## Answering questions

Use `list_lolbins` to find binaries and `get_lolbin` for one binary's full record; both answer
from the same data the report renders, so answers and report agree. `list_lolbins` returns rows
strongest evidence first (`score`) and filters (all must match):

- `query`: text in path, name, description, capability, technique, note, signing identifier or
  entitlement keys
- `capability`: a capability id, e.g. `fetches-urls`, `runs-programs`, `reads-keychain`
- `tactic`: an ATT&CK tactic name as the catalogue spells it (e.g. `Persistence`)
- `flag`: one flag, e.g. `setuid`, `private-entitled`, `tcc-entitled`, `weakened-runtime`
- `entitlement`: a key or prefix, e.g. `com.apple.private.tcc.`

`get_lolbin` takes a path, or a file name when it maps to one path. `explain_entitlement`
explains any key without a scan.

When you write the answer:

- **Ground it in the scan.** Name the `scan_id` and macOS version, and say what the data does
  not show: a capability means a symbol name or library path appears in the binary, not
  that a caller can drive it from the command line; XPC entries are candidates from launchd plists and strings, not tested
  connections; TCC grants exist only if the database was readable.
- **Quote the evidence.** When you say a binary can do something, name the capability and the
  `evidence` that shows it (`_curl_easy_perform`, `libcurl`), so the claim can be checked.
- **Link ATT&CK.** Every technique has a `url`; use it. Link tactics by ID from
  `references/attack.md`. The catalogue predates ATT&CK v20 (October 2026): where a technique
  or tactic changed, give the catalogue's ID first (it matches the report) and the v20
  equivalent after it, e.g. "[T1562.001](https://attack.mitre.org/techniques/T1562/001/) (in
  v20: [T1685](https://attack.mitre.org/techniques/T1685/), Defense Impairment)".
- **Link entitlements.** Use `apple_docs_url` when `documented` is true. An undocumented key
  has no Apple page; say it is undocumented and give its namespace meaning (`summary`),
  rather than guessing a URL.
- **Separate how a binary reaches TCC data.** A `com.apple.private.tcc.allow` or
  `.allow.overridable` entitlement (`tcc_services` names the services) works with no prompt on
  any Mac; a `tcc_grants` entry is a decision recorded on this Mac. Say which applies. Other
  `com.apple.private.tcc.*` keys, such as `allow-prompting`, have empty `tcc_services`: they
  are not known to grant access, so explain them by `summary` and never as a grant.
- **Explain flags in words.** `references/report-and-flags.md` says what each flag means and
  why it matters.
- **Use worked commands as they are.** `examples` come from hand-written catalogue notes, with
  their privilege level, and only some binaries have them (`has_note`). Quote them for
  detection engineering and testing on systems the user is authorised to use, without inventing
  variants that go further than the catalogue does.

A one-binary answer usually reads well in this order: what it is (description), why it matters
(capabilities with evidence, the note's abuse text if any, techniques with links, tactics), what
this Mac shows (signing, hardened runtime, SIP, entitlements with links, TCC, XPC), then any
worked commands and a deep link into the report. Lists of several binaries read better as a
table with path, score, capabilities and the relevant flags.

## When the tools are not connected

The repo's `.mcp.json` registers the server as `maclolbins` (`uv run maclolbins mcp --reports
reports`, run from the repo root). If no `mcp__maclolbins__*` tools are available, tell the user to
approve the project MCP server (`/mcp` in Claude Code) or restart the session. From a shell,
`uv run maclolbins scan --vm <parallels vm>` and `uv run maclolbins render <scan.json>` produce the
same report; the CLI scan only reaches Parallels VMs.

## Reference files

- `references/attack.md`: tactic IDs and links, and the ATT&CK v20 changes that affect the
  catalogue. Read it whenever an answer names tactics or techniques.
- `references/report-and-flags.md`: the PATH scope, what the report keeps and leaves out,
  capabilities and the evidence score, notes, every flag and signing state. Read it when
  explaining scope, counts, flags or the report's contents.
