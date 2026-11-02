# The MacLOLBins report, its scope, evidence and flags

## What the report contains

`index.html` is a column browser over the scanned filesystem, reading `assets/data.js`:

- **Columns** walk the directory tree; file rows carry glyphs for worked commands (a catalogue
  note), setuid/setgid, TCC access, weakened runtime, entitlements, XPC candidate, script,
  unreadable.
- **Smart folders**: with worked commands, setuid or setgid, unsigned, private entitlements, TCC
  access, weakened runtime, scripts. **Capabilities**: one folder per capability rule that
  matched, strongest evidence first.
- **Inspector** for the selected file: what it is, why it matters (capabilities with the symbols
  or library paths that show them, the note's abuse text if any, ATT&CK techniques, evidence score),
  XPC-server evidence, worked commands, permission matrix, SIP protection, privacy and code
  integrity (TCC grants and entitlements, hardened runtime, weakening entitlements), signing
  chain, and every entitlement with its value, grouped by namespace and linked to Apple's page
  when documented.
- **Search** over name, path, note, capability, tactic, technique, man-page summary, signing
  identifier and entitlement key. `index.html#/usr/bin/curl` selects a file directly.
- The overview (`#/`) shows the PATH that was scanned, how many executables were inventoried,
  and the fifteen binaries with the strongest evidence.

## Which binaries are in it

The probe reads the target's default PATH the way `path_helper` builds it: `/etc/paths`, then
each file in `/etc/paths.d` in name order (`path_dirs` in `list_scans`). It inventories every
executable at the top level of those directories (`inventoried`). App bundles, frameworks,
`/usr/libexec` and other helpers that are not on PATH are out of scope: they are services other
programs start, not commands someone runs by name.

The report, and the MCP server's `list_lolbins`/`get_lolbin`, keep a file when it is

1. part of the Apple install: platform-signed, or carrying SIP's `restricted` flag (which keeps
   Apple's unsigned system scripts), and
2. not an inactive xcode-select shim.

Evidence does not decide inclusion; it ranks. A tool whose abuse is its normal job (`id`,
`base64`, `chmod`) shows nothing distinctive, so it is listed with a `score` of 0 rather than
dropped. `lolbins_in_report` is smaller than `inventoried` only because of third-party
executables and inactive shims. The privilege signals are `setuid`, `setgid`,
`private-entitled`, `tcc-entitled`, `tcc-granted`, `weakened-runtime` and
`xpc-server-candidate`.

## Capabilities and evidence

Each capability rule in the catalogue lists symbol names (`_posix_spawn`,
`_OBJC_CLASS_$_NSURLSession`, ...) and library names (`libcurl`, `Tcl`, ...). The probe greps the
whole binary for them, so `evidence` shows exactly which symbols or library paths matched. Most
are imports and load commands, but a symbol the binary defines, or a name inside a text string,
matches too: `DirectoryService` matches Open Directory names it implements itself, and `open`
carries a table of framework paths it never loads. Read `evidence` as "found in the binary", not
"imported". A capability says what the code can do, not that a caller can drive it from
the command line: `runs-programs` on a binary that only starts a fixed helper is still a match.
Functionality compiled into the binary (`sqlite3`, `zip`) leaves no symbol to find, so it shows only if
another symbol or library gives it away. Scripts get no capabilities.

`score` is one point per capability plus two per privilege signal; `list_lolbins` returns rows
highest score first, and binaries with no evidence come last with 0.

## Notes and worked commands

Catalogue notes are hand-written abuse text and worked commands for specific paths. They show in
`abuse` and `examples` when a reported binary has one, and add their techniques, but they never
decide whether a binary is reported or change its score. `has_note` in `list_lolbins` says which rows have one.

## File flags

| Flag | Meaning | Why it matters |
|---|---|---|
| `setuid` / `setgid` | Runs with the file owner's / group's ID | A setuid-root binary is a privilege boundary |
| `world-writable` | Anyone can modify the file | Anyone can replace what others execute |
| `dev-shim` | xcode-select tool shim | Inactive until developer tools are installed |
| `script` | Starts with `#!` | Behaviour comes from an interpreter; usually unsigned |
| `unsigned` | No code signature (scripts excluded) | No signing identity or entitlements to check |
| `adhoc-signed` | Signed without an identity | Not traceable to a developer |
| `unreadable` | codesign could not read it | Signing facts unknown |
| `third-party` | Signed with a Team ID | Not part of the Apple install |
| `sip-unprotected` | No SIP `restricted` flag | Root can modify or replace it |
| `private-entitled` | Holds a `com.apple.private.*` or `com.apple.rootless.*` entitlement | Reserved for Apple code; Apple services trust these keys |
| `weakened-runtime` | Holds a code-signing protection weakener set to true | Host for injected code or a debugger target |
| `tcc-entitled` | Holds a `com.apple.private.tcc.*` entitlement | `allow` and `allow.overridable` reach the services in `tcc_services` with no prompt; manager keys change TCC grants; others, such as `allow-prompting`, are undocumented |
| `tcc-granted` | A TCC database grants it `allowed` | Consent was recorded on this Mac |
| `xpc-server-candidate` | Registered as a launchd Mach service | Possible XPC attack surface; not verified |

Weakening entitlements: `com.apple.security.get-task-allow` / `get-task-allow`,
`com.apple.security.cs.disable-library-validation`,
`com.apple.private.security.clear-library-validation`,
`com.apple.security.cs.allow-dyld-environment-variables`,
`com.apple.security.cs.allow-unsigned-executable-memory`,
`com.apple.security.cs.disable-executable-page-protection`. They count only with the value true;
`get_lolbin` sets `weakens_runtime` to the reason when that is so.

## Signing

`signing.state` is `signed`, `adhoc`, `unsigned` or `unreadable`. `platform_binary` marks Apple's
own platform code; Apple binaries have no `team_id`. `hardened_runtime` is true when the code
directory flags include `runtime`; platform binaries are protected by the system instead.

## TCC

Two databases: system (`/Library/Application Support/com.apple.TCC/TCC.db`) and the user's own.
Reading them needs Full Disk Access for whatever runs the probe; `tcc_sources` records `ok`,
`unreadable` or `missing`. A grant's `auth` is `allowed`, `denied`, `limited`, `unknown` or
`other`; it matches a binary by path (`client_type: path`) or signing identifier (`bundle`).
`target` is the object of the grant, such as the app an Automation grant controls.

## XPC evidence

An `xpc` entry means a launchd plist in `/System/Library/Launch{Agents,Daemons}` or
`/Library/Launch{Agents,Daemons}` registers Mach services whose program is this binary, with any
listener symbols found in the file (`NSXPCListener`, `xpc_main`, ...). The probe never looks up
the service or connects to it, so exported methods and client checks are unknown.
