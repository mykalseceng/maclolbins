# The MacLOLBins report, its flags and statuses

## What the report contains

`index.html` is a column browser over the scanned filesystem, reading `assets/data.js`:

- **Columns** walk the directory tree; file rows carry glyphs for catalogued LOLBin,
  setuid/setgid, TCC access, weakened runtime, entitlements, script, developer shim, unreadable.
- **Smart folders**: catalogued LOLBins, setuid or setgid, unsigned, private entitlements, TCC
  access, scripts.
- **Inspector** for the selected file: what it is, why it matters (abuse, ATT&CK techniques,
  worked commands), XPC-server evidence, permission matrix, SIP protection, privacy and code
  integrity (TCC grants and entitlements, hardened runtime, weakening entitlements), signing
  chain, and every entitlement with its value, grouped by namespace and linked to Apple's page
  when documented.
- **Search** over name, path, catalogue entry, tactic, technique, man-page summary, signing
  identifier and entitlement key. `index.html#/usr/bin/curl` selects a file directly.

## Which binaries are in it

The probe inventories every executable in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` and
`/usr/libexec` plus every catalogue path (about 1,650 files on macOS 26). The report, and the MCP
server's `list_lolbins`/`get_lolbin`, show only files that are

1. a catalogued path, and
2. not an inactive xcode-select shim, and
3. Apple platform-signed, or carrying SIP's `restricted` flag (which keeps unsigned Apple
   scripts such as `kickstart`).

So `lolbins_in_report` (116 on a stock macOS 26.6.2 VM) is smaller than the inventory and can
exceed the number of catalogue entries, because one entry may list several paths (e.g. "Unix
shells").

## Catalogue entry statuses (`catalogued_present`, `catalogued_absent`)

- `present`: at least one of the entry's paths exists and is usable.
- `inactive-shim`: the path is an xcode-select stub that does nothing until Command Line Tools
  are installed (`python3`, `swift` on a VM without them).
- `missing`: no path exists.

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
| `weakened-runtime` | Holds a code-signing protection weakener set to true | Host for injected code or a debugger target |
| `tcc-entitled` | Holds a `com.apple.private.tcc.*` entitlement | Reaches privacy-protected data without the usual prompt |
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
