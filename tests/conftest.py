import base64

APPLE_CODESIGN = """Executable=/usr/bin/curl
Identifier=com.apple.curl
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=679 flags=0x10000(runtime) hashes=16+2 location=embedded
Platform identifier=26
Signature size=4567
Authority=macOS Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
TeamIdentifier=not set
"""

SHIM_CODESIGN = """Executable=/usr/bin/swift
Identifier=com.apple.dt.xcode_select.tool-shim-public
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=500 flags=0x0(none) hashes=5+7 location=embedded
Platform identifier=26
Authority=macOS Software Signing
TeamIdentifier=not set
"""

ENTITLEMENTS_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
    "<key>com.apple.private.tcc.allow</key><array><string>kTCCServiceAll</string></array>"
    "<key>com.apple.security.cs.disable-library-validation</key><true/>"
    "<key>com.apple.application-identifier</key><string>x</string>"
    "</dict></plist>"
)


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def f_record(path: str, codesign: str = APPLE_CODESIGN, ents: str = "", link: str = "") -> str:
    return f"F\t{path}\t{link}\t0\t{b64(codesign)}\t{b64(ents)}"


def probe_text(*records: str, facts: dict[str, str] | None = None) -> str:
    facts = facts or {"collected_at": "2026-10-26T17:00:00Z", "developer_dir": "none"}
    lines = [f"H\t{key}\t{value}" for key, value in facts.items()]
    lines.extend(records)
    lines.append("E\tok")
    return "\n".join(lines) + "\n"
