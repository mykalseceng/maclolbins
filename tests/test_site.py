import json
import re
from pathlib import Path

import pytest
from conftest import APPLE_CODESIGN, ENTITLEMENTS_PLIST, SHIM_CODESIGN, b64, f_record, probe_text

from lolbins.catalog import load_catalog
from lolbins.probe import parse_output
from lolbins.scan import build_scan
from lolbins.site import render_site, site_data

CATALOG = """
[meta]
version = "test"

[techniques]
"T1059" = { name = "Command and Scripting Interpreter", tactics = ["Execution"] }

[[binary]]
name = "osascript"
paths = ["/usr/bin/osascript"]
techniques = ["T1059"]
privilege = "user"
abuse = "runs scripts"
xpc_functionality = "Runs a test XPC interface."

[[binary.example]]
title = "Run a command"
command = "osascript -e 'do shell script \\"id\\"'"
explanation = "runs a shell command"

[[binary]]
name = "swift"
paths = ["/usr/bin/swift"]
techniques = ["T1059"]
privilege = "user"
abuse = "runs code when developer tools are installed"

[[binary]]
name = "vendor-tool"
paths = ["/opt/vendor/tool"]
techniques = ["T1059"]
privilege = "user"
abuse = "must not appear in this Apple-only report"
"""


@pytest.fixture
def scan(tmp_path: Path):
    catalog_path = tmp_path / "catalog.toml"
    catalog_path.write_text(CATALOG)
    probe = parse_output(
        probe_text(
            f_record("/usr/bin/osascript", codesign=APPLE_CODESIGN, ents=ENTITLEMENTS_PLIST),
            f_record("/usr/bin/plain"),
            f_record("/usr/bin/swift", codesign=SHIM_CODESIGN),
            f_record(
                "/opt/vendor/tool",
                codesign="Identifier=com.vendor.tool\nTeamIdentifier=ABCDE12345\n",
            ),
            "W\tosascript(1) - run scripts",
            "P\t-rwxr-xr-x\troot\twheel\t10\trestricted,compressed\t/usr/bin/osascript",
            "D\tsystem\tok\t/Library/Application Support/com.apple.TCC/TCC.db",
            "T\tsystem\tkTCCServiceSystemPolicyAllFiles\t/usr/bin/osascript\t1\t2\tUNUSED",
            "D\tuser\tunreadable\tauthorization denied",
            "X\t/usr/bin/osascript\tcom.apple.test\tuser\t"
            "/System/Library/LaunchAgents/com.apple.test.plist\t"
            + b64('{"com.apple.test":{"HideUntilCheckIn":true}}')
            + "\t"
            + b64("NSXPCListener\nshouldAcceptNewConnection"),
        )
    )
    return build_scan(load_catalog(catalog_path), probe, target="vm", scan_dirs=["/usr/bin"])


@pytest.fixture
def site_dir(scan, tmp_path: Path) -> Path:
    out = tmp_path / "site"
    out.mkdir()
    render_site(scan, out)
    return out


def loaded_data(site_dir: Path) -> dict:
    """Parse assets/data.js the way the page does: one window.LOLBINS assignment."""
    text = (site_dir / "assets" / "data.js").read_text()
    match = re.fullmatch(r"window\.LOLBINS = (.*);\n", text, re.S)
    assert match, "data.js must be a single window.LOLBINS assignment"
    return json.loads(match[1])


def test_site_writes_one_page_and_its_data(site_dir: Path):
    assert (site_dir / "index.html").is_file()
    assert (site_dir / "assets" / "data.js").is_file()
    assert sorted(p.name for p in site_dir.iterdir()) == ["assets", "index.html"]


def test_page_loads_its_data_and_needs_no_other_local_file(site_dir: Path):
    page = (site_dir / "index.html").read_text()
    assert '<script src="assets/data.js"></script>' in page
    local = [
        ref
        for ref in re.findall(r'(?:src|href)="([^"#]+)"', page)
        if not ref.startswith(("https://", "data:", "${"))
    ]
    assert local == ["assets/data.js"]


def test_data_carries_only_usable_apple_lolbins_with_exact_entitlement_values(site_dir: Path):
    data = loaded_data(site_dir)
    files = {f["path"]: f for f in data["inventory"]}
    assert set(files) == {"/usr/bin/osascript"}
    osascript = files["/usr/bin/osascript"]
    assert osascript["entry"] == "osascript"
    assert osascript["owner"] == "root:wheel"
    assert osascript["bsd_flags"] == ["restricted", "compressed"]
    # Arrays and booleans stay as they were signed, not flattened to text.
    assert osascript["entitlements"]["com.apple.private.tcc.allow"] == ["kTCCServiceAll"]
    assert osascript["entitlements"]["com.apple.security.cs.disable-library-validation"] is True
    assert osascript["xpc"][0]["mach_services"][0] == {
        "name": "com.apple.test",
        "properties": {"HideUntilCheckIn": True},
    }
    assert "xpc-server-candidate" in osascript["flags"]


def test_data_explains_each_entitlement_key_the_page_shows(site_dir: Path):
    ents = loaded_data(site_dir)["entitlements"]
    assert ents["com.apple.private.tcc.allow"]["namespace"] == "Private TCC"
    documented = ents["com.apple.security.cs.disable-library-validation"]
    assert documented["documented"] is True
    assert documented["url"].startswith("https://developer.apple.com/")


def test_data_carries_tcc_grants_and_the_labels_for_them(site_dir: Path):
    data = loaded_data(site_dir)
    assert [s["status"] for s in data["tcc"]["sources"]] == ["ok", "unreadable"]
    assert data["tcc"]["grants"][0]["auth"] == "allowed"
    assert data["tcc_labels"]["kTCCServiceSystemPolicyAllFiles"] == "Full Disk Access"
    assert "com.apple.security.cs.disable-library-validation" in data["runtime_weakeners"]
    osascript = next(f for f in data["inventory"] if f["path"] == "/usr/bin/osascript")
    assert [g["service"] for g in osascript["tcc"]] == ["kTCCServiceSystemPolicyAllFiles"]
    assert "tcc-granted" in osascript["flags"]


def test_data_carries_catalog_entries_with_their_examples(site_dir: Path):
    entry = loaded_data(site_dir)["entries"][0]
    assert entry["name"] == "osascript"
    assert entry["status"] == "present"
    assert entry["examples"][0]["command"] == "osascript -e 'do shell script \"id\"'"
    assert entry["techniques"][0]["id"] == "T1059"
    assert entry["xpc_functionality"] == "Runs a test XPC interface."


def test_page_contains_xpc_candidate_panel(site_dir: Path):
    page = (site_dir / "index.html").read_text()
    assert "XPC server candidate" in page
    assert "Known functionality" in page
    assert "No Mach lookup or XPC connection was attempted" in page


def test_render_replaces_pages_left_by_an_earlier_report(scan, tmp_path: Path):
    out = tmp_path / "old"
    (out / "binaries").mkdir(parents=True)
    (out / "assets").mkdir()
    (out / "catalog.html").write_text("old")
    (out / "binaries" / "curl.html").write_text("old")
    (out / "assets" / "site.css").write_text("old")
    render_site(scan, out)
    assert not (out / "catalog.html").exists()
    assert not (out / "binaries").exists()
    assert not (out / "assets" / "site.css").exists()
    assert (out / "index.html").is_file()


def test_site_data_is_json_serialisable_without_coercion(scan):
    assert json.loads(json.dumps(site_data(scan))) == site_data(scan)
