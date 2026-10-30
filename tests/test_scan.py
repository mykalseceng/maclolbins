import json
from pathlib import Path

import pytest
from conftest import APPLE_CODESIGN, ENTITLEMENTS_PLIST, SHIM_CODESIGN, f_record, probe_text

from maclolbins.catalog import load_catalog
from maclolbins.probe import parse_codesign, parse_output
from maclolbins.scan import (
    ScanFileError,
    build_scan,
    file_flags,
    load_scan,
    save_scan,
)

CATALOG = """
[meta]
version = "test"

[techniques]
"T1059" = { name = "Command and Scripting Interpreter", tactics = ["Execution"] }

[[binary]]
name = "shells"
paths = ["/bin/zsh", "/bin/ksh"]
techniques = ["T1059"]
privilege = "user"
abuse = "n"

[[binary]]
name = "swift"
paths = ["/usr/bin/swift"]
techniques = ["T1059"]
privilege = "user"
abuse = "n"

[[binary]]
name = "gone"
paths = ["/usr/bin/gone"]
techniques = ["T1059"]
privilege = "user"
abuse = "n"
"""


@pytest.fixture
def catalog(tmp_path: Path):
    path = tmp_path / "catalog.toml"
    path.write_text(CATALOG)
    return load_catalog(path)


def scan_for(catalog, developer_dir: str):
    probe = parse_output(
        probe_text(
            f_record("/bin/zsh"),
            f_record("/usr/bin/swift", codesign=SHIM_CODESIGN),
            f_record("/usr/libexec/helper", ents=ENTITLEMENTS_PLIST),
            "M\t/bin/ksh",
            "M\t/usr/bin/gone",
            facts={"developer_dir": developer_dir},
        )
    )
    return build_scan(catalog, probe, target="vm", scan_dirs=["/bin"])


def test_entry_status_uses_best_path_and_shim_activity(catalog):
    without_tools = {e["name"]: e for e in scan_for(catalog, "none")["entries"]}
    assert without_tools["shells"]["status"] == "present"
    assert [p["status"] for p in without_tools["shells"]["paths"]] == ["present", "missing"]
    assert without_tools["swift"]["status"] == "inactive-shim"
    assert without_tools["gone"]["status"] == "missing"

    with_tools = {e["name"]: e for e in scan_for(catalog, "/Library/Developer")["entries"]}
    assert with_tools["swift"]["status"] == "present"


def test_inventory_links_catalog_entries_and_entitlements(catalog):
    inventory = {i["file"]["path"]: i for i in scan_for(catalog, "none")["inventory"]}
    assert inventory["/bin/zsh"]["catalog_entry"] == "shells"
    helper = inventory["/usr/libexec/helper"]
    assert helper["catalog_entry"] is None
    assert "com.apple.private.tcc.allow" in helper["file"]["entitlements"]


def record(perms: str | None, codesign: str = APPLE_CODESIGN, *, is_script: bool = False):
    probe = parse_output(probe_text(f_record("/x")))
    rec = probe["files"]["/x"]
    rec["perms"] = perms
    rec["is_script"] = is_script
    rec["signing"] = parse_codesign(codesign)
    # Files in the scanned system directories carry SIP's restricted flag.
    rec["bsd_flags"] = ["restricted", "compressed"]
    return rec


@pytest.mark.parametrize(
    ("perms", "codesign", "is_script", "expected"),
    [
        ("-rwxr-xr-x", APPLE_CODESIGN, False, []),
        ("-rwsr-xr-x", APPLE_CODESIGN, False, ["setuid"]),
        ("-rwxr-sr-x", APPLE_CODESIGN, False, ["setgid"]),
        ("-rwxrwxrwx", APPLE_CODESIGN, False, ["world-writable"]),
        ("-rwxr-xr-x", "x: code object is not signed at all", False, ["unsigned"]),
        ("-rwxr-xr-x", "x: code object is not signed at all", True, ["script"]),
        ("-rwxr-xr-x", "Identifier=a\nSignature=adhoc\n", False, ["adhoc-signed"]),
        ("-r-s--x--x", "x: Permission denied", False, ["setuid", "unreadable"]),
        ("-rwxr-xr-x", "Identifier=a\nTeamIdentifier=ABCDE12345\n", False, ["third-party"]),
    ],
)
def test_file_flags(perms, codesign, is_script, expected):
    assert file_flags(record(perms, codesign, is_script=is_script)) == expected


def test_file_flags_sip_unprotected_needs_a_stat_and_no_restricted_flag():
    unprotected = record("-rwxr-xr-x")
    unprotected["bsd_flags"] = []
    assert file_flags(unprotected) == ["sip-unprotected"]
    no_stat = record(None)
    no_stat["bsd_flags"] = []
    assert "sip-unprotected" not in file_flags(no_stat)


def test_file_flags_launchd_mach_service_as_xpc_candidate():
    rec = record("-rwxr-xr-x")
    rec["xpc"] = [
        {
            "label": "com.apple.helper",
            "run_context": "system",
            "plist_path": "/System/Library/LaunchDaemons/com.apple.helper.plist",
            "mach_services": [{"name": "com.apple.helper", "properties": True}],
            "listener_markers": ["NSXPCListener"],
        }
    ]
    assert file_flags(rec) == ["xpc-server-candidate"]


@pytest.mark.parametrize(
    ("entitlements", "expected"),
    [
        ({"com.apple.security.cs.disable-library-validation": True}, ["weakened-runtime"]),
        ({"com.apple.security.get-task-allow": True}, ["weakened-runtime"]),
        ({"com.apple.security.cs.allow-dyld-environment-variables": False}, []),
        ({"com.apple.private.tcc.allow": ["kTCCServiceAll"]}, ["tcc-entitled"]),
        ({"com.apple.private.tcc.manager": True}, ["tcc-entitled"]),
        ({"com.apple.security.network.client": True}, []),
    ],
)
def test_file_flags_from_entitlements(entitlements, expected):
    rec = record("-rwxr-xr-x")
    rec["entitlements"] = entitlements
    assert file_flags(rec) == expected


def test_inventory_matches_tcc_grants_by_path_and_signing_identifier(catalog):
    probe = parse_output(
        probe_text(
            f_record("/bin/zsh", codesign="Identifier=com.apple.zsh\n"),
            f_record("/usr/bin/curl"),
            f_record("/usr/libexec/helper", codesign="Identifier=com.apple.helper\n"),
            "D\tsystem\tok\t/db",
            "T\tsystem\tkTCCServiceSystemPolicyAllFiles\t/bin/zsh\t1\t2\tUNUSED",
            "T\tuser\tkTCCServiceAppleEvents\tcom.apple.curl\t0\t2\tcom.apple.finder",
            "T\tsystem\tkTCCServiceSystemPolicyAllFiles\t/usr/libexec/helper\t1\t0\tUNUSED",
            "T\tsystem\tkTCCServiceCamera\t/somewhere/else\t1\t2\tUNUSED",
        )
    )
    scan = build_scan(catalog, probe, target="vm", scan_dirs=["/bin"])
    inventory = {i["file"]["path"]: i for i in scan["inventory"]}
    assert [g["service"] for g in inventory["/bin/zsh"]["tcc"]] == [
        "kTCCServiceSystemPolicyAllFiles"
    ]
    assert "tcc-granted" in inventory["/bin/zsh"]["flags"]
    assert [g["target"] for g in inventory["/usr/bin/curl"]["tcc"]] == ["com.apple.finder"]
    helper = inventory["/usr/libexec/helper"]
    assert [g["auth"] for g in helper["tcc"]] == ["denied"]
    assert "tcc-granted" not in helper["flags"]
    assert scan["tcc"]["sources"][0]["status"] == "ok"
    assert len(scan["tcc"]["grants"]) == 4


def test_denied_grant_alone_does_not_flag_tcc_granted(catalog):
    probe = parse_output(
        probe_text(
            f_record("/bin/zsh", codesign="Identifier=com.example.zsh\n"),
            "T\tsystem\tkTCCServiceSystemPolicyAllFiles\t/bin/zsh\t1\t0\tUNUSED",
        )
    )
    item = build_scan(catalog, probe, target="vm", scan_dirs=["/bin"])["inventory"][0]
    assert item["tcc"][0]["auth"] == "denied"
    assert "tcc-granted" not in item["flags"]


def test_scan_round_trips_through_json(catalog, tmp_path):
    scan = scan_for(catalog, "none")
    path = tmp_path / "scan.json"
    save_scan(scan, path)
    assert load_scan(path) == scan


def test_load_scan_migrates_schema_four_without_xpc_evidence(catalog, tmp_path):
    scan = scan_for(catalog, "none")
    scan["schema"] = 4
    for item in scan["inventory"]:
        item["file"].pop("xpc")
    path = tmp_path / "scan-v4.json"
    path.write_text(json.dumps(scan))

    migrated = load_scan(path)

    assert migrated["schema"] == 5
    assert all(item["file"]["xpc"] == [] for item in migrated["inventory"])


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "cannot read scan file"),
        (json.dumps({"schema": 99}), "found 99"),
        (json.dumps([1, 2]), "found 'list'"),
    ],
)
def test_load_scan_rejects_bad_files(tmp_path, content, message):
    path = tmp_path / "scan.json"
    path.write_text(content)
    with pytest.raises(ScanFileError, match=message):
        load_scan(path)


def test_load_scan_missing_file(tmp_path):
    with pytest.raises(ScanFileError, match="cannot read scan file"):
        load_scan(tmp_path / "absent.json")


def test_entry_description_comes_from_first_path_with_a_summary(catalog):
    probe = parse_output(
        probe_text(
            f_record("/bin/zsh"),
            f_record("/bin/ksh"),
            "W\tksh(1) - KornShell",
            facts={"developer_dir": "none"},
        )
    )
    entries = {e["name"]: e for e in build_scan(catalog, probe, "vm", ["/bin"])["entries"]}
    assert entries["shells"]["description"] == "KornShell"
    assert entries["shells"]["abuse"] == "n"
    assert entries["gone"]["description"] is None
