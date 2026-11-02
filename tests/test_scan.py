import json
from pathlib import Path

import pytest
from conftest import (
    APPLE_CODESIGN,
    ENTITLEMENTS_PLIST,
    SHIM_CODESIGN,
    c_record,
    f_record,
    probe_text,
)

from maclolbins.catalog import load_catalog
from maclolbins.probe import parse_codesign, parse_output
from maclolbins.scan import (
    SCHEMA_VERSION,
    ScanFileError,
    build_scan,
    file_flags,
    load_scan,
    rejoin_catalog,
    save_scan,
)

CATALOG = """
[meta]
version = "test"

[techniques]
"T1059" = { name = "Command and Scripting Interpreter", tactics = ["Execution"] }
"T1105" = { name = "Ingress Tool Transfer", tactics = ["Command and Control"] }

[[capability]]
id = "fetches-urls"
title = "Makes HTTP requests"
summary = "Uses libcurl."
techniques = ["T1105"]
symbols = ["_curl_easy_perform"]
libraries = ["libcurl"]

[[capability]]
id = "runs-programs"
title = "Starts other programs"
summary = "Spawns processes."
techniques = ["T1059"]
symbols = ["_posix_spawn"]

[[note]]
name = "shells"
paths = ["/bin/zsh", "/bin/ksh"]
techniques = ["T1059"]
privilege = "user"
abuse = "n"
"""


def load(tmp_path: Path, text: str):
    path = tmp_path / "catalog.toml"
    path.write_text(text)
    return load_catalog(path)


@pytest.fixture
def catalog(tmp_path: Path):
    return load(tmp_path, CATALOG)


def scan_for(catalog):
    probe = parse_output(
        probe_text(
            f_record("/bin/zsh"),
            c_record("/bin/zsh", "_posix_spawn", "/usr/lib/libSystem.B.dylib"),
            f_record("/usr/bin/curl"),
            c_record("/usr/bin/curl", "_curl_easy_perform", "/usr/lib/libcurl.4.dylib"),
            f_record("/usr/bin/swift", codesign=SHIM_CODESIGN),
            f_record("/usr/libexec/helper", ents=ENTITLEMENTS_PLIST),
            facts={"developer_dir": "none", "path_dirs": "/usr/bin:/bin"},
        )
    )
    return build_scan(catalog, probe, target="vm")


def test_scan_dirs_come_from_the_targets_path(catalog):
    assert scan_for(catalog)["scan_dirs"] == ["/usr/bin", "/bin"]


def test_inventory_matches_capabilities_with_their_evidence(catalog):
    inventory = {i["file"]["path"]: i for i in scan_for(catalog)["inventory"]}
    assert inventory["/usr/bin/curl"]["capabilities"] == [
        {"id": "fetches-urls", "evidence": ["/usr/lib/libcurl.4.dylib", "_curl_easy_perform"]}
    ]
    assert inventory["/bin/zsh"]["capabilities"] == [
        {"id": "runs-programs", "evidence": ["_posix_spawn"]}
    ]
    assert inventory["/usr/bin/swift"]["capabilities"] == []


def test_inventory_links_notes_by_path(catalog):
    inventory = {i["file"]["path"]: i for i in scan_for(catalog)["inventory"]}
    assert inventory["/bin/zsh"]["note"] == "shells"
    helper = inventory["/usr/libexec/helper"]
    assert helper["note"] is None
    assert "com.apple.private.tcc.allow" in helper["file"]["entitlements"]


def test_scan_copies_rule_and_note_definitions(catalog):
    scan = scan_for(catalog)
    fetches = next(c for c in scan["capabilities"] if c["id"] == "fetches-urls")
    assert fetches["techniques"] == [{"id": "T1105", "name": "Ingress Tool Transfer"}]
    assert fetches["tactics"] == ["Command and Control"]
    (note,) = scan["notes"]
    assert (note["name"], note["paths"], note["tactics"]) == (
        "shells",
        ["/bin/zsh", "/bin/ksh"],
        ["Execution"],
    )


def test_rejoin_catalog_applies_edited_rules_to_a_saved_scan(catalog, tmp_path):
    scan = scan_for(catalog)
    edited = load(
        tmp_path, CATALOG.replace('symbols = ["_posix_spawn"]', 'symbols = ["_curl_easy_perform"]')
    )
    rebuilt = {i["file"]["path"]: i for i in rejoin_catalog(scan, edited)["inventory"]}
    assert [c["id"] for c in rebuilt["/usr/bin/curl"]["capabilities"]] == [
        "fetches-urls",
        "runs-programs",
    ]
    assert rebuilt["/bin/zsh"]["capabilities"] == []


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
        (
            {"com.apple.private.tcc.allow": ["kTCCServiceAll"]},
            ["private-entitled", "tcc-entitled"],
        ),
        ({"com.apple.private.tcc.manager": True}, ["private-entitled", "tcc-entitled"]),
        ({"com.apple.private.alf": True}, ["private-entitled"]),
        ({"com.apple.rootless.install": True}, ["private-entitled"]),
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
    scan = build_scan(catalog, probe, target="vm")
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
    item = build_scan(catalog, probe, target="vm")["inventory"][0]
    assert item["tcc"][0]["auth"] == "denied"
    assert "tcc-granted" not in item["flags"]


def test_scan_round_trips_through_json(catalog, tmp_path):
    scan = scan_for(catalog)
    path = tmp_path / "scan.json"
    save_scan(scan, path)
    assert load_scan(path) == scan


def test_load_scan_rejects_the_previous_schema(catalog, tmp_path):
    scan = scan_for(catalog)
    scan["schema"] = SCHEMA_VERSION - 1
    path = tmp_path / "scan-old.json"
    path.write_text(json.dumps(scan))
    with pytest.raises(ScanFileError, match="re-run the scan"):
        load_scan(path)


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
