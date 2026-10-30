import os
import sys
from pathlib import Path

import pytest
from conftest import ENTITLEMENTS_PLIST, SHIM_CODESIGN, b64, f_record, probe_text

from maclolbins.probe import (
    HEREDOC_DELIMITER,
    ProbeError,
    build_script,
    parse_codesign,
    parse_output,
    parse_whatis,
    run_probe,
)

LOCAL_BASH = ["/bin/bash", "-s"]


def test_parse_codesign_apple_platform_binary():
    signing = parse_codesign(
        "Identifier=com.apple.curl\nFormat=Mach-O\n"
        "CodeDirectory v=20400 size=1 flags=0x10000(runtime) hashes=1\n"
        "Platform identifier=26\nAuthority=macOS Software Signing\nAuthority=Apple Root CA\n"
        "TeamIdentifier=not set\n"
    )
    assert signing["state"] == "signed"
    assert signing["identifier"] == "com.apple.curl"
    assert signing["platform_binary"] is True
    assert signing["team_id"] is None
    assert signing["flags"] == ["runtime"]
    assert signing["authorities"] == ["macOS Software Signing", "Apple Root CA"]


def test_parse_codesign_adhoc_with_team_and_no_flags():
    signing = parse_codesign(
        "Identifier=a.out\nCodeDirectory v=20400 flags=0x2(adhoc) hashes=1\n"
        "Signature=adhoc\nTeamIdentifier=ABCDE12345\n"
    )
    assert signing["state"] == "adhoc"
    assert signing["team_id"] == "ABCDE12345"
    assert signing["platform_binary"] is False


@pytest.mark.parametrize(
    ("text", "state", "error"),
    [
        ("/opt/x: code object is not signed at all\n", "unsigned", "not signed at all"),
        ("/usr/bin/sudo: Permission denied\n", "unreadable", "Permission denied"),
        ("", "unreadable", "no output"),
    ],
)
def test_parse_codesign_failures(text, state, error):
    signing = parse_codesign(text)
    assert signing["state"] == state
    assert error in (signing["error"] or "")
    assert signing["identifier"] is None


def test_parse_output_joins_stats_hashes_and_entitlements():
    output = parse_output(
        probe_text(
            "P\t-rwsr-xr-x\troot\twheel\t1234\trestricted,compressed\t/bin/ps",
            "S\tabc123\t/bin/ps",
            f_record("/bin/ps", ents=ENTITLEMENTS_PLIST, link="../ps"),
            f_record("/usr/bin/swift", codesign=SHIM_CODESIGN),
            "M\t/usr/bin/gone",
        )
    )
    ps = output["files"]["/bin/ps"]
    assert (ps["perms"], ps["owner"], ps["size"], ps["sha256"]) == (
        "-rwsr-xr-x",
        "root",
        1234,
        "abc123",
    )
    assert ps["bsd_flags"] == ["restricted", "compressed"]
    assert ps["link_target"] == "../ps"
    assert ps["entitlements"]["com.apple.private.tcc.allow"] == ["kTCCServiceAll"]
    assert output["files"]["/usr/bin/swift"]["is_dev_shim"] is True
    assert output["files"]["/usr/bin/swift"]["sha256"] is None
    assert output["files"]["/usr/bin/swift"]["bsd_flags"] == []
    assert output["missing"] == ["/usr/bin/gone"]
    assert output["facts"]["developer_dir"] == "none"


def test_parse_output_reads_tcc_sources_and_grants():
    output = parse_output(
        probe_text(
            "P\t-rwxr-xr-x\troot\twheel\t10\t-\t/opt/tool",
            "D\tsystem\tok\t/Library/Application Support/com.apple.TCC/TCC.db",
            "T\tsystem\tkTCCServiceSystemPolicyAllFiles\t/opt/tool\t1\t2\tUNUSED",
            "D\tuser\tunreadable\tError: authorization denied",
            "T\tuser\tkTCCServiceAppleEvents\tcom.apple.Terminal\t0\t0\tcom.apple.finder",
            "T\tuser\tkTCCServiceCamera\tcom.example.app\t0\t5\t",
            "T\tuser\tkTCCServiceMicrophone\tcom.example.app\t0\t1\t",
            f_record("/opt/tool"),
        )
    )
    assert output["files"]["/opt/tool"]["bsd_flags"] == []
    sources = {s["scope"]: s for s in output["tcc"]["sources"]}
    assert sources["system"]["status"] == "ok"
    assert sources["user"] == {
        "scope": "user",
        "status": "unreadable",
        "detail": "Error: authorization denied",
    }
    fda, automation, camera, microphone = output["tcc"]["grants"]
    assert (fda["client_type"], fda["auth"], fda["target"]) == ("path", "allowed", None)
    assert (automation["client_type"], automation["auth"]) == ("bundle", "denied")
    assert automation["target"] == "com.apple.finder"
    assert (fda["auth_value"], automation["auth_value"]) == (2, 0)
    # Codes outside 0-3 must not be mistaken for "unknown" (1); the raw code is kept.
    assert (camera["auth"], camera["auth_value"], camera["target"]) == ("other", 5, None)
    assert (microphone["auth"], microphone["auth_value"]) == ("unknown", 1)


def test_parse_output_without_tcc_records_has_empty_snapshot():
    output = parse_output(probe_text(f_record("/x")))
    assert output["tcc"] == {"sources": [], "grants": []}


def test_parse_output_attaches_launchd_xpc_candidate_evidence():
    mach_services = b64(
        '{"com.apple.helper":{"HideUntilCheckIn":true},"com.apple.helper.events":true}'
    )
    listener_markers = b64("NSXPCListener\nshouldAcceptNewConnection")
    output = parse_output(
        probe_text(
            f_record("/usr/libexec/helper"),
            "X\t/usr/libexec/helper\tcom.apple.helper\tsystem\t"
            f"/System/Library/LaunchDaemons/com.apple.helper.plist\t"
            f"{mach_services}\t{listener_markers}",
        )
    )
    (registration,) = output["files"]["/usr/libexec/helper"]["xpc"]
    assert registration["label"] == "com.apple.helper"
    assert registration["run_context"] == "system"
    assert registration["listener_markers"] == ["NSXPCListener", "shouldAcceptNewConnection"]
    assert registration["mach_services"] == [
        {
            "name": "com.apple.helper",
            "properties": {"HideUntilCheckIn": True},
        },
        {"name": "com.apple.helper.events", "properties": True},
    ]


def test_parse_output_converts_plist_data_to_json_safe_values():
    plist = (
        '<?xml version="1.0"?><plist version="1.0"><dict>'
        "<key>blob</key><data>AAE=</data><key>when</key><date>2026-01-01T00:00:00Z</date>"
        "</dict></plist>"
    )
    record = parse_output(probe_text(f_record("/x", ents=plist)))["files"]["/x"]
    assert record["entitlements"]["blob"] == "base64:AAE="
    assert record["entitlements"]["when"].startswith("2026-01-01")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("H\tonly-key\n", "expected 2"),
        ("Z\twhat\n", "unknown record"),
        ("H\tk\tv\n", "truncated"),
        ("F\t/x\t\t0\tnot-base64!\t\nE\tok\n", "invalid base64"),
        (f"F\t/x\t\t0\t\t{b64('<plist><array/></plist>')}\nE\tok\n", "not a dictionary"),
        (f"F\t/x\t\t0\t\t{b64('garbage')}\nE\tok\n", "not a valid plist"),
        ("P\t-rwxr-xr-x\troot\twheel\t1\t/x\nE\tok\n", "expected 6"),
        ("D\tother\tok\t/db\nE\tok\n", "unknown TCC database"),
        ("D\tsystem\tbroken\t/db\nE\tok\n", "unknown TCC database"),
        ("T\tsystem\tsvc\tclient\t9\t2\t\nE\tok\n", "unknown TCC grant"),
        ("T\tsystem\tsvc\tclient\t1\nE\tok\n", "expected 6"),
        ("T\tsystem\tsvc\tclient\t1\tallowed\t\nE\tok\n", "unknown TCC grant"),
        (
            "X\t/x\tlabel\tother\t/p\t"
            + b64('{"svc":true}')
            + "\t"
            + b64("NSXPCListener")
            + "\nE\tok\n",
            "unknown XPC run context",
        ),
        (
            "X\t/x\tlabel\tsystem\t/p\t" + b64("{}") + "\t" + b64("NSXPCListener") + "\nE\tok\n",
            "non-empty dictionary",
        ),
        (
            "X\t/x\tlabel\tsystem\t/p\t"
            + b64('{"svc":true}')
            + "\t"
            + b64("made-up-marker")
            + "\nE\tok\n",
            "unknown XPC listener markers",
        ),
    ],
)
def test_parse_output_rejects_malformed_input(text, message):
    with pytest.raises(ProbeError, match=message):
        parse_output(text)


def test_build_script_rejects_values_that_would_break_the_heredoc():
    with pytest.raises(ProbeError, match="cannot be passed"):
        build_script(["/bin"], ["/a\nb"])
    with pytest.raises(ProbeError, match="cannot be passed"):
        build_script(["/bin"], [HEREDOC_DELIMITER])


def test_run_probe_reports_missing_command():
    with pytest.raises(ProbeError, match="not found on PATH"):
        run_probe(["/nonexistent/prlctl"], ["/bin"], [], timeout=5)


def test_run_probe_reports_failure_with_stderr():
    with pytest.raises(ProbeError, match=r"exit code 3.*boom"):
        run_probe(["/bin/sh", "-c", "echo boom >&2; exit 3"], ["/bin"], [], timeout=5)


def test_run_probe_reports_timeout():
    with pytest.raises(ProbeError, match="did not finish"):
        run_probe(["/bin/sh", "-c", "exec /bin/sleep 5"], ["/bin"], [], timeout=0.2)


@pytest.mark.skipif(sys.platform != "darwin", reason="probe.sh relies on macOS tools")
def test_probe_script_end_to_end_on_this_mac(tmp_path: Path):
    scan_dir = tmp_path / "bin"
    scan_dir.mkdir()
    script = scan_dir / "hello.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o755)
    (scan_dir / "not-executable").write_text("data")
    (scan_dir / "link").symlink_to("hello.sh")
    space_dir = tmp_path / "with space"
    space_dir.mkdir()
    spaced = space_dir / "tool"
    spaced.write_text("#!/bin/sh\n")
    # A setuid file owned by the test user in a private temp dir, so the flag can be observed.
    os.chmod(spaced, 0o4755)  # noqa: S103

    output = run_probe(
        LOCAL_BASH, [str(scan_dir)], [str(spaced), str(tmp_path / "missing")], timeout=60
    )

    assert set(output["files"]) == {str(script), str(scan_dir / "link"), str(spaced)}
    hello = output["files"][str(script)]
    assert hello["is_script"] is True
    assert hello["signing"]["state"] == "unsigned"
    assert hello["sha256"] is not None
    assert len(hello["sha256"]) == 64
    assert output["files"][str(scan_dir / "link")]["link_target"] == "hello.sh"
    assert output["files"][str(spaced)]["perms"] == "-rwsr-xr-x"
    assert hello["bsd_flags"] == []
    assert output["missing"] == [str(tmp_path / "missing")]
    assert {source["scope"] for source in output["tcc"]["sources"]} == {"system", "user"}
    assert output["facts"]["user"]
    assert "collected_at" in output["facts"]


@pytest.mark.skipif(sys.platform != "darwin", reason="probe.sh relies on macOS tools")
def test_probe_script_reads_real_entitlements():
    output = run_probe(LOCAL_BASH, [], ["/usr/bin/tccutil"], timeout=60)
    record = output["files"]["/usr/bin/tccutil"]
    assert record["signing"]["platform_binary"] is True
    assert "restricted" in record["bsd_flags"]
    assert any(key.startswith("com.apple.private.tcc.") for key in record["entitlements"])


def test_parse_whatis_prefers_most_specific_page():
    summaries = parse_whatis(
        [
            "builtin(1), !(1), log(1), login(1) - shell built-in commands",
            "log(1)                   - Access system wide log messages",
            "curl(1)                  - transfer a URL",
            "curl-config(1)           - Get information about a libcurl installation",
            "tool(3)                  - library page",
            "tool(8)                  - admin page",
            "malformed line without separator",
        ]
    )
    assert summaries["log"] == "Access system wide log messages"
    assert summaries["login"] == "shell built-in commands"
    assert summaries["curl"] == "transfer a URL"
    assert summaries["tool"] == "admin page"
    assert "malformed" not in " ".join(summaries)


def test_parse_output_attaches_summary_by_basename():
    output = parse_output(
        probe_text(
            f_record("/usr/bin/curl"), f_record("/usr/bin/nodoc"), "W\tcurl(1) - transfer a URL"
        )
    )
    assert output["files"]["/usr/bin/curl"]["summary"] == "transfer a URL"
    assert output["files"]["/usr/bin/nodoc"]["summary"] is None


@pytest.mark.skipif(sys.platform != "darwin", reason="probe.sh relies on macOS tools")
def test_probe_script_collects_man_page_summaries():
    output = run_probe(LOCAL_BASH, [], ["/usr/bin/tccutil"], timeout=120)
    summary = output["files"]["/usr/bin/tccutil"]["summary"]
    assert summary is not None
    assert "privacy" in summary.lower()
