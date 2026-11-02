from pathlib import Path
from typing import Any

import anyio
import pytest
from conftest import ENTITLEMENTS_PLIST, b64, c_record, f_record, probe_text
from mcp import Client
from parity import mismatches, report_data

from maclolbins import cli
from maclolbins import server as server_module
from maclolbins.catalog import load_catalog
from maclolbins.probe import ProbeError, parse_output
from maclolbins.reports import write_report
from maclolbins.scan import build_scan
from maclolbins.server import build_server

TCC_GRANT = "T\tsystem\tkTCCServiceSystemPolicyAllFiles\t/usr/bin/osascript\t1\t2\tUNUSED"
SIP = "-rwxr-xr-x\troot\twheel\t100\trestricted"
LIBRARY_VALIDATION_KEPT = (
    '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
    "<key>com.apple.security.cs.disable-library-validation</key><false/>"
    "</dict></plist>"
)
PROBE = probe_text(
    f_record("/usr/bin/curl", ents=LIBRARY_VALIDATION_KEPT),
    c_record("/usr/bin/curl", "_curl_easy_perform", "/usr/lib/libcurl.4.dylib"),
    f_record("/usr/bin/osascript", ents=ENTITLEMENTS_PLIST),
    c_record("/usr/bin/osascript", "_AESendMessage"),
    f_record("/usr/bin/killall"),
    c_record("/usr/bin/killall", "_proc_listpids"),
    f_record("/usr/bin/pkill"),
    c_record("/usr/bin/pkill", "_proc_listpids"),
    f_record("/usr/sbin/killall"),
    c_record("/usr/sbin/killall", "_proc_listpids"),
    f_record("/usr/bin/no-evidence"),
    f"P\t{SIP}\t/usr/bin/curl",
    "W\tcurl(1) - transfer a URL",
    "W\tkillall(1) - kill processes by name",
    "D\tsystem\tok\t/Library/Application Support/com.apple.TCC/TCC.db",
    TCC_GRANT,
    "\t".join(
        [
            "X",
            "/usr/bin/osascript",
            "com.apple.osascript.helper",
            "user",
            "/System/Library/LaunchAgents/com.apple.osascript.helper.plist",
            b64('{"com.apple.osascript.helper": true}'),
            b64("xpc_main\n"),
        ]
    ),
    facts={
        "collected_at": "2026-10-26T17:00:00Z",
        "developer_dir": "none",
        "path_dirs": "/usr/bin:/usr/sbin",
    },
)


def call(server, tool: str, arguments: dict[str, Any] | None = None):
    async def run():
        async with Client(server) as client:
            return await client.call_tool(tool, arguments or {})

    return anyio.run(run)


@pytest.fixture
def reports(tmp_path: Path) -> Path:
    catalog = load_catalog()
    scan = build_scan(catalog, parse_output(PROBE), "macOS")
    write_report(scan, tmp_path)
    return tmp_path


@pytest.fixture
def server(reports: Path):
    return build_server(reports, load_catalog())


SCAN_ID = "macOS-20261026T170000Z"


def test_answers_match_the_rendered_report(server, reports: Path):
    assert anyio.run(mismatches, server, SCAN_ID, reports / SCAN_ID) == []
    assert len(report_data(reports / SCAN_ID)["inventory"]) == 6


def test_speaks_protocol_2026_07_28(server):
    async def run():
        async with Client(server) as client:
            tools = await client.list_tools()
            return client.session.protocol_version, tools

    protocol, tools = anyio.run(run)
    assert protocol == "2026-07-28"
    assert tools.ttl_ms == 3_600_000
    by_name = {tool.name: tool for tool in tools.tools}
    assert set(by_name) == {
        "discover_targets",
        "scan_target",
        "get_probe_script",
        "import_probe_output",
        "list_scans",
        "render_report",
        "list_lolbins",
        "get_lolbin",
        "explain_entitlement",
    }
    assert all(tool.output_schema for tool in tools.tools)
    assert by_name["get_lolbin"].annotations.read_only_hint is True
    assert by_name["scan_target"].annotations.open_world_hint is True


def test_get_lolbin_explains_entitlements_and_grants(server):
    detail = call(server, "get_lolbin", {"scan_id": SCAN_ID, "binary": "osascript"})
    content = detail.structured_content
    entitlements = {e["key"]: e for e in content["entitlements"]}
    tcc = entitlements["com.apple.private.tcc.allow"]
    assert tcc["tcc_services"] == [{"service": "kTCCServiceAll", "label": "Every TCC service"}]
    assert tcc["documented"] is False
    assert tcc["apple_docs_url"] is None
    weakener = entitlements["com.apple.security.cs.disable-library-validation"]
    assert weakener["value"] is True
    assert weakener["weakens_runtime"].startswith("Loads libraries")
    assert weakener["apple_docs_url"].startswith("https://developer.apple.com/")
    assert content["tcc_grants"][0]["service_label"] == "Full Disk Access"
    assert "tcc-granted" in content["flags"]


def test_get_lolbin_shows_capabilities_evidence_and_note(server):
    content = call(server, "get_lolbin", {"scan_id": SCAN_ID, "binary": "curl"}).structured_content
    (cap,) = content["capabilities"]
    assert cap["id"] == "fetches-urls"
    assert cap["evidence"] == ["/usr/lib/libcurl.4.dylib", "_curl_easy_perform"]
    assert cap["techniques"][0]["url"] == "https://attack.mitre.org/techniques/T1105/"
    assert content["abuse"]
    assert content["examples"]
    assert content["score"] == 1


def test_get_lolbin_without_a_note_has_no_abuse_text(server):
    content = call(
        server, "get_lolbin", {"scan_id": SCAN_ID, "binary": "/usr/sbin/killall"}
    ).structured_content
    assert content["abuse"] is None
    assert content["examples"] == []
    assert [c["id"] for c in content["capabilities"]] == ["lists-processes"]


def test_get_lolbin_by_ambiguous_name_lists_paths(server):
    result = call(server, "get_lolbin", {"scan_id": SCAN_ID, "binary": "killall"})
    assert result.is_error
    assert "/usr/bin/killall, /usr/sbin/killall" in result.content[0].text


def test_binary_without_evidence_is_listed_last_with_score_zero(server):
    rows = call(server, "list_lolbins", {"scan_id": SCAN_ID}).structured_content["result"]
    assert (rows[-1]["path"], rows[-1]["score"], rows[-1]["capabilities"]) == (
        "/usr/bin/no-evidence",
        0,
        [],
    )


def test_get_lolbin_rejects_binaries_outside_the_report(server):
    result = call(server, "get_lolbin", {"scan_id": SCAN_ID, "binary": "/usr/bin/nothing-here"})
    assert result.is_error
    assert "list_lolbins" in result.content[0].text


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        (
            {},
            [
                "/usr/bin/curl",
                "/usr/bin/killall",
                "/usr/bin/no-evidence",
                "/usr/bin/osascript",
                "/usr/bin/pkill",
                "/usr/sbin/killall",
            ],
        ),
        ({"query": "TRANSFER A url"}, ["/usr/bin/curl"]),
        (
            {"capability": "lists-processes"},
            ["/usr/bin/killall", "/usr/bin/pkill", "/usr/sbin/killall"],
        ),
        ({"query": "lists PROCESSES"}, ["/usr/bin/killall", "/usr/bin/pkill", "/usr/sbin/killall"]),
        ({"tactic": "execution"}, ["/usr/bin/osascript"]),
        ({"flag": "weakened-runtime"}, ["/usr/bin/osascript"]),
        ({"entitlement": "com.apple.private.tcc."}, ["/usr/bin/osascript"]),
        ({"query": "transfer", "flag": "weakened-runtime"}, []),
    ],
)
def test_list_lolbins_filters(server, filters, expected):
    result = call(server, "list_lolbins", {"scan_id": SCAN_ID, **filters})
    assert sorted(row["path"] for row in result.structured_content["result"]) == expected


def test_list_lolbins_puts_the_strongest_evidence_first(server):
    rows = call(server, "list_lolbins", {"scan_id": SCAN_ID}).structured_content["result"]
    assert rows[0]["path"] == "/usr/bin/osascript"
    assert [row["score"] for row in rows] == sorted((row["score"] for row in rows), reverse=True)


@pytest.mark.parametrize("scan_id", ["../etc", "macOS-19990101T000000Z", ".hidden"])
def test_unknown_or_unsafe_scan_ids_are_errors(server, scan_id):
    result = call(server, "list_lolbins", {"scan_id": scan_id})
    assert result.is_error


def test_list_scans_reports_unreadable_scans(server, reports: Path):
    (reports / "broken-1").mkdir()
    (reports / "broken-1" / "scan.json").write_text("{}")
    listing = call(server, "list_scans").structured_content
    assert [s["scan_id"] for s in listing["scans"]] == [SCAN_ID]
    summary = listing["scans"][0]
    assert summary["lolbins_in_report"] == 6
    assert summary["inventoried"] == 6
    assert summary["path_dirs"] == ["/usr/bin", "/usr/sbin"]
    assert summary["report"] == str(reports / SCAN_ID / "index.html")
    assert listing["unreadable"][0]["scan_id"] == "broken-1"


def test_scan_target_pipes_probe_into_command(tmp_path: Path, monkeypatch):
    seen = {}

    def fake_run_probe(command, symbols, timeout):
        seen.update(command=command, timeout=timeout, asks_for_curl="_curl_easy_perform" in symbols)
        return parse_output(PROBE)

    monkeypatch.setattr(server_module, "run_probe", fake_run_probe)
    server = build_server(tmp_path, load_catalog())
    command = ["ssh", "-o", "BatchMode=yes", "mac", "/bin/bash", "-s"]
    result = call(
        server, "scan_target", {"command": command, "target": "mac", "timeout_seconds": 60}
    )
    assert seen == {"command": command, "timeout": 60, "asks_for_curl": True}
    scan_id = result.structured_content["scan_id"]
    assert scan_id == "mac-20261026T170000Z"
    assert (tmp_path / scan_id / "index.html").is_file()
    assert anyio.run(mismatches, server, scan_id, tmp_path / scan_id) == []


def test_scan_target_reports_probe_failure(tmp_path: Path, monkeypatch):
    def failing_run_probe(*_args):
        raise ProbeError("cannot run 'prlctl': not found on PATH")

    monkeypatch.setattr(server_module, "run_probe", failing_run_probe)
    result = call(
        build_server(tmp_path, load_catalog()),
        "scan_target",
        {"command": ["prlctl", "exec", "vm", "/bin/bash", "-s"], "target": "vm"},
    )
    assert result.is_error
    assert "scan of vm failed: cannot run 'prlctl'" in result.content[0].text


def test_scan_target_rejects_empty_command(server):
    assert call(server, "scan_target", {"command": [], "target": "x"}).is_error


def test_probe_script_round_trips_through_import(tmp_path: Path):
    server = build_server(tmp_path, load_catalog())
    script = call(server, "get_probe_script").structured_content
    assert "LOLBINS_PATH_SOURCES=" in script["script"]
    assert "/etc/paths.d" in script["script"]
    assert "_curl_easy_perform" in script["script"]
    output = tmp_path / "probe.out"
    output.write_text(PROBE)
    result = call(server, "import_probe_output", {"output_path": str(output), "target": "fusion"})
    scan_id = result.structured_content["scan_id"]
    assert anyio.run(mismatches, server, scan_id, tmp_path / scan_id) == []


@pytest.mark.parametrize(
    ("content", "message"),
    [(None, "cannot read probe output"), ("H\tk\tv\n", "is not complete probe output")],
)
def test_import_rejects_missing_or_truncated_output(tmp_path: Path, content, message):
    output = tmp_path / "probe.out"
    if content is not None:
        output.write_text(content)
    server = build_server(tmp_path, load_catalog())
    result = call(server, "import_probe_output", {"output_path": str(output), "target": "x"})
    assert result.is_error
    assert message in result.content[0].text


def test_explain_entitlement_links_apple_docs(server):
    documented = call(
        server, "explain_entitlement", {"key": "com.apple.security.cs.disable-library-validation"}
    ).structured_content
    assert documented["documented"] is True
    assert documented["apple_docs_url"].startswith("https://developer.apple.com/documentation/")
    undocumented = call(
        server, "explain_entitlement", {"key": "com.apple.private.tcc.allow"}
    ).structured_content
    assert undocumented == {
        "key": "com.apple.private.tcc.allow",
        "title": "com.apple.private.tcc.allow",
        "summary": undocumented["summary"],
        "namespace": "Private TCC",
        "documented": False,
        "apple_docs_url": None,
        "weakens_runtime": None,
    }


def test_render_report_matches_the_cli(server, reports: Path, tmp_path: Path):
    report_dir = reports / SCAN_ID
    (report_dir / "index.html").unlink()
    (report_dir / "assets" / "data.js").write_text("stale")
    result = call(server, "render_report", {"scan_id": SCAN_ID})
    assert result.structured_content["report"] == str(report_dir / "index.html")

    cli_dir = tmp_path / "cli"
    assert cli.main(["render", str(report_dir / "scan.json"), "-o", str(cli_dir)]) == 0
    for name in ("index.html", "assets/data.js"):
        assert (report_dir / name).read_bytes() == (cli_dir / name).read_bytes()


def test_render_report_rejects_unknown_scans(server):
    assert call(server, "render_report", {"scan_id": "nope"}).is_error


def test_discover_targets_runs_discovery(server, monkeypatch):
    found = {"targets": [], "checked": []}
    monkeypatch.setattr(server_module, "discover", lambda: found)
    assert call(server, "discover_targets").structured_content == found
