import json
from pathlib import Path

import pytest

from maclolbins.targets import DiscoveryError, discover, run_listing

PRLCTL_LIST = json.dumps(
    [
        {"Name": "macOS", "State": "running", "OS": "macosx"},
        {"Name": "Sonoma test", "State": "stopped", "OS": "macosx"},
        {"Name": "Windows 11", "State": "running", "OS": "win-11"},
    ]
)
TART_LIST = json.dumps([{"Name": "sequoia-base", "State": "running", "Source": "local"}])
VMRUN_LIST = "Total running VMs: 1\n/Users/me/Virtual Machines.localized/mac.vmwarevm/mac.vmx\n"
UTMCTL_LIST = "UUID                                 Status   Name\nA-B-C started  My Mac VM\n"
OUTPUTS = {"prlctl": PRLCTL_LIST, "tart": TART_LIST, "vmrun": VMRUN_LIST, "utmctl": UTMCTL_LIST}


def fake_run(argv: list[str]) -> str:
    return OUTPUTS[Path(argv[0]).name]


def all_installed(name: str, _app_path: str | None) -> str:
    return f"/opt/bin/{name}"


def none_installed(_name: str, _app_path: str | None) -> None:
    return None


def by_kind(discovery, kind):
    return [t for t in discovery["targets"] if t["kind"] == kind]


def test_lists_every_kind_with_a_command_where_stdin_works(tmp_path: Path):
    config = tmp_path / "config"
    config.write_text("Host mini *.lan !bad\n  HostName 10.0.0.2\nhost=studio\nMatch all\n")
    found = discover(fake_run, all_installed, config, "darwin")

    assert by_kind(found, "local")[0]["command"] == ["/bin/bash", "-s"]
    parallels = by_kind(found, "parallels")
    assert [t["name"] for t in parallels] == ["macOS", "Sonoma test"]
    assert parallels[0]["command"] == [
        "/opt/bin/prlctl",
        "exec",
        "macOS",
        "--current-user",
        "/bin/bash",
        "-s",
    ]
    assert "prlctl start 'Sonoma test'" in parallels[1]["note"]
    assert by_kind(found, "tart")[0]["command"] == [
        "/opt/bin/tart",
        "exec",
        "-i",
        "sequoia-base",
        "/bin/bash",
        "-s",
    ]
    fusion = by_kind(found, "vmware-fusion")
    assert fusion[0]["name"].endswith("mac.vmx")
    assert fusion[0]["command"] is None
    assert "getGuestIPAddress" in fusion[0]["note"]
    utm = by_kind(found, "utm")
    assert (utm[0]["name"], utm[0]["state"], utm[0]["command"]) == ("My Mac VM", "started", None)
    assert [t["command"] for t in by_kind(found, "ssh")] == [
        ["ssh", "-o", "BatchMode=yes", "mini", "/bin/bash", "-s"],
        ["ssh", "-o", "BatchMode=yes", "studio", "/bin/bash", "-s"],
    ]
    assert {c["kind"]: c["status"] for c in found["checked"]} == dict.fromkeys(
        ["local", "parallels", "tart", "vmware-fusion", "utm", "ssh"], "found"
    )


def test_missing_tools_and_non_mac_hosts_are_reported(tmp_path: Path):
    found = discover(fake_run, none_installed, tmp_path / "no-config", "linux")
    assert found["targets"] == []
    checked = {c["kind"]: c for c in found["checked"]}
    assert checked["local"]["detail"] == "this host is linux"
    assert checked["parallels"] == {
        "kind": "parallels",
        "status": "not-installed",
        "detail": "prlctl not found",
    }
    assert checked["ssh"]["status"] == "found"


@pytest.mark.parametrize(
    "failure", [DiscoveryError("prlctl exited 1: no license"), ValueError("bad json")]
)
def test_a_failing_provider_does_not_hide_the_others(tmp_path: Path, failure):
    def run(argv: list[str]) -> str:
        if argv[0].endswith("prlctl"):
            raise failure
        return fake_run(argv)

    found = discover(run, all_installed, tmp_path / "none", "darwin")
    checked = {c["kind"]: c for c in found["checked"]}
    assert checked["parallels"]["status"] == "error"
    assert str(failure) in checked["parallels"]["detail"]
    assert by_kind(found, "tart")


def test_run_listing_raises_on_failure():
    assert run_listing(["/bin/echo", "ok"]) == "ok\n"
    with pytest.raises(DiscoveryError, match="exited 3: boom"):
        run_listing(["/bin/sh", "-c", "echo boom >&2; exit 3"])
